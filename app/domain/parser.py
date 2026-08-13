"""
Phase 1: Basic email parser.

Turns raw .eml bytes (or raw pasted email source encoded as bytes) into
a structured ParsedEmail. This module has ONE job: parsing. It does not
extract IOCs, judge anything as suspicious, or compute risk — that is
later phases' responsibility, kept deliberately separate so each piece
can be understood and tested on its own.
"""

from __future__ import annotations

from datetime import datetime
from email import policy
from email.parser import BytesParser
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime

from app.domain.models import Attachment, ParsedEmail

# A generous but firm upper bound. Real emails are almost always well
# under this; this exists to stop a deliberately huge upload from
# consuming excessive memory/CPU during parsing (see THREAT_MODEL.md,
# "resource exhaustion / DoS").
MAX_EMAIL_SIZE_BYTES = 25 * 1024 * 1024  # 25 MB


class EmailTooLargeError(ValueError):
    """Raised when the input exceeds MAX_EMAIL_SIZE_BYTES."""


class EmailParser:
    """
    Stateless parser: parse() takes raw bytes and returns a ParsedEmail.

    Deliberately has no constructor arguments and no instance state —
    there's nothing to configure yet, and keeping it stateless makes it
    trivial to test (just call EmailParser().parse(some_bytes)).
    """

    def parse(self, raw_bytes: bytes) -> ParsedEmail:
        if not isinstance(raw_bytes, (bytes, bytearray)):
            raise TypeError("EmailParser.parse() expects raw bytes")

        size = len(raw_bytes)
        if size > MAX_EMAIL_SIZE_BYTES:
            raise EmailTooLargeError(
                f"Email is {size} bytes, exceeds the "
                f"{MAX_EMAIL_SIZE_BYTES}-byte limit"
            )

        # policy.default: modern, RFC-compliant parsing policy. It
        # decodes encoded-word headers (e.g. "=?UTF-8?B?...?=") for us
        # and records malformed-structure issues in msg.defects instead
        # of raising, which is what we want for a security tool that
        # must be able to report on intentionally malformed emails.
        msg: Message = BytesParser(policy=policy.default).parsebytes(raw_bytes)

        warnings = [str(defect) for defect in msg.defects]

        body_plain, body_html, attachments, part_warnings = self._walk_parts(msg)
        warnings.extend(part_warnings)

        return ParsedEmail(
            from_address=self._header_str(msg, "From"),
            to_addresses=self._address_list(msg, "To"),
            cc_addresses=self._address_list(msg, "Cc"),
            reply_to=self._header_str(msg, "Reply-To"),
            subject=self._header_str(msg, "Subject"),
            date=self._parse_date(msg),
            message_id=self._header_str(msg, "Message-ID"),
            return_path=self._header_str(msg, "Return-Path"),
            received_headers=[str(h) for h in msg.get_all("Received", [])],
            authentication_results=[
                str(h) for h in msg.get_all("Authentication-Results", [])
            ],
            content_type=msg.get_content_type(),
            body_plain=body_plain,
            body_html=body_html,
            attachments=attachments,
            raw_size_bytes=size,
            parse_warnings=warnings,
        )

    # -- helpers -----------------------------------------------------

    @staticmethod
    def _header_str(msg: Message, name: str) -> str | None:
        value = msg.get(name)
        return str(value) if value is not None else None

    @staticmethod
    def _address_list(msg: Message, name: str) -> list[str]:
        """
        Correctly split a header that may contain multiple, comma-
        separated addresses with display names, e.g.:
            "Alice <a@x.com>, Bob <b@y.com>"
        Naive msg.get(name).split(",") breaks if a display name itself
        contains a comma; email.utils.getaddresses handles that.
        """
        raw_values = msg.get_all(name, [])
        if not raw_values:
            return []
        pairs = getaddresses([str(v) for v in raw_values])
        # getaddresses returns (display_name, email_address) tuples;
        # we want the address, and we skip empty results from blank
        # or malformed entries.
        return [addr for _, addr in pairs if addr]

    @staticmethod
    def _parse_date(msg: Message) -> datetime | None:
        raw_date = msg.get("Date")
        if not raw_date:
            return None
        try:
            return parsedate_to_datetime(str(raw_date))
        except (TypeError, ValueError):
            # Malformed Date header — don't crash the whole parse over
            # one bad header, just leave date unset. This itself could
            # become a finding in a later phase.
            return None

    def _walk_parts(
        self, msg: Message
    ) -> tuple[str | None, str | None, list[Attachment], list[str]]:
        """
        Walk the MIME tree (handles nested multipart/*) and split parts
        into: plain-text body, HTML body, and attachments.

        Classification rule, applied per leaf part:
          - Content-Disposition: attachment  -> attachment
          - has a filename                   -> attachment
          - content-type is text/plain or
            text/html AND not flagged above   -> body content
          - anything else                     -> attachment (safe default:
            unrecognized content types are treated as attachments rather
            than silently dropped or rendered)
        """
        body_plain: str | None = None
        body_html: str | None = None
        attachments: list[Attachment] = []
        warnings: list[str] = []

        for part in msg.walk():
            # Skip multipart "container" parts themselves; we only care
            # about their leaves, which walk() also yields.
            if part.is_multipart():
                continue

            content_type = part.get_content_type()
            disposition = part.get_content_disposition()  # 'attachment', 'inline', or None
            filename = part.get_filename()

            is_attachment = (
                disposition == "attachment"
                or filename is not None
                or content_type not in ("text/plain", "text/html")
            )

            if is_attachment:
                try:
                    payload = part.get_payload(decode=True) or b""
                except Exception as exc:  # noqa: BLE001 - defensive, see below
                    # A malformed part (e.g. bad base64) shouldn't crash
                    # the whole parse; record it and move on. This is
                    # exactly the kind of "attacker sends something
                    # slightly broken on purpose" case a security tool
                    # must survive.
                    warnings.append(f"Failed to decode part {filename!r}: {exc}")
                    payload = b""
                attachments.append(
                    Attachment(
                        filename=filename,
                        content_type=content_type,
                        size_bytes=len(payload),
                        content=payload,
                    )
                )
                continue

            # Body text part (plain or html)
            try:
                text = part.get_content()
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"Failed to decode {content_type} body part: {exc}")
                continue

            if content_type == "text/plain" and body_plain is None:
                body_plain = text
            elif content_type == "text/html" and body_html is None:
                body_html = text

        return body_plain, body_html, attachments, warnings
