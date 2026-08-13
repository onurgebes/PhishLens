"""
Phase 2: IOC extraction.

Turns a ParsedEmail (Phase 1's output) into a flat, deduplicated list of
IOC objects: IPv4/IPv6 addresses, domains, URLs, email addresses, and
SHA256 hashes of attachments.

This module ONLY extracts facts. It never judges whether an IOC is
suspicious -- that is IOC *analysis*, a later phase (see the
extraction-vs-analysis discussion). Keeping this boundary means
IOCExtractor is deterministic and has zero external dependencies: same
input always produces the same output, no network calls, nothing to
mock in tests.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from email.utils import getaddresses
from urllib.parse import urlparse

from app.domain.models import IOC, IOCType, ParsedEmail

# --- Regexes: these find *candidates*. Each candidate is then validated
# (for IPs, via ipaddress; for URLs, via urlparse) before being trusted.
# This two-step "regex to find, stdlib to validate" pattern avoids
# false positives like "999.999.999.999" being accepted as an IP.

_IPV4_CANDIDATE_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# IPv6 is far more varied in shape than IPv4 (compressed "::" forms,
# mixed with IPv4-mapped notation, etc.). Rather than trying to write a
# fully correct IPv6 regex by hand -- a notoriously error-prone exercise
# -- we cast a reasonably wide net for hex-and-colon tokens and let
# ipaddress.ip_address() be the actual authority on validity.
_IPV6_CANDIDATE_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")

_URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.IGNORECASE)

_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"
)

# Matches the hostname/IP that follows "from" in a Received header, e.g.:
#   "from mail.example.com (mail.example.com [203.0.113.10])"
#   "from [185.220.101.7] by mx.example.org"
_RECEIVED_FROM_HOST_RE = re.compile(
    r"from\s+\[?([A-Za-z0-9.\-]+|[0-9A-Fa-f:]+)\]?", re.IGNORECASE
)


class IOCExtractor:
    """
    Stateless extractor: extract() takes a ParsedEmail and returns a
    deduplicated list[IOC]. No constructor arguments, no instance state
    -- same pattern as EmailParser in Phase 1.
    """

    def extract(self, email: ParsedEmail) -> list[IOC]:
        if not isinstance(email, ParsedEmail):
            raise TypeError("IOCExtractor.extract() expects a ParsedEmail")

        # merged: (ioc_type, normalized_value) -> IOC (with sources
        # accumulating as we go). Using a dict keeps dedup O(1) instead
        # of scanning the whole list-so-far for every new candidate.
        merged: dict[tuple[IOCType, str], IOC] = {}

        self._extract_header_emails(email, merged)
        self._extract_body_emails(email, merged)
        self._extract_body_urls(email, merged)
        self._extract_received_header_ips_and_hosts(email, merged)
        self._extract_domains_from_emails_and_urls(merged)
        self._extract_attachment_hashes(email, merged)

        # Stable, sorted order so tests (and callers) get deterministic
        # output regardless of internal extraction order.
        return sorted(
            merged.values(), key=lambda ioc: (ioc.ioc_type.value, ioc.value)
        )

    # -- internal helpers ---------------------------------------------

    @staticmethod
    def _add(
        merged: dict[tuple[IOCType, str], IOC],
        ioc_type: IOCType,
        value: str,
        source: str,
        dedup_key_value: str | None = None,
    ) -> None:
        """
        Add one occurrence of an IOC. If (type, dedup key) already
        exists, just append the source instead of creating a duplicate
        entry -- this is the core of requirement #6 (no duplicate IOCs,
        but preserve source/context).
        """
        key_value = dedup_key_value if dedup_key_value is not None else value
        key = (ioc_type, key_value)

        existing = merged.get(key)
        if existing is None:
            merged[key] = IOC(ioc_type=ioc_type, value=value, sources=[source])
        elif source not in existing.sources:
            existing.sources.append(source)

    def _extract_header_emails(
        self, email: ParsedEmail, merged: dict[tuple[IOCType, str], IOC]
    ) -> None:
        """Email addresses from structured headers (already-parsed fields)."""
        header_fields: list[tuple[str, str | list[str] | None]] = [
            ("header:From", email.from_address),
            ("header:To", email.to_addresses),
            ("header:Cc", email.cc_addresses),
            ("header:Reply-To", email.reply_to),
            ("header:Return-Path", email.return_path),
        ]
        for source, value in header_fields:
            if value is None:
                continue
            raw_values = value if isinstance(value, list) else [value]
            for raw in raw_values:
                for _, addr in getaddresses([raw]):
                    if addr:
                        self._add(
                            merged, IOCType.EMAIL, addr, source,
                            dedup_key_value=addr.lower(),
                        )

    def _extract_body_emails(
        self, email: ParsedEmail, merged: dict[tuple[IOCType, str], IOC]
    ) -> None:
        """Email-shaped strings mentioned in the body text."""
        for source, text in (
            ("body:plain", email.body_plain),
            ("body:html", email.body_html),
        ):
            if not text:
                continue
            for match in _EMAIL_RE.findall(text):
                self._add(
                    merged, IOCType.EMAIL, match, source,
                    dedup_key_value=match.lower(),
                )

    def _extract_body_urls(
        self, email: ParsedEmail, merged: dict[tuple[IOCType, str], IOC]
    ) -> None:
        """
        URLs from the body. For each URL, if its host is a raw IP
        (rather than a domain name), also emit that IP as its own IOC
        -- this is the "URLs containing IPs" case.
        """
        for source, text in (
            ("body:plain", email.body_plain),
            ("body:html", email.body_html),
        ):
            if not text:
                continue
            for url in _URL_RE.findall(text):
                self._add(merged, IOCType.URL, url, source)

                host = urlparse(url).hostname
                if host:
                    ip_type = self._classify_ip(host)
                    if ip_type is not None:
                        self._add(merged, ip_type, host, f"{source} (url host)")

    def _extract_received_header_ips_and_hosts(
        self, email: ParsedEmail, merged: dict[tuple[IOCType, str], IOC]
    ) -> None:
        """
        The Received chain is where mail-relay IPs live. We scan each
        Received header for: (a) any IPv4/IPv6-shaped token anywhere in
        the line (relays often list an IP in parentheses/brackets), and
        (b) the hostname immediately after "from" (a domain-shaped
        mail-server name, if present).
        """
        for header in email.received_headers:
            for candidate in _IPV4_CANDIDATE_RE.findall(header):
                if self._classify_ip(candidate) == IOCType.IPV4:
                    self._add(merged, IOCType.IPV4, candidate, "received_header")

            for candidate in _IPV6_CANDIDATE_RE.findall(header):
                if self._classify_ip(candidate) == IOCType.IPV6:
                    self._add(merged, IOCType.IPV6, candidate, "received_header")

            match = _RECEIVED_FROM_HOST_RE.search(header)
            if match:
                host = match.group(1)
                if self._classify_ip(host) is None and "." in host:
                    # domain-shaped hostname, not an IP -- record as a
                    # DOMAIN IOC directly (Received headers are the one
                    # place we trust bare-hostname scanning, since their
                    # structure is predictable; see architecture notes)
                    self._add(
                        merged, IOCType.DOMAIN, host, "received_header",
                        dedup_key_value=host.lower(),
                    )

    def _extract_domains_from_emails_and_urls(
        self, merged: dict[tuple[IOCType, str], IOC]
    ) -> None:
        """
        Derive DOMAIN IOCs from the EMAIL and URL IOCs already found,
        rather than scanning free text for bare domains (too noisy --
        see architecture discussion). Iterates over a snapshot of
        `merged`'s current values since we're adding new entries to the
        same dict while reading from it.
        """
        for ioc in list(merged.values()):
            domain: str | None = None
            source = f"derived_from:{ioc.ioc_type.value}:{ioc.value}"

            if ioc.ioc_type == IOCType.EMAIL:
                domain = ioc.value.rsplit("@", 1)[-1] or None
            elif ioc.ioc_type == IOCType.URL:
                host = urlparse(ioc.value).hostname
                # Only treat it as a domain if it's NOT an IP literal --
                # IP-hosted URLs already produced an IPv4/IPv6 IOC above.
                if host and self._classify_ip(host) is None:
                    domain = host

            if domain:
                self._add(
                    merged, IOCType.DOMAIN, domain, source,
                    dedup_key_value=domain.lower(),
                )

    def _extract_attachment_hashes(
        self, email: ParsedEmail, merged: dict[tuple[IOCType, str], IOC]
    ) -> None:
        """
        SHA256 of each attachment's raw bytes. This is computed, not
        pattern-matched -- and note this is the ONLY thing this class
        does with attachment content: hash it. It is never opened,
        parsed, or executed.
        """
        for attachment in email.attachments:
            digest = hashlib.sha256(attachment.content).hexdigest()
            source = f"attachment:{attachment.filename or 'unnamed'}"
            self._add(merged, IOCType.SHA256, digest, source)

    @staticmethod
    def _classify_ip(candidate: str) -> IOCType | None:
        """Return IOCType.IPV4 / IPV6 if candidate is a valid IP, else None."""
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            return None
        return IOCType.IPV4 if parsed.version == 4 else IOCType.IPV6
