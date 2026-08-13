"""
Unit tests for EmailParser (Phase 1).

These are pure unit tests: no network, no filesystem access beyond
reading the fixture .eml files, no database. That's possible because
EmailParser has zero framework/I-O dependencies (see app/domain/parser.py).
"""

from datetime import datetime
from pathlib import Path

import pytest

from app.domain.parser import EmailParser, EmailTooLargeError, MAX_EMAIL_SIZE_BYTES

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def load_fixture(name: str) -> bytes:
    return (FIXTURES_DIR / name).read_bytes()


@pytest.fixture
def parser() -> EmailParser:
    return EmailParser()


class TestSimplePlainEmail:
    """simple_plain.eml: a well-formed, plain-text-only email."""

    def test_core_headers_are_extracted(self, parser: EmailParser):
        result = parser.parse(load_fixture("simple_plain.eml"))

        assert result.from_address == "Alice Example <alice@example.com>"
        assert result.subject == "Quarterly report attached"
        assert result.message_id == "<abc123@example.com>"
        assert result.return_path == "<alice@example.com>"
        assert result.reply_to == "alice.replies@example.com"

    def test_to_and_cc_are_parsed_as_address_lists(self, parser: EmailParser):
        result = parser.parse(load_fixture("simple_plain.eml"))

        assert result.to_addresses == ["bob@example.org"]
        assert result.cc_addresses == ["carol@example.net"]

    def test_date_is_parsed_into_a_datetime(self, parser: EmailParser):
        result = parser.parse(load_fixture("simple_plain.eml"))

        assert isinstance(result.date, datetime)
        assert result.date.year == 2024
        assert result.date.month == 8
        assert result.date.day == 12

    def test_received_and_auth_results_are_captured_raw(self, parser: EmailParser):
        result = parser.parse(load_fixture("simple_plain.eml"))

        assert len(result.received_headers) == 1
        assert "mail.example.com" in result.received_headers[0]
        assert len(result.authentication_results) == 1
        assert "spf=pass" in result.authentication_results[0]

    def test_plain_body_is_extracted_and_no_attachments(self, parser: EmailParser):
        result = parser.parse(load_fixture("simple_plain.eml"))

        assert result.body_plain is not None
        assert "quarterly report" in result.body_plain.lower()
        assert result.body_html is None
        assert result.attachments == []

    def test_no_parse_warnings_for_a_well_formed_email(self, parser: EmailParser):
        result = parser.parse(load_fixture("simple_plain.eml"))

        assert result.parse_warnings == []


class TestMultipartEmailWithAttachment:
    """
    multipart_with_attachment.eml: plain + HTML alternative body, plus
    one text-file attachment. Exercises MIME-tree walking.
    """

    def test_both_plain_and_html_bodies_are_extracted(self, parser: EmailParser):
        result = parser.parse(load_fixture("multipart_with_attachment.eml"))

        assert result.body_plain is not None
        assert "invoice is attached" in result.body_plain.lower()

        assert result.body_html is not None
        assert "<p>" in result.body_html.lower()

    def test_attachment_is_extracted_with_correct_metadata(self, parser: EmailParser):
        result = parser.parse(load_fixture("multipart_with_attachment.eml"))

        assert len(result.attachments) == 1
        attachment = result.attachments[0]
        assert attachment.filename == "invoice.txt"
        assert attachment.content_type == "text/plain"
        assert attachment.size_bytes > 0
        assert b"Invoice #001" in attachment.content

    def test_multi_address_to_header_with_display_names_is_split_correctly(
        self, parser: EmailParser
    ):
        result = parser.parse(load_fixture("multipart_with_attachment.eml"))

        # "Smith, Carol" contains a comma in the display name; a naive
        # split(",") on the raw header would incorrectly produce three
        # entries instead of two. getaddresses() must handle this.
        assert result.to_addresses == ["bob@example.org", "carol@example.net"]

    def test_authentication_results_reflect_a_failing_email(self, parser: EmailParser):
        result = parser.parse(load_fixture("multipart_with_attachment.eml"))

        auth = result.authentication_results[0]
        assert "spf=fail" in auth
        assert "dmarc=fail" in auth


class TestMalformedHeaders:
    """malformed_headers.eml: broken Date header, comma-in-display-name To header."""

    def test_broken_date_header_does_not_crash_parsing(self, parser: EmailParser):
        result = parser.parse(load_fixture("malformed_headers.eml"))

        # The parser should degrade gracefully: date is None, not an
        # exception, and the rest of the email still parses.
        assert result.date is None
        assert result.subject == "Test with a broken date header"

    def test_to_header_with_comma_in_display_name_still_splits_correctly(
        self, parser: EmailParser
    ):
        result = parser.parse(load_fixture("malformed_headers.eml"))

        assert result.to_addresses == ["jane@example.org", "john@example.net"]


class TestSizeLimit:
    """The parser must reject oversized input before doing any real work."""

    def test_oversized_input_raises_email_too_large_error(self, parser: EmailParser):
        # Build something bigger than the limit without actually
        # allocating a huge amount of memory for a "real" email --
        # a big blob of bytes is enough to trigger the size check.
        oversized = b"A" * (MAX_EMAIL_SIZE_BYTES + 1)

        with pytest.raises(EmailTooLargeError):
            parser.parse(oversized)

    def test_input_at_exactly_the_limit_is_accepted(self, parser: EmailParser):
        # A minimal valid email padded with a long Subject so the total
        # size sits exactly at the limit -- confirms the boundary is
        # ">", not ">=".
        base = load_fixture("simple_plain.eml")
        padding_needed = MAX_EMAIL_SIZE_BYTES - len(base)
        padded = base + b"X" * padding_needed

        result = parser.parse(padded)
        assert result.raw_size_bytes == MAX_EMAIL_SIZE_BYTES


class TestInputTypeValidation:
    def test_passing_a_str_instead_of_bytes_raises_type_error(self, parser: EmailParser):
        with pytest.raises(TypeError):
            parser.parse("this is a str, not bytes")  # type: ignore[arg-type]
