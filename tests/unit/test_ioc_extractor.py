"""
Unit tests for IOCExtractor (Phase 2).

Pure unit tests: no network, no database, no mocking needed, because
IOCExtractor has zero external dependencies -- it's a pure function of
its ParsedEmail input (via EmailParser from Phase 1).
"""

from pathlib import Path

import pytest

from app.domain.ioc_extractor import IOCExtractor
from app.domain.models import IOC, IOCType, ParsedEmail
from app.domain.parser import EmailParser

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def load_and_parse(name: str) -> ParsedEmail:
    raw = (FIXTURES_DIR / name).read_bytes()
    return EmailParser().parse(raw)


@pytest.fixture
def extractor() -> IOCExtractor:
    return IOCExtractor()


def values_of(iocs: list[IOC], ioc_type: IOCType) -> set[str]:
    return {ioc.value for ioc in iocs if ioc.ioc_type == ioc_type}


def find_one(iocs: list[IOC], ioc_type: IOCType, value: str) -> IOC:
    matches = [i for i in iocs if i.ioc_type == ioc_type and i.value == value]
    assert len(matches) == 1, f"expected exactly one match for {ioc_type}:{value}, got {len(matches)}"
    return matches[0]


class TestSimplePlainEmail:
    """simple_plain.eml: well-formed, no URLs, no attachments."""

    def test_header_emails_are_extracted(self, extractor: IOCExtractor):
        parsed = load_and_parse("simple_plain.eml")
        iocs = extractor.extract(parsed)

        emails = values_of(iocs, IOCType.EMAIL)
        assert emails == {
            "alice@example.com",
            "alice.replies@example.com",
            "bob@example.org",
            "carol@example.net",
        }

    def test_domains_are_derived_from_emails(self, extractor: IOCExtractor):
        parsed = load_and_parse("simple_plain.eml")
        iocs = extractor.extract(parsed)

        domains = values_of(iocs, IOCType.DOMAIN)
        assert "example.com" in domains
        assert "example.org" in domains
        assert "example.net" in domains

    def test_received_header_ip_and_hostname_are_extracted(self, extractor: IOCExtractor):
        parsed = load_and_parse("simple_plain.eml")
        iocs = extractor.extract(parsed)

        assert "203.0.113.10" in values_of(iocs, IOCType.IPV4)
        assert "mail.example.com" in values_of(iocs, IOCType.DOMAIN)

    def test_no_urls_or_hashes_present(self, extractor: IOCExtractor):
        parsed = load_and_parse("simple_plain.eml")
        iocs = extractor.extract(parsed)

        assert values_of(iocs, IOCType.URL) == set()
        assert values_of(iocs, IOCType.SHA256) == set()


class TestDuplicateIOCsAreMerged:
    """
    phishing_duplicate_iocs.eml: the same domain/email/IP appears in
    multiple places (From, Reply-To, Received, and body text).
    """

    def test_repeated_domain_appears_exactly_once_with_multiple_sources(
        self, extractor: IOCExtractor
    ):
        parsed = load_and_parse("phishing_duplicate_iocs.eml")
        iocs = extractor.extract(parsed)

        matches = [
            i for i in iocs
            if i.ioc_type == IOCType.DOMAIN and i.value == "paypa1-secure.com"
        ]
        assert len(matches) == 1, "duplicate domain should merge into a single IOC"

        merged = matches[0]
        # It was seen via a Received header, derived from two different
        # email addresses, AND derived from a URL -- all of that context
        # should be preserved, not discarded.
        assert "received_header" in merged.sources
        assert any(s.startswith("derived_from:email:") for s in merged.sources)
        assert any(s.startswith("derived_from:url:") for s in merged.sources)

    def test_repeated_email_address_merges_sources(self, extractor: IOCExtractor):
        parsed = load_and_parse("phishing_duplicate_iocs.eml")
        iocs = extractor.extract(parsed)

        # security@paypa1-secure.com appears both in the From header and
        # in the body text.
        ioc = find_one(iocs, IOCType.EMAIL, "security@paypa1-secure.com")
        assert "header:From" in ioc.sources
        assert "body:plain" in ioc.sources

    def test_email_comparison_is_case_insensitive_for_dedup(self, extractor: IOCExtractor):
        parsed = EmailParser().parse(
            (
                b"From: Test@Example.com\r\n"
                b"To: victim@example.com\r\n"
                b"Subject: case test\r\n\r\n"
                b"Please reply to test@example.com for help.\r\n"
            )
        )
        iocs = extractor.extract(parsed)

        matches = [i for i in iocs if i.ioc_type == IOCType.EMAIL]
        # "Test@Example.com" (header) and "test@example.com" (body)
        # should merge into ONE IOC despite differing case.
        merged_values = {m.value.lower() for m in matches}
        assert "test@example.com" in merged_values
        count = sum(1 for m in matches if m.value.lower() == "test@example.com")
        assert count == 1, "case-differing duplicates must merge into a single IOC"


class TestURLsContainingIPs:
    """
    phishing_duplicate_iocs.eml also contains a URL whose host is a raw
    IP address (http://185.220.101.7/paypal/login.php), and that same
    IP independently appears in a Received header.
    """

    def test_ip_hosted_url_produces_both_a_url_ioc_and_an_ip_ioc(
        self, extractor: IOCExtractor
    ):
        parsed = load_and_parse("phishing_duplicate_iocs.eml")
        iocs = extractor.extract(parsed)

        assert "http://185.220.101.7/paypal/login.php" in values_of(iocs, IOCType.URL)
        assert "185.220.101.7" in values_of(iocs, IOCType.IPV4)

    def test_ip_from_url_and_ip_from_received_header_merge_into_one_ioc(
        self, extractor: IOCExtractor
    ):
        parsed = load_and_parse("phishing_duplicate_iocs.eml")
        iocs = extractor.extract(parsed)

        ioc = find_one(iocs, IOCType.IPV4, "185.220.101.7")
        assert any("url host" in s for s in ioc.sources)
        assert "received_header" in ioc.sources

    def test_domain_hosted_url_does_not_produce_a_spurious_ip(self, extractor: IOCExtractor):
        parsed = load_and_parse("phishing_duplicate_iocs.eml")
        iocs = extractor.extract(parsed)

        # https://paypa1-secure.com/help has a domain host, not an IP --
        # it must contribute a DOMAIN, not accidentally match as an IP.
        assert "https://paypa1-secure.com/help" in values_of(iocs, IOCType.URL)
        assert "paypa1-secure.com" in values_of(iocs, IOCType.DOMAIN)

    def test_ipv6_relay_is_extracted(self, extractor: IOCExtractor):
        parsed = load_and_parse("phishing_duplicate_iocs.eml")
        iocs = extractor.extract(parsed)

        assert "2001:db8::1" in values_of(iocs, IOCType.IPV6)


class TestAttachmentHashing:
    """multipart_with_attachment.eml: one text attachment."""

    def test_attachment_produces_a_sha256_ioc(self, extractor: IOCExtractor):
        parsed = load_and_parse("multipart_with_attachment.eml")
        iocs = extractor.extract(parsed)

        hashes = [i for i in iocs if i.ioc_type == IOCType.SHA256]
        assert len(hashes) == 1
        assert len(hashes[0].value) == 64  # SHA256 hex digest length
        assert hashes[0].sources == ["attachment:invoice.txt"]

    def test_hash_matches_a_manual_sha256_computation(self, extractor: IOCExtractor):
        import hashlib

        parsed = load_and_parse("multipart_with_attachment.eml")
        iocs = extractor.extract(parsed)
        hash_ioc = next(i for i in iocs if i.ioc_type == IOCType.SHA256)

        attachment = parsed.attachments[0]
        expected = hashlib.sha256(attachment.content).hexdigest()
        assert hash_ioc.value == expected

    def test_identical_attachment_bytes_in_two_attachments_merge_into_one_hash_ioc(
        self, extractor: IOCExtractor
    ):
        # Two differently-named attachments with IDENTICAL content should
        # merge into a single SHA256 IOC with both filenames as sources,
        # since the hash -- the actual indicator -- is the same.
        from email.message import EmailMessage

        msg = EmailMessage()
        msg["From"] = "a@example.com"
        msg["To"] = "b@example.com"
        msg["Subject"] = "duplicate attachment content"
        msg.set_content("see attached")
        payload = b"identical payload bytes"
        msg.add_attachment(payload, maintype="text", subtype="plain", filename="a.txt")
        msg.add_attachment(payload, maintype="text", subtype="plain", filename="b.txt")

        parsed = EmailParser().parse(msg.as_bytes())
        iocs = extractor.extract(parsed)

        hash_iocs = [i for i in iocs if i.ioc_type == IOCType.SHA256]
        assert len(hash_iocs) == 1
        assert set(hash_iocs[0].sources) == {"attachment:a.txt", "attachment:b.txt"}


class TestMalformedAndEmptyInput:
    def test_email_with_no_urls_attachments_or_body_matches_still_extracts_headers(
        self, extractor: IOCExtractor
    ):
        parsed = load_and_parse("malformed_headers.eml")
        iocs = extractor.extract(parsed)

        assert "weird@example.com" in values_of(iocs, IOCType.EMAIL)
        assert values_of(iocs, IOCType.URL) == set()
        assert values_of(iocs, IOCType.SHA256) == set()

    def test_wrong_input_type_raises_type_error(self, extractor: IOCExtractor):
        with pytest.raises(TypeError):
            extractor.extract("not a ParsedEmail")  # type: ignore[arg-type]

    def test_empty_parsed_email_produces_empty_ioc_list(self, extractor: IOCExtractor):
        empty = ParsedEmail(
            from_address=None,
            to_addresses=[],
            cc_addresses=[],
            reply_to=None,
            subject=None,
            date=None,
            message_id=None,
            return_path=None,
            received_headers=[],
            authentication_results=[],
            content_type="text/plain",
            body_plain=None,
            body_html=None,
            attachments=[],
            raw_size_bytes=0,
        )
        iocs = extractor.extract(empty)
        assert iocs == []

    def test_malformed_received_header_does_not_crash_extraction(
        self, extractor: IOCExtractor
    ):
        # A Received header with no recognizable "from <host>" structure
        # and garbage content should be skipped gracefully, not raise.
        broken = ParsedEmail(
            from_address="a@example.com",
            to_addresses=["b@example.com"],
            cc_addresses=[],
            reply_to=None,
            subject=None,
            date=None,
            message_id=None,
            return_path=None,
            received_headers=["this is not a valid received header at all !!!"],
            authentication_results=[],
            content_type="text/plain",
            body_plain=None,
            body_html=None,
            attachments=[],
            raw_size_bytes=0,
        )
        iocs = extractor.extract(broken)  # should not raise
        emails = values_of(iocs, IOCType.EMAIL)
        assert "a@example.com" in emails
        assert "b@example.com" in emails


class TestResultIsSortedAndDeterministic:
    def test_extracting_the_same_email_twice_yields_identical_results(
        self, extractor: IOCExtractor
    ):
        parsed = load_and_parse("phishing_duplicate_iocs.eml")

        result1 = extractor.extract(parsed)
        result2 = extractor.extract(parsed)

        as_tuples = lambda iocs: [(i.ioc_type, i.value, sorted(i.sources)) for i in iocs]
        assert as_tuples(result1) == as_tuples(result2)

    def test_results_are_sorted_by_type_then_value(self, extractor: IOCExtractor):
        parsed = load_and_parse("phishing_duplicate_iocs.eml")
        iocs = extractor.extract(parsed)

        keys = [(i.ioc_type.value, i.value) for i in iocs]
        assert keys == sorted(keys)
