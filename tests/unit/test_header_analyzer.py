"""
Unit tests for HeaderAnalyzer (Phase 3).
"""

from __future__ import annotations

import pytest

from app.domain.analyzers.header_analyzer import HeaderAnalyzer
from app.domain.models import FindingCategory, FindingSeverity, ParsedEmail
from tests.unit.conftest import empty_email, extract_iocs, findings_by_rule, load_and_parse


@pytest.fixture
def analyzer() -> HeaderAnalyzer:
    return HeaderAnalyzer()


class TestReplyToMismatch:
    def test_triggers_when_reply_to_domain_differs_from_from(self, analyzer: HeaderAnalyzer):
        email = empty_email(
            from_address="Alice <alice@example.com>",
            reply_to="Attacker <attacker@evil.com>",
            message_id="<msg-1@example.com>",
        )
        findings = analyzer.analyze(email, extract_iocs(email))

        hits = findings_by_rule(findings, "header_reply_to_domain_mismatch")
        assert len(hits) == 1
        assert hits[0].severity == FindingSeverity.HIGH
        assert hits[0].category == FindingCategory.HEADER
        assert hits[0].evidence["from_domain"] == "example.com"
        assert hits[0].evidence["reply_to_domain"] == "evil.com"
        assert "alice@example.com" in hits[0].evidence["from_address"]
        assert "attacker@evil.com" in hits[0].evidence["reply_to"]

    def test_clean_when_reply_to_matches_from_domain(self, analyzer: HeaderAnalyzer):
        email = empty_email(
            from_address="Alice <alice@example.com>",
            reply_to="alice.replies@example.com",
            message_id="<msg-1@example.com>",
        )
        findings = analyzer.analyze(email, extract_iocs(email))
        assert findings_by_rule(findings, "header_reply_to_domain_mismatch") == []

    def test_clean_when_reply_to_is_missing(self, analyzer: HeaderAnalyzer):
        email = empty_email(
            from_address="Alice <alice@example.com>",
            message_id="<msg-1@example.com>",
        )
        findings = analyzer.analyze(email, extract_iocs(email))
        assert findings_by_rule(findings, "header_reply_to_domain_mismatch") == []


class TestReturnPathMismatch:
    def test_triggers_when_return_path_domain_differs(self, analyzer: HeaderAnalyzer):
        email = empty_email(
            from_address="Notify <notify@example.com>",
            return_path="<bounce@other.net>",
            message_id="<msg-1@example.com>",
        )
        findings = analyzer.analyze(email, extract_iocs(email))

        hits = findings_by_rule(findings, "header_return_path_mismatch")
        assert len(hits) == 1
        assert hits[0].severity == FindingSeverity.MEDIUM
        assert hits[0].evidence["from_domain"] == "example.com"
        assert hits[0].evidence["return_path_domain"] == "other.net"

    def test_clean_when_return_path_matches_from_domain(self, analyzer: HeaderAnalyzer):
        parsed = load_and_parse("simple_plain.eml")
        findings = analyzer.analyze(parsed, extract_iocs(parsed))
        assert findings_by_rule(findings, "header_return_path_mismatch") == []

    def test_clean_on_multipart_fixture_when_domains_match(self, analyzer: HeaderAnalyzer):
        parsed = load_and_parse("multipart_with_attachment.eml")
        findings = analyzer.analyze(parsed, extract_iocs(parsed))
        assert findings_by_rule(findings, "header_return_path_mismatch") == []


class TestDisplayNameBrandSpoofing:
    def test_triggers_for_brand_display_name_with_unrelated_domain(
        self, analyzer: HeaderAnalyzer
    ):
        email = empty_email(
            from_address="PayPal Security <security@paypa1-secure.com>",
            message_id="<msg-1@example.com>",
        )
        findings = analyzer.analyze(email, extract_iocs(email))

        hits = findings_by_rule(findings, "header_display_name_brand_spoofing")
        assert len(hits) == 1
        assert hits[0].severity == FindingSeverity.HIGH
        assert hits[0].evidence["brand"] == "PayPal"
        assert hits[0].evidence["from_domain"] == "paypa1-secure.com"
        assert "PayPal" in hits[0].evidence["display_name"]

    def test_clean_for_legitimate_brand_domain(self, analyzer: HeaderAnalyzer):
        email = empty_email(
            from_address="PayPal <noreply@paypal.com>",
            message_id="<msg-1@example.com>",
        )
        findings = analyzer.analyze(email, extract_iocs(email))
        assert findings_by_rule(findings, "header_display_name_brand_spoofing") == []

    def test_clean_when_display_name_has_no_brand(self, analyzer: HeaderAnalyzer):
        email = empty_email(
            from_address="Alice Example <alice@example.com>",
            message_id="<msg-1@example.com>",
        )
        findings = analyzer.analyze(email, extract_iocs(email))
        assert findings_by_rule(findings, "header_display_name_brand_spoofing") == []


class TestMissingMessageId:
    def test_triggers_when_message_id_is_absent(self, analyzer: HeaderAnalyzer):
        email = empty_email(from_address="a@example.com")
        findings = analyzer.analyze(email, extract_iocs(email))

        hits = findings_by_rule(findings, "header_missing_message_id")
        assert len(hits) == 1
        assert hits[0].severity == FindingSeverity.LOW
        assert hits[0].evidence["message_id"] == ""

    def test_clean_when_message_id_is_present(self, analyzer: HeaderAnalyzer):
        parsed = load_and_parse("simple_plain.eml")
        findings = analyzer.analyze(parsed, extract_iocs(parsed))
        assert findings_by_rule(findings, "header_missing_message_id") == []


class TestPhishingFixtureIntegration:
    def test_phishing_fixture_triggers_brand_spoofing_and_missing_message_id(
        self, analyzer: HeaderAnalyzer
    ):
        parsed = load_and_parse("phishing_duplicate_iocs.eml")
        findings = analyzer.analyze(parsed, extract_iocs(parsed))

        assert findings_by_rule(findings, "header_display_name_brand_spoofing")
        assert findings_by_rule(findings, "header_missing_message_id")
        # From and Reply-To share the same domain in this fixture.
        assert findings_by_rule(findings, "header_reply_to_domain_mismatch") == []


class TestMalformedAndEmptyInput:
    def test_empty_email_does_not_crash(self, analyzer: HeaderAnalyzer):
        email = empty_email()
        findings = analyzer.analyze(email, [])
        assert isinstance(findings, list)

    def test_malformed_from_header_does_not_crash(self, analyzer: HeaderAnalyzer):
        email = empty_email(from_address="not-an-email", reply_to="also-bad")
        findings = analyzer.analyze(email, [])
        assert isinstance(findings, list)

    def test_wrong_email_type_raises_type_error(self, analyzer: HeaderAnalyzer):
        with pytest.raises(TypeError):
            analyzer.analyze("not a ParsedEmail", [])  # type: ignore[arg-type]

    def test_wrong_ioc_type_raises_type_error(self, analyzer: HeaderAnalyzer):
        with pytest.raises(TypeError):
            analyzer.analyze(empty_email(), "not a list")  # type: ignore[arg-type]


class TestDeterministicOutput:
    def test_same_input_produces_identical_findings(self, analyzer: HeaderAnalyzer):
        parsed = load_and_parse("phishing_duplicate_iocs.eml")
        iocs = extract_iocs(parsed)

        first = analyzer.analyze(parsed, iocs)
        second = analyzer.analyze(parsed, iocs)

        def as_tuples(findings):
            return [
                (
                    f.rule_id,
                    f.category,
                    f.severity,
                    f.title,
                    sorted(f.evidence.items()),
                )
                for f in findings
            ]

        assert as_tuples(first) == as_tuples(second)

    def test_findings_are_sorted_stably(self, analyzer: HeaderAnalyzer):
        parsed = load_and_parse("phishing_duplicate_iocs.eml")
        findings = analyzer.analyze(parsed, extract_iocs(parsed))
        keys = [(f.category.value, f.severity.value, f.rule_id) for f in findings]
        assert keys == sorted(keys)
