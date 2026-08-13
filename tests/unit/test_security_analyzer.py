"""
Unit tests for SecurityAnalyzer (Phase 3).
"""

from __future__ import annotations

import pytest

from app.domain.analyzers.security_analyzer import SecurityAnalyzer
from app.domain.models import FindingCategory, FindingSeverity
from tests.unit.conftest import empty_email, extract_iocs, findings_by_rule, load_and_parse


@pytest.fixture
def analyzer() -> SecurityAnalyzer:
    return SecurityAnalyzer()


class TestSpfFail:
    def test_triggers_for_spf_fail(self, analyzer: SecurityAnalyzer):
        email = empty_email(
            from_address="sender@example.com",
            authentication_results=[
                "mx.example.org; spf=fail smtp.mailfrom=example.com; dkim=none"
            ],
        )
        findings = analyzer.analyze(email, [])

        hits = findings_by_rule(findings, "auth_spf_fail")
        assert len(hits) == 1
        assert hits[0].severity == FindingSeverity.HIGH
        assert hits[0].category == FindingCategory.AUTHENTICATION
        assert "fail" in hits[0].evidence["spf_results"]

    def test_clean_for_spf_pass(self, analyzer: SecurityAnalyzer):
        parsed = load_and_parse("simple_plain.eml")
        findings = analyzer.analyze(parsed, extract_iocs(parsed))
        assert findings_by_rule(findings, "auth_spf_fail") == []


class TestSpfSoftfail:
    def test_triggers_for_spf_softfail_without_fail(self, analyzer: SecurityAnalyzer):
        email = empty_email(
            from_address="sender@example.com",
            authentication_results=["mx.example.org; spf=softfail; dkim=pass"],
        )
        findings = analyzer.analyze(email, [])

        hits = findings_by_rule(findings, "auth_spf_softfail")
        assert len(hits) == 1
        assert hits[0].severity == FindingSeverity.MEDIUM
        assert "softfail" in hits[0].evidence["spf_results"]

    def test_fail_takes_precedence_over_softfail(self, analyzer: SecurityAnalyzer):
        email = empty_email(
            from_address="sender@example.com",
            authentication_results=["mx.example.org; spf=fail; spf=softfail"],
        )
        findings = analyzer.analyze(email, [])
        assert findings_by_rule(findings, "auth_spf_fail")
        assert findings_by_rule(findings, "auth_spf_softfail") == []


class TestDkimFail:
    def test_triggers_for_dkim_fail(self, analyzer: SecurityAnalyzer):
        email = empty_email(
            from_address="sender@example.com",
            authentication_results=["mx.example.org; spf=pass; dkim=fail"],
        )
        findings = analyzer.analyze(email, [])

        hits = findings_by_rule(findings, "auth_dkim_fail")
        assert len(hits) == 1
        assert hits[0].severity == FindingSeverity.HIGH
        assert "fail" in hits[0].evidence["dkim_results"]

    def test_clean_for_dkim_none(self, analyzer: SecurityAnalyzer):
        parsed = load_and_parse("multipart_with_attachment.eml")
        findings = analyzer.analyze(parsed, extract_iocs(parsed))
        assert findings_by_rule(findings, "auth_dkim_fail") == []


class TestDmarcFail:
    def test_triggers_for_dmarc_fail(self, analyzer: SecurityAnalyzer):
        email = empty_email(
            from_address="sender@example.com",
            authentication_results=["mx.example.org; spf=pass; dmarc=fail"],
        )
        findings = analyzer.analyze(email, [])

        hits = findings_by_rule(findings, "auth_dmarc_fail")
        assert len(hits) == 1
        assert hits[0].severity == FindingSeverity.HIGH
        assert "fail" in hits[0].evidence["dmarc_results"]

    def test_clean_for_dmarc_pass(self, analyzer: SecurityAnalyzer):
        parsed = load_and_parse("simple_plain.eml")
        findings = analyzer.analyze(parsed, extract_iocs(parsed))
        assert findings_by_rule(findings, "auth_dmarc_fail") == []


class TestMissingAuthenticationResults:
    def test_triggers_when_auth_results_missing_and_from_present(
        self, analyzer: SecurityAnalyzer
    ):
        email = empty_email(
            from_address="sender@example.com",
            authentication_results=[],
        )
        findings = analyzer.analyze(email, [])

        hits = findings_by_rule(findings, "auth_results_missing")
        assert len(hits) == 1
        assert hits[0].severity == FindingSeverity.LOW
        assert hits[0].evidence["authentication_results"] == []

    def test_clean_when_auth_results_missing_and_from_absent(
        self, analyzer: SecurityAnalyzer
    ):
        email = empty_email(authentication_results=[])
        findings = analyzer.analyze(email, [])
        assert findings_by_rule(findings, "auth_results_missing") == []


class TestMultipartFixtureIntegration:
    def test_multipart_fixture_reports_spf_and_dmarc_failures(
        self, analyzer: SecurityAnalyzer
    ):
        parsed = load_and_parse("multipart_with_attachment.eml")
        findings = analyzer.analyze(parsed, extract_iocs(parsed))

        assert findings_by_rule(findings, "auth_spf_fail")
        assert findings_by_rule(findings, "auth_dmarc_fail")


class TestMalformedAndEmptyInput:
    def test_empty_auth_header_string_does_not_crash(self, analyzer: SecurityAnalyzer):
        email = empty_email(
            from_address="sender@example.com",
            authentication_results=[""],
        )
        findings = analyzer.analyze(email, [])
        assert isinstance(findings, list)

    def test_garbage_auth_header_does_not_crash(self, analyzer: SecurityAnalyzer):
        email = empty_email(
            from_address="sender@example.com",
            authentication_results=["this is not a valid auth results header"],
        )
        findings = analyzer.analyze(email, [])
        assert isinstance(findings, list)

    def test_wrong_email_type_raises_type_error(self, analyzer: SecurityAnalyzer):
        with pytest.raises(TypeError):
            analyzer.analyze("bad", [])  # type: ignore[arg-type]

    def test_wrong_ioc_type_raises_type_error(self, analyzer: SecurityAnalyzer):
        with pytest.raises(TypeError):
            analyzer.analyze(empty_email(), "bad")  # type: ignore[arg-type]


class TestDeterministicOutput:
    def test_same_input_produces_identical_findings(self, analyzer: SecurityAnalyzer):
        parsed = load_and_parse("multipart_with_attachment.eml")
        iocs = extract_iocs(parsed)

        first = analyzer.analyze(parsed, iocs)
        second = analyzer.analyze(parsed, iocs)
        assert [(f.rule_id, f.evidence) for f in first] == [
            (f.rule_id, f.evidence) for f in second
        ]

    def test_findings_are_sorted_stably(self, analyzer: SecurityAnalyzer):
        parsed = load_and_parse("multipart_with_attachment.eml")
        findings = analyzer.analyze(parsed, extract_iocs(parsed))
        keys = [(f.category.value, f.severity.value, f.rule_id) for f in findings]
        assert keys == sorted(keys)
