"""
Unit tests for URLAnalyzer (Phase 3).
"""

from __future__ import annotations

import pytest

from app.domain.analyzers.url_analyzer import URLAnalyzer
from app.domain.models import FindingCategory, FindingSeverity, IOC, IOCType
from tests.unit.conftest import empty_email, extract_iocs, findings_by_rule, load_and_parse


@pytest.fixture
def analyzer() -> URLAnalyzer:
    return URLAnalyzer()


def url_iocs(*urls: str) -> list[IOC]:
    return [IOC(ioc_type=IOCType.URL, value=url, sources=["test"]) for url in urls]


class TestIpLiteralHost:
    def test_triggers_for_ip_hosted_url(self, analyzer: URLAnalyzer):
        email = empty_email()
        iocs = url_iocs("http://185.220.101.7/paypal/login.php")
        findings = analyzer.analyze(email, iocs)

        hits = findings_by_rule(findings, "url_ip_literal_host")
        assert len(hits) == 1
        assert hits[0].severity == FindingSeverity.HIGH
        assert hits[0].category == FindingCategory.URL
        assert hits[0].evidence["host"] == "185.220.101.7"
        assert hits[0].evidence["url"] == "http://185.220.101.7/paypal/login.php"

    def test_clean_for_domain_hosted_url(self, analyzer: URLAnalyzer):
        email = empty_email()
        iocs = url_iocs("https://example.com/help")
        findings = analyzer.analyze(email, iocs)
        assert findings_by_rule(findings, "url_ip_literal_host") == []

    def test_triggers_on_phishing_fixture(self, analyzer: URLAnalyzer):
        parsed = load_and_parse("phishing_duplicate_iocs.eml")
        findings = analyzer.analyze(parsed, extract_iocs(parsed))
        assert findings_by_rule(findings, "url_ip_literal_host")


class TestUrlShortener:
    def test_triggers_for_known_shortener(self, analyzer: URLAnalyzer):
        email = empty_email()
        iocs = url_iocs("https://bit.ly/abc123")
        findings = analyzer.analyze(email, iocs)

        hits = findings_by_rule(findings, "url_shortener")
        assert len(hits) == 1
        assert hits[0].severity == FindingSeverity.MEDIUM
        assert hits[0].evidence["host"] == "bit.ly"

    def test_clean_for_normal_domain(self, analyzer: URLAnalyzer):
        email = empty_email()
        iocs = url_iocs("https://example.com/page")
        findings = analyzer.analyze(email, iocs)
        assert findings_by_rule(findings, "url_shortener") == []


class TestAtSymbol:
    def test_triggers_when_url_contains_at_symbol(self, analyzer: URLAnalyzer):
        email = empty_email()
        iocs = url_iocs("http://user@evil.com@trusted.example/login")
        findings = analyzer.analyze(email, iocs)

        hits = findings_by_rule(findings, "url_at_symbol")
        assert len(hits) == 1
        assert hits[0].severity == FindingSeverity.HIGH
        assert "@" in hits[0].evidence["url"]

    def test_clean_for_normal_url(self, analyzer: URLAnalyzer):
        email = empty_email()
        iocs = url_iocs("https://example.com/login")
        findings = analyzer.analyze(email, iocs)
        assert findings_by_rule(findings, "url_at_symbol") == []


class TestSuspiciousTld:
    def test_triggers_for_abused_tld(self, analyzer: URLAnalyzer):
        email = empty_email()
        iocs = url_iocs("https://login-update.xyz/verify")
        findings = analyzer.analyze(email, iocs)

        hits = findings_by_rule(findings, "url_suspicious_tld")
        assert len(hits) == 1
        assert hits[0].evidence["tld"] == "xyz"
        assert hits[0].severity == FindingSeverity.MEDIUM

    def test_clean_for_common_tld(self, analyzer: URLAnalyzer):
        email = empty_email()
        iocs = url_iocs("https://example.com/help")
        findings = analyzer.analyze(email, iocs)
        assert findings_by_rule(findings, "url_suspicious_tld") == []


class TestExcessiveSubdomains:
    def test_triggers_for_long_subdomain_chain(self, analyzer: URLAnalyzer):
        email = empty_email()
        iocs = url_iocs("https://a.b.c.d.e.example.com/path")
        findings = analyzer.analyze(email, iocs)

        hits = findings_by_rule(findings, "url_excessive_subdomains")
        assert len(hits) == 1
        assert hits[0].severity == FindingSeverity.LOW
        assert hits[0].evidence["label_count"] == 7

    def test_clean_for_short_host(self, analyzer: URLAnalyzer):
        email = empty_email()
        iocs = url_iocs("https://www.example.com/path")
        findings = analyzer.analyze(email, iocs)
        assert findings_by_rule(findings, "url_excessive_subdomains") == []


class TestMalformedAndEmptyInput:
    def test_empty_iocs_produce_no_findings(self, analyzer: URLAnalyzer):
        findings = analyzer.analyze(empty_email(), [])
        assert findings == []

    def test_malformed_url_does_not_crash(self, analyzer: URLAnalyzer):
        email = empty_email()
        iocs = url_iocs("not-a-valid-url", "http://")
        findings = analyzer.analyze(email, iocs)
        assert isinstance(findings, list)

    def test_wrong_email_type_raises_type_error(self, analyzer: URLAnalyzer):
        with pytest.raises(TypeError):
            analyzer.analyze("bad", [])  # type: ignore[arg-type]

    def test_wrong_ioc_type_raises_type_error(self, analyzer: URLAnalyzer):
        with pytest.raises(TypeError):
            analyzer.analyze(empty_email(), "bad")  # type: ignore[arg-type]


class TestDeterministicOutput:
    def test_same_input_produces_identical_findings(self, analyzer: URLAnalyzer):
        parsed = load_and_parse("phishing_duplicate_iocs.eml")
        iocs = extract_iocs(parsed)

        first = analyzer.analyze(parsed, iocs)
        second = analyzer.analyze(parsed, iocs)
        assert [(f.rule_id, f.evidence) for f in first] == [
            (f.rule_id, f.evidence) for f in second
        ]

    def test_duplicate_url_iocs_deduplicate_findings_per_rule(self, analyzer: URLAnalyzer):
        email = empty_email()
        duplicate = "http://185.220.101.7/login"
        iocs = [
            IOC(ioc_type=IOCType.URL, value=duplicate, sources=["body:plain"]),
            IOC(ioc_type=IOCType.URL, value=duplicate, sources=["body:html"]),
        ]
        findings = analyzer.analyze(email, iocs)
        hits = findings_by_rule(findings, "url_ip_literal_host")
        assert len(hits) == 1
