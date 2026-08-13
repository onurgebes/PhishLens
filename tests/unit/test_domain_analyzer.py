"""
Unit tests for DomainAnalyzer (Phase 3).
"""

from __future__ import annotations

import pytest

from app.domain.analyzers.domain_analyzer import DomainAnalyzer
from app.domain.models import FindingCategory, FindingSeverity, IOC, IOCType
from tests.unit.conftest import empty_email, extract_iocs, findings_by_rule, load_and_parse


@pytest.fixture
def analyzer() -> DomainAnalyzer:
    return DomainAnalyzer()


def domain_iocs(*domains: str) -> list[IOC]:
    return [
        IOC(ioc_type=IOCType.DOMAIN, value=domain, sources=["test"])
        for domain in domains
    ]


class TestBrandImpersonation:
    def test_triggers_for_typosquatted_brand_domain(self, analyzer: DomainAnalyzer):
        email = empty_email()
        iocs = domain_iocs("paypa1-secure.com")
        findings = analyzer.analyze(email, iocs)

        hits = findings_by_rule(findings, "domain_brand_impersonation")
        assert len(hits) == 1
        assert hits[0].severity == FindingSeverity.HIGH
        assert hits[0].category == FindingCategory.DOMAIN
        assert hits[0].evidence["brand"] == "PayPal"
        assert hits[0].evidence["domain"] == "paypa1-secure.com"

    def test_clean_for_legitimate_brand_domain(self, analyzer: DomainAnalyzer):
        email = empty_email()
        iocs = domain_iocs("paypal.com")
        findings = analyzer.analyze(email, iocs)
        assert findings_by_rule(findings, "domain_brand_impersonation") == []

    def test_triggers_on_phishing_fixture(self, analyzer: DomainAnalyzer):
        parsed = load_and_parse("phishing_duplicate_iocs.eml")
        findings = analyzer.analyze(parsed, extract_iocs(parsed))
        hits = findings_by_rule(findings, "domain_brand_impersonation")
        assert hits
        assert any(hit.evidence["domain"] == "paypa1-secure.com" for hit in hits)


class TestSuspiciousTld:
    def test_triggers_for_abused_tld(self, analyzer: DomainAnalyzer):
        email = empty_email()
        iocs = domain_iocs("secure-login.xyz")
        findings = analyzer.analyze(email, iocs)

        hits = findings_by_rule(findings, "domain_suspicious_tld")
        assert len(hits) == 1
        assert hits[0].evidence["tld"] == "xyz"
        assert hits[0].severity == FindingSeverity.MEDIUM

    def test_clean_for_common_tld(self, analyzer: DomainAnalyzer):
        email = empty_email()
        iocs = domain_iocs("example.com")
        findings = analyzer.analyze(email, iocs)
        assert findings_by_rule(findings, "domain_suspicious_tld") == []


class TestPunycode:
    def test_triggers_for_punycode_domain(self, analyzer: DomainAnalyzer):
        email = empty_email()
        iocs = domain_iocs("xn--pple-43d.com")
        findings = analyzer.analyze(email, iocs)

        hits = findings_by_rule(findings, "domain_punycode")
        assert len(hits) == 1
        assert hits[0].severity == FindingSeverity.HIGH
        assert hits[0].evidence["domain"] == "xn--pple-43d.com"

    def test_clean_for_ascii_domain(self, analyzer: DomainAnalyzer):
        email = empty_email()
        iocs = domain_iocs("example.com")
        findings = analyzer.analyze(email, iocs)
        assert findings_by_rule(findings, "domain_punycode") == []


class TestMalformedAndEmptyInput:
    def test_empty_iocs_produce_no_findings(self, analyzer: DomainAnalyzer):
        findings = analyzer.analyze(empty_email(), [])
        assert findings == []

    def test_bare_hostname_without_tld_does_not_crash(self, analyzer: DomainAnalyzer):
        email = empty_email()
        iocs = domain_iocs("localhost", "mailserver")
        findings = analyzer.analyze(email, iocs)
        assert isinstance(findings, list)

    def test_wrong_email_type_raises_type_error(self, analyzer: DomainAnalyzer):
        with pytest.raises(TypeError):
            analyzer.analyze("bad", [])  # type: ignore[arg-type]

    def test_wrong_ioc_type_raises_type_error(self, analyzer: DomainAnalyzer):
        with pytest.raises(TypeError):
            analyzer.analyze(empty_email(), "bad")  # type: ignore[arg-type]


class TestDeterministicOutput:
    def test_same_input_produces_identical_findings(self, analyzer: DomainAnalyzer):
        parsed = load_and_parse("phishing_duplicate_iocs.eml")
        iocs = extract_iocs(parsed)

        first = analyzer.analyze(parsed, iocs)
        second = analyzer.analyze(parsed, iocs)
        assert [(f.rule_id, f.evidence) for f in first] == [
            (f.rule_id, f.evidence) for f in second
        ]

    def test_duplicate_domain_iocs_deduplicate_findings(self, analyzer: DomainAnalyzer):
        email = empty_email()
        iocs = [
            IOC(ioc_type=IOCType.DOMAIN, value="paypa1-secure.com", sources=["a"]),
            IOC(ioc_type=IOCType.DOMAIN, value="paypa1-secure.com", sources=["b"]),
        ]
        findings = analyzer.analyze(email, iocs)
        hits = findings_by_rule(findings, "domain_brand_impersonation")
        assert len(hits) == 1
