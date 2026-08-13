"""
Unit tests for RiskScoringEngine (Phase 4).
"""

from __future__ import annotations

import pytest

from app.domain.analyzers.attachment_analyzer import AttachmentAnalyzer
from app.domain.analyzers.domain_analyzer import DomainAnalyzer
from app.domain.analyzers.header_analyzer import HeaderAnalyzer
from app.domain.analyzers.security_analyzer import SecurityAnalyzer
from app.domain.analyzers.url_analyzer import URLAnalyzer
from app.domain.models import Finding, FindingCategory, FindingSeverity, RiskLevel
from app.domain.scoring.risk_engine import RiskScoringEngine
from tests.unit.conftest import empty_email, extract_iocs, load_and_parse


@pytest.fixture
def engine() -> RiskScoringEngine:
    return RiskScoringEngine()


def make_finding(
    rule_id: str,
    *,
    severity: FindingSeverity,
    title: str = "Test",
    evidence: dict | None = None,
    category: FindingCategory = FindingCategory.HEADER,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category=category,
        severity=severity,
        title=title,
        description="test",
        evidence=evidence or {},
    )


def collect_all_phase3_findings(fixture_name: str) -> list[Finding]:
    parsed = load_and_parse(fixture_name)
    iocs = extract_iocs(parsed)
    findings: list[Finding] = []
    findings.extend(HeaderAnalyzer().analyze(parsed, iocs))
    findings.extend(URLAnalyzer().analyze(parsed, iocs))
    findings.extend(DomainAnalyzer().analyze(parsed, iocs))
    findings.extend(AttachmentAnalyzer().analyze(parsed, iocs))
    findings.extend(SecurityAnalyzer().analyze(parsed, iocs))
    return findings


class TestEmptyAndCleanInput:
    def test_empty_findings_yield_zero_low_risk(self, engine: RiskScoringEngine):
        result = engine.score([])

        assert result.score == 0
        assert result.level == RiskLevel.LOW
        assert result.raw_points == 0.0
        assert result.contributions == []
        assert "No suspicious findings" in result.summary
        assert result.recommendation

    def test_simple_plain_fixture_scores_low(self, engine: RiskScoringEngine):
        parsed = load_and_parse("simple_plain.eml")
        findings = collect_all_phase3_findings("simple_plain.eml")
        # simple_plain should produce no Phase 3 findings
        assert findings == []
        result = engine.score(findings)
        assert result.score == 0
        assert result.level == RiskLevel.LOW


class TestSingleFindingScoring:
    def test_single_low_finding_scores_in_low_band(self, engine: RiskScoringEngine):
        finding = make_finding(
            "header_missing_message_id",
            severity=FindingSeverity.LOW,
            title="Missing Message-ID",
        )
        result = engine.score([finding])
        # 5 base × 0.4 weight = 2
        assert result.score == 2
        assert result.level == RiskLevel.LOW
        assert len(result.contributions) == 1
        assert result.contributions[0].weighted_points == 2.0

    def test_critical_attachment_scores_high_or_above(self, engine: RiskScoringEngine):
        finding = make_finding(
            "attachment_dangerous_extension",
            severity=FindingSeverity.CRITICAL,
            title="Dangerous extension",
            category=FindingCategory.ATTACHMENT,
            evidence={"filename": "malware.exe"},
        )
        result = engine.score([finding])
        # 45 × 1.2 = 54 → HIGH band
        assert result.score == 54
        assert result.level == RiskLevel.HIGH


class TestCombinedFindings:
    def test_multiple_findings_sum_with_linear_cap(self, engine: RiskScoringEngine):
        findings = [
            make_finding(
                "header_display_name_brand_spoofing",
                severity=FindingSeverity.HIGH,
                title="Brand spoof",
            ),
            make_finding(
                "auth_spf_fail",
                severity=FindingSeverity.HIGH,
                title="SPF fail",
                category=FindingCategory.AUTHENTICATION,
            ),
        ]
        result = engine.score(findings)
        # 30×1.3 + 30×1.1 = 39 + 33 = 72 → HIGH
        assert result.raw_points == 72.0
        assert result.score == 72
        assert result.level == RiskLevel.HIGH
        assert len(result.contributions) == 2

    def test_raw_points_above_100_are_capped(self, engine: RiskScoringEngine):
        findings = [
            make_finding(
                "attachment_dangerous_extension",
                severity=FindingSeverity.CRITICAL,
                title="Dangerous",
                category=FindingCategory.ATTACHMENT,
                evidence={"filename": f"bad{i}.exe"},
            )
            for i in range(3)
        ]
        result = engine.score(findings)
        # 3 × 54 = 162 raw → capped at 100
        assert result.raw_points == 162.0
        assert result.score == 100
        assert result.level == RiskLevel.CRITICAL


class TestPhishingFixtureIntegration:
    def test_phishing_fixture_produces_high_or_critical_score(
        self, engine: RiskScoringEngine
    ):
        findings = collect_all_phase3_findings("phishing_duplicate_iocs.eml")
        assert findings  # sanity: Phase 3 should emit findings
        result = engine.score(findings)
        assert result.score >= 50
        assert result.level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
        assert result.contributions
        assert "Risk score:" in result.summary


class TestDedupInEngine:
    def test_duplicate_findings_do_not_double_score(self, engine: RiskScoringEngine):
        url = "http://185.220.101.7/login"
        finding = make_finding(
            "url_ip_literal_host",
            severity=FindingSeverity.HIGH,
            title="IP URL",
            category=FindingCategory.URL,
            evidence={"url": url},
        )
        once = engine.score([finding])
        twice = engine.score([finding, finding])
        assert once.score == twice.score
        assert twice.contributions[0].count_before_dedup == 2


class TestRiskLevelThresholds:
    def test_low_band_example(self, engine: RiskScoringEngine):
        findings = [
            make_finding("header_missing_message_id", severity=FindingSeverity.LOW)
        ]
        result = engine.score(findings)
        assert result.score == 2
        assert result.level == RiskLevel.LOW

    def test_medium_band_example(self, engine: RiskScoringEngine):
        findings = [
            make_finding(
                "header_return_path_mismatch",
                severity=FindingSeverity.MEDIUM,
                title="Return path",
            ),
            make_finding(
                "url_shortener",
                severity=FindingSeverity.MEDIUM,
                title="Shortener",
                category=FindingCategory.URL,
                evidence={"url": "https://bit.ly/abc"},
            ),
        ]
        # 15×1.0 + 15×0.8 = 27 → MEDIUM
        result = engine.score(findings)
        assert result.score == 27
        assert result.level == RiskLevel.MEDIUM

    def test_high_band_example(self, engine: RiskScoringEngine):
        findings = [
            make_finding(
                "attachment_dangerous_extension",
                severity=FindingSeverity.CRITICAL,
                title="Dangerous extension",
                category=FindingCategory.ATTACHMENT,
                evidence={"filename": "malware.exe"},
            )
        ]
        # 45×1.2 = 54 → HIGH
        result = engine.score(findings)
        assert result.score == 54
        assert result.level == RiskLevel.HIGH

    def test_critical_band_via_phishing_fixture(self, engine: RiskScoringEngine):
        findings = collect_all_phase3_findings("phishing_duplicate_iocs.eml")
        result = engine.score(findings)
        assert result.score == 100
        assert result.level == RiskLevel.CRITICAL


class TestMalformedInput:
    def test_wrong_input_type_raises_type_error(self, engine: RiskScoringEngine):
        with pytest.raises(TypeError):
            engine.score("not a list")  # type: ignore[arg-type]


class TestDeterministicOutput:
    def test_same_findings_produce_identical_risk_score(
        self, engine: RiskScoringEngine
    ):
        findings = collect_all_phase3_findings("phishing_duplicate_iocs.eml")
        first = engine.score(findings)
        second = engine.score(list(reversed(findings)))
        assert first == second

    def test_contributions_sorted_by_weight_descending(
        self, engine: RiskScoringEngine
    ):
        findings = collect_all_phase3_findings("phishing_duplicate_iocs.eml")
        result = engine.score(findings)
        weights = [c.weighted_points for c in result.contributions]
        assert weights == sorted(weights, reverse=True)
