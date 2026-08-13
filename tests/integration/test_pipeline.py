"""
Integration tests for the Phase 1–4 analysis pipeline.

These exercise PhishLensAnalyzer end-to-end over real .eml fixtures.
Unit tests for individual phases remain in tests/unit/.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.domain.models import RiskLevel
from app.domain.pipeline import PhishLensAnalyzer

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def analyzer() -> PhishLensAnalyzer:
    return PhishLensAnalyzer()


def load_fixture(name: str) -> bytes:
    return (FIXTURES_DIR / name).read_bytes()


class TestSimplePlainEmail:
    def test_pipeline_produces_expected_outputs(self, analyzer: PhishLensAnalyzer):
        result = analyzer.analyze(load_fixture("simple_plain.eml"))

        assert result.parsed_email.from_address is not None
        assert "alice@example.com" in result.parsed_email.from_address
        assert result.parsed_email.parse_warnings == []
        assert len(result.iocs) == 9
        assert result.findings == []
        assert result.risk_score.score == 0
        assert result.risk_score.level == RiskLevel.LOW


class TestPhishingDuplicateIocs:
    def test_pipeline_produces_expected_outputs(self, analyzer: PhishLensAnalyzer):
        result = analyzer.analyze(load_fixture("phishing_duplicate_iocs.eml"))

        assert len(result.iocs) == 10
        assert len(result.findings) == 5
        assert result.risk_score.score == 100
        assert result.risk_score.level == RiskLevel.CRITICAL

        rule_ids = {finding.rule_id for finding in result.findings}
        assert "header_display_name_brand_spoofing" in rule_ids
        assert "url_ip_literal_host" in rule_ids
        assert "domain_brand_impersonation" in rule_ids


class TestMultipartWithAttachment:
    def test_pipeline_produces_expected_outputs(self, analyzer: PhishLensAnalyzer):
        result = analyzer.analyze(load_fixture("multipart_with_attachment.eml"))

        assert len(result.iocs) == 9
        assert len(result.findings) == 2
        assert result.risk_score.score == 66
        assert result.risk_score.level == RiskLevel.HIGH
        assert len(result.parsed_email.attachments) == 1

        rule_ids = {finding.rule_id for finding in result.findings}
        assert rule_ids == {"auth_spf_fail", "auth_dmarc_fail"}


class TestMalformedHeaders:
    def test_pipeline_produces_expected_outputs(self, analyzer: PhishLensAnalyzer):
        result = analyzer.analyze(load_fixture("malformed_headers.eml"))

        assert result.parsed_email.date is None
        assert len(result.iocs) == 6
        assert len(result.findings) == 1
        assert result.risk_score.score == 2
        assert result.risk_score.level == RiskLevel.LOW
        assert result.findings[0].rule_id == "auth_results_missing"


class TestDeterministicOutput:
    def test_same_raw_email_produces_identical_analysis_result(
        self, analyzer: PhishLensAnalyzer
    ):
        raw = load_fixture("phishing_duplicate_iocs.eml")

        first = analyzer.analyze(raw)
        second = analyzer.analyze(raw)

        assert first == second


class TestInputValidation:
    def test_non_bytes_input_raises_type_error(self, analyzer: PhishLensAnalyzer):
        with pytest.raises(TypeError):
            analyzer.analyze("not bytes")  # type: ignore[arg-type]
