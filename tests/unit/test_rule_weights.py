"""
Unit tests for Phase 4 scoring configuration (rule_weights.py).
"""

from __future__ import annotations

import pytest

from app.domain.models import FindingSeverity, RiskLevel
from app.domain.scoring.rule_weights import (
    DEFAULT_MAX_INSTANCES_PER_RULE,
    DEFAULT_RULE_WEIGHT,
    MAX_INSTANCES_OVERRIDES,
    RECOMMENDATIONS,
    RULE_WEIGHTS,
    SEVERITY_BASE_POINTS,
    max_instances_for_rule,
    rule_weight,
    score_to_level,
)

# Every rule_id currently emitted by Phase 3 analyzers.
PHASE3_RULE_IDS = frozenset(
    {
        "header_reply_to_domain_mismatch",
        "header_return_path_mismatch",
        "header_display_name_brand_spoofing",
        "header_missing_message_id",
        "url_ip_literal_host",
        "url_shortener",
        "url_at_symbol",
        "url_suspicious_tld",
        "url_excessive_subdomains",
        "domain_brand_impersonation",
        "domain_suspicious_tld",
        "domain_punycode",
        "attachment_dangerous_extension",
        "attachment_double_extension",
        "attachment_macro_enabled",
        "attachment_extension_mime_mismatch",
        "attachment_missing_filename",
        "auth_spf_fail",
        "auth_spf_softfail",
        "auth_dkim_fail",
        "auth_dmarc_fail",
        "auth_results_missing",
    }
)


class TestSeverityBasePoints:
    def test_every_finding_severity_has_base_points(self):
        for severity in FindingSeverity:
            assert severity in SEVERITY_BASE_POINTS
            assert SEVERITY_BASE_POINTS[severity] > 0

    def test_severity_ordering_is_monotonic(self):
        assert SEVERITY_BASE_POINTS[FindingSeverity.LOW] < SEVERITY_BASE_POINTS[
            FindingSeverity.MEDIUM
        ]
        assert SEVERITY_BASE_POINTS[FindingSeverity.MEDIUM] < SEVERITY_BASE_POINTS[
            FindingSeverity.HIGH
        ]
        assert SEVERITY_BASE_POINTS[FindingSeverity.HIGH] < SEVERITY_BASE_POINTS[
            FindingSeverity.CRITICAL
        ]


class TestRuleWeights:
    def test_every_phase3_rule_has_explicit_weight(self):
        assert set(RULE_WEIGHTS.keys()) == PHASE3_RULE_IDS

    def test_unknown_rule_uses_default_weight(self):
        assert rule_weight("future_unknown_rule") == DEFAULT_RULE_WEIGHT

    def test_all_weights_are_positive(self):
        for rule_id, weight in RULE_WEIGHTS.items():
            assert weight > 0, f"{rule_id} weight must be positive"


class TestInstanceCaps:
    def test_default_cap_is_three(self):
        assert DEFAULT_MAX_INSTANCES_PER_RULE == 3
        assert max_instances_for_rule("url_ip_literal_host") == 3

    def test_override_caps_are_lower_than_default(self):
        for rule_id, cap in MAX_INSTANCES_OVERRIDES.items():
            assert cap <= DEFAULT_MAX_INSTANCES_PER_RULE
            assert max_instances_for_rule(rule_id) == cap


class TestScoreToLevel:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (0, RiskLevel.LOW),
            (24, RiskLevel.LOW),
            (25, RiskLevel.MEDIUM),
            (49, RiskLevel.MEDIUM),
            (50, RiskLevel.HIGH),
            (74, RiskLevel.HIGH),
            (75, RiskLevel.CRITICAL),
            (100, RiskLevel.CRITICAL),
        ],
    )
    def test_threshold_mapping(self, score: int, expected: RiskLevel):
        assert score_to_level(score) == expected


class TestRecommendations:
    def test_every_risk_level_has_recommendation(self):
        for level in RiskLevel:
            assert level in RECOMMENDATIONS
            assert RECOMMENDATIONS[level]
