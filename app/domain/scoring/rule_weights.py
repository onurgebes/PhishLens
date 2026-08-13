"""
Phase 4: static scoring configuration.

Pure data — no Finding objects, no I/O. Every Phase 3 rule_id that
currently exists in the project has an explicit weight entry so adding
a new analyzer rule without updating this file fails loudly in tests.
"""

from __future__ import annotations

from app.domain.models import FindingSeverity, RiskLevel

# Base points before per-rule weight is applied.
SEVERITY_BASE_POINTS: dict[FindingSeverity, int] = {
    FindingSeverity.LOW: 5,
    FindingSeverity.MEDIUM: 15,
    FindingSeverity.HIGH: 30,
    FindingSeverity.CRITICAL: 45,
}

# Per-rule multipliers (approved design table).
RULE_WEIGHTS: dict[str, float] = {
    "header_reply_to_domain_mismatch": 1.2,
    "header_return_path_mismatch": 1.0,
    "header_display_name_brand_spoofing": 1.3,
    "header_missing_message_id": 0.4,
    "url_ip_literal_host": 1.2,
    "url_shortener": 0.8,
    "url_at_symbol": 1.3,
    "url_suspicious_tld": 0.9,
    "url_excessive_subdomains": 0.6,
    "domain_brand_impersonation": 1.3,
    "domain_suspicious_tld": 0.9,
    "domain_punycode": 1.2,
    "attachment_dangerous_extension": 1.2,
    "attachment_double_extension": 1.1,
    "attachment_macro_enabled": 1.0,
    "attachment_extension_mime_mismatch": 0.9,
    "attachment_missing_filename": 0.5,
    "auth_spf_fail": 1.1,
    "auth_spf_softfail": 0.7,
    "auth_dkim_fail": 1.0,
    "auth_dmarc_fail": 1.1,
    "auth_results_missing": 0.5,
}

DEFAULT_RULE_WEIGHT: float = 1.0
DEFAULT_MAX_INSTANCES_PER_RULE: int = 3

# Optional stricter caps for noisy multi-instance rules (design note).
MAX_INSTANCES_OVERRIDES: dict[str, int] = {
    "url_shortener": 2,
    "url_suspicious_tld": 2,
    "url_excessive_subdomains": 2,
}

# Score bands (approved thresholds).
RISK_LEVEL_THRESHOLDS: tuple[tuple[int, RiskLevel], ...] = (
    (24, RiskLevel.LOW),
    (49, RiskLevel.MEDIUM),
    (74, RiskLevel.HIGH),
    (100, RiskLevel.CRITICAL),
)

RECOMMENDATIONS: dict[RiskLevel, str] = {
    RiskLevel.LOW: (
        "Normal islem akisina devam edebilirsiniz. "
        "(Low risk — standard caution is sufficient.)"
    ),
    RiskLevel.MEDIUM: (
        "Gondereni dogrulamadan linklere tiklamayin. "
        "(Medium risk — verify the sender before clicking links.)"
    ),
    RiskLevel.HIGH: (
        "Bu email phishing olabilir. Link veya ek acmayin. "
        "(High risk — do not open links or attachments.)"
    ),
    RiskLevel.CRITICAL: (
        "Emaili silin ve IT guvenlik ekibine iletin. "
        "(Critical risk — delete the email and report to IT security.)"
    ),
}


def rule_weight(rule_id: str) -> float:
    return RULE_WEIGHTS.get(rule_id, DEFAULT_RULE_WEIGHT)


def max_instances_for_rule(rule_id: str) -> int:
    return MAX_INSTANCES_OVERRIDES.get(rule_id, DEFAULT_MAX_INSTANCES_PER_RULE)


def score_to_level(score: int) -> RiskLevel:
    for upper_bound, level in RISK_LEVEL_THRESHOLDS:
        if score <= upper_bound:
            return level
    return RiskLevel.CRITICAL
