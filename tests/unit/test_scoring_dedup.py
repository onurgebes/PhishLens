"""
Unit tests for Phase 4 deduplication (dedup.py).
"""

from __future__ import annotations

from app.domain.models import Finding, FindingCategory, FindingSeverity
from app.domain.scoring.dedup import (
    apply_instance_cap,
    dedup_key,
    deduplicate_findings,
    weighted_points_for,
)


def make_finding(
    rule_id: str,
    *,
    severity: FindingSeverity = FindingSeverity.HIGH,
    evidence: dict | None = None,
    title: str = "Test finding",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category=FindingCategory.URL,
        severity=severity,
        title=title,
        description="test",
        evidence=evidence or {},
    )


class TestDedupKey:
    def test_url_rules_use_url_evidence(self):
        finding = make_finding(
            "url_ip_literal_host",
            evidence={"url": "http://1.2.3.4/login"},
        )
        assert dedup_key(finding) == "http://1.2.3.4/login"

    def test_domain_rules_use_domain_evidence(self):
        finding = make_finding(
            "domain_brand_impersonation",
            evidence={"domain": "paypa1-secure.com"},
        )
        assert dedup_key(finding) == "paypa1-secure.com"

    def test_attachment_rules_use_filename_evidence(self):
        finding = make_finding(
            "attachment_dangerous_extension",
            evidence={"filename": "malware.exe"},
        )
        assert dedup_key(finding) == "malware.exe"

    def test_header_rules_use_rule_id_only(self):
        finding = make_finding(
            "header_reply_to_domain_mismatch",
            evidence={"from_domain": "a.com", "reply_to_domain": "b.com"},
        )
        assert dedup_key(finding) == "header_reply_to_domain_mismatch"


class TestDeduplicateFindings:
    def test_identical_rule_and_target_collapses_to_one(self):
        url = "http://1.2.3.4/login"
        findings = [
            make_finding("url_ip_literal_host", evidence={"url": url}),
            make_finding("url_ip_literal_host", evidence={"url": url}),
        ]
        deduped = deduplicate_findings(findings)
        assert len(deduped) == 1
        assert deduped[0][1] == 2  # count_before_dedup

    def test_different_urls_remain_separate(self):
        findings = [
            make_finding("url_ip_literal_host", evidence={"url": "http://1.1.1.1/a"}),
            make_finding("url_ip_literal_host", evidence={"url": "http://2.2.2.2/b"}),
        ]
        deduped = deduplicate_findings(findings)
        assert len(deduped) == 2

    def test_output_order_is_deterministic(self):
        findings = [
            make_finding("url_shortener", evidence={"url": "https://bit.ly/z"}),
            make_finding("url_ip_literal_host", evidence={"url": "http://1.1.1.1/a"}),
        ]
        first = deduplicate_findings(findings)
        second = deduplicate_findings(list(reversed(findings)))
        assert [dedup_key(f) for f, _ in first] == [dedup_key(f) for f, _ in second]


class TestApplyInstanceCap:
    def test_default_cap_limits_to_three_instances_per_rule(self):
        findings = [
            make_finding("url_ip_literal_host", evidence={"url": f"http://{i}.0.0.1/a"})
            for i in range(5)
        ]
        deduped = deduplicate_findings(findings)
        capped = apply_instance_cap(deduped)
        assert len(capped) == 3

    def test_shortener_override_cap_is_two(self):
        findings = [
            make_finding("url_shortener", evidence={"url": f"https://bit.ly/{i}"})
            for i in range(4)
        ]
        deduped = deduplicate_findings(findings)
        capped = apply_instance_cap(deduped)
        assert len(capped) == 2


class TestWeightedPointsFor:
    def test_high_severity_with_weight_is_base_times_weight(self):
        finding = make_finding(
            "url_at_symbol",
            severity=FindingSeverity.HIGH,
            evidence={"url": "http://x@y"},
        )
        # HIGH base = 30, url_at_symbol weight = 1.3 → 39.0
        assert weighted_points_for(finding) == 39.0
