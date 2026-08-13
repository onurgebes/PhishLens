"""
Phase 4: deduplication helpers.

Prevents the same (rule, evidence target) from inflating the score and
applies a per-rule instance cap so many similar hits cannot dominate.
"""

from __future__ import annotations

from app.domain.models import Finding
from app.domain.scoring.rule_weights import max_instances_for_rule, rule_weight, SEVERITY_BASE_POINTS


def dedup_key(finding: Finding) -> str:
    """
    Stable key derived from evidence so identical targets score once.

    Example: two pipeline passes both flag http://1.2.3.4/login with
    url_ip_literal_host → same dedup_key → counted once.
    """
    rule_id = finding.rule_id
    evidence = finding.evidence

    if rule_id.startswith("url_"):
        return str(evidence.get("url", ""))
    if rule_id.startswith("domain_"):
        return str(evidence.get("domain", ""))
    if rule_id.startswith("attachment_"):
        return str(evidence.get("filename", ""))
    return rule_id


def _finding_sort_key(finding: Finding) -> tuple[str, str, str, str]:
    return (
        finding.category.value,
        finding.severity.value,
        finding.rule_id,
        dedup_key(finding),
    )


def weighted_points_for(finding: Finding) -> float:
    base = SEVERITY_BASE_POINTS[finding.severity]
    return round(base * rule_weight(finding.rule_id), 2)


def deduplicate_findings(
    findings: list[Finding],
) -> list[tuple[Finding, int]]:
    """
    Collapse findings that share (rule_id, dedup_key).

    Returns (representative_finding, count_before_dedup) pairs in
    deterministic order.
    """
    groups: dict[tuple[str, str], list[Finding]] = {}
    for finding in sorted(findings, key=_finding_sort_key):
        key = (finding.rule_id, dedup_key(finding))
        groups.setdefault(key, []).append(finding)

    result: list[tuple[Finding, int]] = []
    for group_key in sorted(groups.keys()):
        group = groups[group_key]
        result.append((group[0], len(group)))
    return result


def apply_instance_cap(
    deduped: list[tuple[Finding, int]],
) -> list[tuple[Finding, int]]:
    """
    Keep at most N distinct instances per rule_id (default N=3).

    Example: five different bit.ly URLs → only the first two count when
    url_shortener override cap is 2; other rules use default cap 3.
    """
    by_rule: dict[str, list[tuple[Finding, int]]] = {}
    for finding, count in deduped:
        by_rule.setdefault(finding.rule_id, []).append((finding, count))

    capped: list[tuple[Finding, int]] = []
    for rule_id in sorted(by_rule.keys()):
        items = sorted(by_rule[rule_id], key=lambda item: dedup_key(item[0]))
        limit = max_instances_for_rule(rule_id)
        capped.extend(items[:limit])
    return capped
