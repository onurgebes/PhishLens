"""
Phase 4: risk scoring engine.

Consumes list[Finding] only — never imports parser, IOC extractor, or
analyzers. Same stateless pattern as earlier phases.
"""

from __future__ import annotations

from app.domain.models import (
    Finding,
    RiskLevel,
    RiskScore,
    ScoreContribution,
)
from app.domain.scoring.dedup import (
    apply_instance_cap,
    dedup_key,
    deduplicate_findings,
    weighted_points_for,
)
from app.domain.scoring.rule_weights import (
    RECOMMENDATIONS,
    SEVERITY_BASE_POINTS,
    score_to_level,
    rule_weight,
)


class RiskScoringEngine:
    """Stateless scorer: score() maps findings → RiskScore."""

    def score(self, findings: list[Finding]) -> RiskScore:
        if not isinstance(findings, list):
            raise TypeError("RiskScoringEngine.score() expects a list of Finding")

        deduped = apply_instance_cap(deduplicate_findings(findings))

        contributions: list[ScoreContribution] = []
        raw_points = 0.0

        for finding, count_before_dedup in deduped:
            base = SEVERITY_BASE_POINTS[finding.severity]
            weight = rule_weight(finding.rule_id)
            weighted = weighted_points_for(finding)
            raw_points += weighted
            contributions.append(
                ScoreContribution(
                    rule_id=finding.rule_id,
                    title=finding.title,
                    severity=finding.severity,
                    base_points=base,
                    rule_weight=weight,
                    weighted_points=weighted,
                    dedup_key=dedup_key(finding),
                    count_before_dedup=count_before_dedup,
                )
            )

        contributions.sort(
            key=lambda c: (-c.weighted_points, c.rule_id, c.dedup_key)
        )
        raw_points = round(raw_points, 2)
        normalized = min(100, round(raw_points))
        level = score_to_level(normalized)

        return RiskScore(
            score=normalized,
            level=level,
            raw_points=raw_points,
            contributions=contributions,
            summary=_build_summary(normalized, level, contributions),
            recommendation=RECOMMENDATIONS[level],
        )


def _build_summary(
    score: int,
    level: RiskLevel,
    contributions: list[ScoreContribution],
) -> str:
    level_label = level.value.upper()
    if not contributions:
        return (
            f"Risk score: {score}/100 ({level_label}). "
            "No suspicious findings detected."
        )

    top = contributions[:3]
    top_parts = [
        f"{item.title} (+{int(item.weighted_points) if item.weighted_points == int(item.weighted_points) else item.weighted_points})"
        for item in top
    ]
    return (
        f"Risk score: {score}/100 ({level_label}). "
        f"{len(contributions)} finding(s) contributed. "
        f"Top factors: {', '.join(top_parts)}."
    )
