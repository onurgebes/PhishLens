"""Convert domain AnalysisResult objects into JSON-safe dictionaries."""

from __future__ import annotations

from app.domain.models import (
    AnalysisResult,
    Attachment,
    Finding,
    IOC,
    ParsedEmail,
    RiskScore,
    ScoreContribution,
)


def _serialize_evidence(
    evidence: dict[str, str | list[str] | int | bool],
) -> dict[str, str | list[str] | int | bool]:
    serialized: dict[str, str | list[str] | int | bool] = {}
    for key, value in evidence.items():
        if isinstance(value, list):
            serialized[key] = [str(item) for item in value]
        elif isinstance(value, bool | int):
            serialized[key] = value
        else:
            serialized[key] = str(value)
    return serialized


def serialize_attachment(attachment: Attachment) -> dict[str, str | int | None]:
    return {
        "filename": attachment.filename,
        "content_type": attachment.content_type,
        "size_bytes": attachment.size_bytes,
    }


def serialize_parsed_email(parsed_email: ParsedEmail) -> dict:
    return {
        "from_address": parsed_email.from_address,
        "to_addresses": list(parsed_email.to_addresses),
        "cc_addresses": list(parsed_email.cc_addresses),
        "reply_to": parsed_email.reply_to,
        "subject": parsed_email.subject,
        "date": parsed_email.date.isoformat() if parsed_email.date else None,
        "message_id": parsed_email.message_id,
        "return_path": parsed_email.return_path,
        "received_headers": list(parsed_email.received_headers),
        "authentication_results": list(parsed_email.authentication_results),
        "content_type": parsed_email.content_type,
        "body_plain": parsed_email.body_plain,
        "body_html": parsed_email.body_html,
        "attachments": [
            serialize_attachment(attachment)
            for attachment in parsed_email.attachments
        ],
        "raw_size_bytes": parsed_email.raw_size_bytes,
        "parse_warnings": list(parsed_email.parse_warnings),
    }


def serialize_ioc(ioc: IOC) -> dict:
    return {
        "ioc_type": ioc.ioc_type.value,
        "value": ioc.value,
        "sources": list(ioc.sources),
    }


def serialize_finding(finding: Finding) -> dict:
    return {
        "rule_id": finding.rule_id,
        "category": finding.category.value,
        "severity": finding.severity.value,
        "title": finding.title,
        "description": finding.description,
        "evidence": _serialize_evidence(finding.evidence),
    }


def serialize_score_contribution(contribution: ScoreContribution) -> dict:
    return {
        "rule_id": contribution.rule_id,
        "title": contribution.title,
        "severity": contribution.severity.value,
        "base_points": contribution.base_points,
        "rule_weight": contribution.rule_weight,
        "weighted_points": contribution.weighted_points,
        "dedup_key": contribution.dedup_key,
        "count_before_dedup": contribution.count_before_dedup,
    }


def serialize_risk_score(risk_score: RiskScore) -> dict:
    return {
        "score": risk_score.score,
        "level": risk_score.level.value,
        "raw_points": risk_score.raw_points,
        "contributions": [
            serialize_score_contribution(contribution)
            for contribution in risk_score.contributions
        ],
        "summary": risk_score.summary,
        "recommendation": risk_score.recommendation,
    }


def serialize_analysis_result(result: AnalysisResult) -> dict:
    """Map a domain AnalysisResult to a JSON-safe dictionary."""
    return {
        "parsed_email": serialize_parsed_email(result.parsed_email),
        "iocs": [serialize_ioc(ioc) for ioc in result.iocs],
        "findings": [serialize_finding(finding) for finding in result.findings],
        "risk_score": serialize_risk_score(result.risk_score),
    }
