"""API response schemas."""

from __future__ import annotations

from pydantic import BaseModel


class AttachmentResponse(BaseModel):
    filename: str | None
    content_type: str
    size_bytes: int


class ParsedEmailResponse(BaseModel):
    from_address: str | None
    to_addresses: list[str]
    cc_addresses: list[str]
    reply_to: str | None
    subject: str | None
    date: str | None
    message_id: str | None
    return_path: str | None
    received_headers: list[str]
    authentication_results: list[str]
    content_type: str
    body_plain: str | None
    body_html: str | None
    attachments: list[AttachmentResponse]
    raw_size_bytes: int
    parse_warnings: list[str]


class IOCResponse(BaseModel):
    ioc_type: str
    value: str
    sources: list[str]


class FindingResponse(BaseModel):
    rule_id: str
    category: str
    severity: str
    title: str
    description: str
    evidence: dict[str, str | list[str] | int | bool]


class ScoreContributionResponse(BaseModel):
    rule_id: str
    title: str
    severity: str
    base_points: int
    rule_weight: float
    weighted_points: float
    dedup_key: str
    count_before_dedup: int


class RiskScoreResponse(BaseModel):
    score: int
    level: str
    raw_points: float
    contributions: list[ScoreContributionResponse]
    summary: str
    recommendation: str


class AnalyzeResponse(BaseModel):
    analysis_id: str | None = None
    parsed_email: ParsedEmailResponse
    iocs: list[IOCResponse]
    findings: list[FindingResponse]
    risk_score: RiskScoreResponse


class HistorySummaryResponse(BaseModel):
    analysis_id: str
    created_at: str
    source_type: str
    source_filename: str | None
    subject: str | None
    from_address: str | None
    risk_score: int
    risk_level: str
    ioc_count: int
    finding_count: int


class HistoryListResponse(BaseModel):
    items: list[HistorySummaryResponse]
    total: int
    limit: int
    offset: int


class HealthResponse(BaseModel):
    status: str
    version: str


class ErrorResponse(BaseModel):
    detail: str
