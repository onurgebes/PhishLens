"""
Domain models for PhishLens.

These are plain dataclasses with NO framework dependencies (no FastAPI,
no SQLAlchemy, no Pydantic). That's intentional: the domain layer should
be importable and unit-testable with nothing but the Python standard
library. See ARCHITECTURE.md section 8 for the reasoning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


@dataclass
class Attachment:
    """
    Metadata (+ raw bytes) for a single email attachment.

    IMPORTANT: `content` holds the raw bytes purely so a later phase
    (attachment analysis) can compute a hash. Nothing in this codebase
    ever opens, executes, or renders an attachment's content. See
    SECURITY.md / THREAT_MODEL.md.
    """

    filename: str | None
    content_type: str
    size_bytes: int
    content: bytes = field(repr=False)  # repr=False: keep repr()/logs short


@dataclass
class ParsedEmail:
    """
    The structured result of parsing a single .eml file or raw email
    source. This is Phase 1's entire output — no IOC extraction, no
    security analysis, no scoring happens here.
    """

    # Core headers
    from_address: str | None
    to_addresses: list[str]
    cc_addresses: list[str]
    reply_to: str | None
    subject: str | None
    date: datetime | None
    message_id: str | None
    return_path: str | None

    # Routing / authentication headers (kept as raw strings here;
    # structured parsing of these is Phase 3's job)
    received_headers: list[str]
    authentication_results: list[str]

    # MIME / body
    content_type: str
    body_plain: str | None
    body_html: str | None
    attachments: list[Attachment]

    # Bookkeeping
    raw_size_bytes: int
    parse_warnings: list[str] = field(default_factory=list)


class IOCType(str, Enum):
    """
    The IOC types PhishLens extracts in Phase 2. A str-based Enum so
    values serialize cleanly (e.g. to JSON later) as plain strings like
    "ipv4" rather than "IOCType.IPV4".
    """

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    SHA256 = "sha256"


@dataclass
class IOC:
    """
    A single extracted Indicator of Compromise: a fact, not a verdict.

    IOC extraction (Phase 2) only asks "what is present in this email?".
    It deliberately does NOT include a risk level or explanation --
    judging whether an IOC is suspicious is IOC *analysis* (Phase 3),
    a separate concern. See PHASE2_ARCHITECTURE notes / conversation.

    `sources` accumulates every place this exact IOC was observed
    (e.g. ["header:From", "body:plain"]) instead of collapsing to a
    single source, because repetition across multiple places is itself
    useful context for an analyst.
    """

    ioc_type: IOCType
    value: str
    sources: list[str] = field(default_factory=list)


class FindingCategory(str, Enum):
    """
    Which analyzer produced a finding. A str-based Enum so values
    serialize cleanly (e.g. "header" rather than "FindingCategory.HEADER").
    """

    HEADER = "header"
    URL = "url"
    DOMAIN = "domain"
    ATTACHMENT = "attachment"
    AUTHENTICATION = "authentication"


class FindingSeverity(str, Enum):
    """Analyst-facing severity for a single rule hit — not a composite score."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """
    A single rule-based observation from Phase 3 analysis.

    Findings explain *why* something looks suspicious. They deliberately
    do NOT include a composite risk score — that is Phase 4's job.
    """

    rule_id: str
    category: FindingCategory
    severity: FindingSeverity
    title: str
    description: str
    evidence: dict[str, str | list[str] | int | bool] = field(default_factory=dict)


class RiskLevel(str, Enum):
    """
    Overall email risk band produced by Phase 4 scoring.

    Distinct from FindingSeverity: that rates a single rule hit; this
    rates the whole message after combining all findings.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ScoreContribution:
    """
    One finding's contribution to the final risk score.

    Stored explicitly so the UI can show a transparent breakdown
    ("why 72/100?") without re-running analyzers.
    """

    rule_id: str
    title: str
    severity: FindingSeverity
    base_points: int
    rule_weight: float
    weighted_points: float
    dedup_key: str
    count_before_dedup: int = 1


@dataclass
class RiskScore:
    """Phase 4 output: normalized score, level, and human-readable explanation."""

    score: int
    level: RiskLevel
    raw_points: float
    contributions: list[ScoreContribution] = field(default_factory=list)
    summary: str = ""
    recommendation: str = ""


@dataclass
class AnalysisResult:
    """
    Complete output of the Phase 1–4 analysis pipeline.

    Bundles every structured artifact produced from a single raw email
    so callers (CLI, API — later phases) need one type instead of four.
    Parse warnings live on ``parsed_email.parse_warnings``; they are not
    duplicated here.
    """

    parsed_email: ParsedEmail
    iocs: list[IOC]
    findings: list[Finding]
    risk_score: RiskScore
