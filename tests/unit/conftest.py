"""Shared helpers for Phase 3 analyzer unit tests."""

from __future__ import annotations

from pathlib import Path

from app.domain.ioc_extractor import IOCExtractor
from app.domain.models import Attachment, Finding, IOC, ParsedEmail
from app.domain.parser import EmailParser

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def load_and_parse(name: str) -> ParsedEmail:
    raw = (FIXTURES_DIR / name).read_bytes()
    return EmailParser().parse(raw)


def extract_iocs(email: ParsedEmail) -> list[IOC]:
    return IOCExtractor().extract(email)


def empty_email(**overrides) -> ParsedEmail:
    defaults = {
        "from_address": None,
        "to_addresses": [],
        "cc_addresses": [],
        "reply_to": None,
        "subject": None,
        "date": None,
        "message_id": None,
        "return_path": None,
        "received_headers": [],
        "authentication_results": [],
        "content_type": "text/plain",
        "body_plain": None,
        "body_html": None,
        "attachments": [],
        "raw_size_bytes": 0,
    }
    defaults.update(overrides)
    return ParsedEmail(**defaults)


def findings_by_rule(findings: list[Finding], rule_id: str) -> list[Finding]:
    return [finding for finding in findings if finding.rule_id == rule_id]


def rule_ids(findings: list[Finding]) -> set[str]:
    return {finding.rule_id for finding in findings}
