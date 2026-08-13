"""
Phase 1–4 orchestration: one entry point for full email analysis.

This module only wires existing components together. It does not
implement parsing, extraction, analysis, or scoring logic itself.
"""

from __future__ import annotations

from app.domain.analyzers import (
    AttachmentAnalyzer,
    DomainAnalyzer,
    HeaderAnalyzer,
    SecurityAnalyzer,
    URLAnalyzer,
)
from app.domain.ioc_extractor import IOCExtractor
from app.domain.models import AnalysisResult, Finding
from app.domain.parser import EmailParser
from app.domain.scoring import RiskScoringEngine


class PhishLensAnalyzer:
    """
    Stateless pipeline: analyze() takes raw email bytes and returns a
    complete AnalysisResult.

    Same pattern as EmailParser / IOCExtractor / RiskScoringEngine —
    no instance state, no network calls.
    """

    def analyze(self, raw_bytes: bytes) -> AnalysisResult:
        if not isinstance(raw_bytes, (bytes, bytearray)):
            raise TypeError("PhishLensAnalyzer.analyze() expects raw bytes")

        parsed_email = EmailParser().parse(raw_bytes)
        iocs = IOCExtractor().extract(parsed_email)

        findings: list[Finding] = []
        for analyzer in (
            HeaderAnalyzer(),
            URLAnalyzer(),
            DomainAnalyzer(),
            AttachmentAnalyzer(),
            SecurityAnalyzer(),
        ):
            findings.extend(analyzer.analyze(parsed_email, iocs))

        risk_score = RiskScoringEngine().score(findings)

        return AnalysisResult(
            parsed_email=parsed_email,
            iocs=iocs,
            findings=findings,
            risk_score=risk_score,
        )
