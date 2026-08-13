"""FastAPI dependency injection helpers."""

from __future__ import annotations

from app.domain.pipeline import PhishLensAnalyzer


def get_analyzer() -> PhishLensAnalyzer:
    return PhishLensAnalyzer()
