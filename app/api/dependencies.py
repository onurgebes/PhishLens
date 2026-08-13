"""FastAPI dependency injection helpers."""

from __future__ import annotations

from collections.abc import Generator

from fastapi import Depends
from sqlalchemy.orm import Session

from app.domain.pipeline import PhishLensAnalyzer
from app.infrastructure.database import get_session_factory
from app.infrastructure.history_repository import HistoryRepository


def get_analyzer() -> PhishLensAnalyzer:
    return PhishLensAnalyzer()


def get_db_session() -> Generator[Session, None, None]:
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def get_history_repository(
    session: Session = Depends(get_db_session),
) -> HistoryRepository:
    return HistoryRepository(session)
