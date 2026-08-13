"""Tests for HistoryRepository."""

from __future__ import annotations

from collections.abc import Generator

import pytest
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.schemas.responses import AnalyzeResponse
from app.api.serializers.analysis_result import serialize_analysis_result
from app.domain.pipeline import PhishLensAnalyzer
from app.infrastructure.database import configure_engine, init_db, reset_database_state
from app.infrastructure.history_repository import HistoryRepository
from tests.api.conftest import load_fixture


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    reset_database_state()
    configure_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    init_db()

    from app.infrastructure.database import get_session_factory

    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()
        reset_database_state()


@pytest.fixture
def repository(db_session: Session) -> HistoryRepository:
    return HistoryRepository(db_session)


def _sample_response() -> AnalyzeResponse:
    result = PhishLensAnalyzer().analyze(load_fixture("simple_plain.eml"))
    payload = serialize_analysis_result(result)
    return AnalyzeResponse.model_validate(payload)


def test_save_returns_uuid_string(repository: HistoryRepository):
    response = _sample_response()
    analysis_id = repository.save(response, source_type="upload", source_filename="test.eml")

    assert isinstance(analysis_id, str)
    assert len(analysis_id) == 36


def test_get_by_id_returns_saved_response(repository: HistoryRepository):
    response = _sample_response()
    analysis_id = repository.save(response, source_type="raw")

    loaded = repository.get_by_id(analysis_id)
    assert loaded is not None
    assert loaded.analysis_id == analysis_id
    assert loaded.parsed_email.subject == response.parsed_email.subject
    assert len(loaded.iocs) == len(response.iocs)
    assert loaded.risk_score.score == response.risk_score.score


def test_get_by_id_returns_none_for_missing_id(repository: HistoryRepository):
    assert repository.get_by_id("00000000-0000-0000-0000-000000000000") is None


def test_list_returns_summaries_and_total(repository: HistoryRepository):
    first = _sample_response()
    second_response = PhishLensAnalyzer().analyze(load_fixture("phishing_duplicate_iocs.eml"))
    second = AnalyzeResponse.model_validate(serialize_analysis_result(second_response))

    repository.save(first, source_type="upload", source_filename="simple_plain.eml")
    repository.save(second, source_type="raw")

    items, total = repository.list(limit=20, offset=0)
    assert total == 2
    assert len(items) == 2
    assert items[0].risk_score >= items[1].risk_score
    assert items[0].analysis_id != items[1].analysis_id


def test_list_respects_pagination(repository: HistoryRepository):
    for _ in range(3):
        repository.save(_sample_response(), source_type="raw")

    items, total = repository.list(limit=2, offset=1)
    assert total == 3
    assert len(items) == 2


def test_save_does_not_store_attachment_content(repository: HistoryRepository, db_session: Session):
    from app.infrastructure.models import AnalysisHistoryRecord

    response = AnalyzeResponse.model_validate(
        serialize_analysis_result(
            PhishLensAnalyzer().analyze(load_fixture("multipart_with_attachment.eml"))
        )
    )
    analysis_id = repository.save(response, source_type="upload", source_filename="multipart.eml")

    record = db_session.get(AnalysisHistoryRecord, analysis_id)
    assert record is not None
    assert "SW52b2ljZSAjMDAx" not in record.result_json
    assert '"content"' not in record.result_json
