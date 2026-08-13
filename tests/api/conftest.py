"""Shared fixtures for API tests."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.dependencies import get_db_session
from app.api.main import app
from app.infrastructure.database import configure_engine, init_db, reset_database_state

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


@pytest.fixture(autouse=True)
def isolated_db() -> Generator[None, None, None]:
    reset_database_state()
    configure_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    init_db()
    yield
    reset_database_state()


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    def override_get_db_session() -> Generator[Session, None, None]:
        from app.infrastructure.database import get_session_factory

        session = get_session_factory()()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db_session] = override_get_db_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def load_fixture(name: str) -> bytes:
    return (FIXTURES_DIR / name).read_bytes()


def without_analysis_id(payload: dict) -> dict:
    result = dict(payload)
    result.pop("analysis_id", None)
    return result
