"""Shared fixtures for API tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.main import app

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def load_fixture(name: str) -> bytes:
    return (FIXTURES_DIR / name).read_bytes()
