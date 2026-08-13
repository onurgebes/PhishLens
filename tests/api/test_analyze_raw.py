"""Tests for POST /api/analyze/raw."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.domain.parser import MAX_EMAIL_SIZE_BYTES
from tests.api.conftest import load_fixture, without_analysis_id


def test_raw_simple_plain_fixture(client: TestClient):
    raw_text = load_fixture("simple_plain.eml").decode("utf-8")
    response = client.post("/api/analyze/raw", json={"raw_email": raw_text})

    assert response.status_code == 200
    payload = response.json()
    assert payload["analysis_id"]
    assert len(payload["iocs"]) == 9
    assert payload["findings"] == []
    assert payload["risk_score"]["level"] == "low"


def test_raw_phishing_fixture_matches_upload(client: TestClient):
    raw_bytes = load_fixture("phishing_duplicate_iocs.eml")
    raw_text = raw_bytes.decode("utf-8")

    upload_response = client.post(
        "/api/analyze",
        files={"file": ("phishing_duplicate_iocs.eml", raw_bytes, "message/rfc822")},
    )
    raw_response = client.post("/api/analyze/raw", json={"raw_email": raw_text})

    assert upload_response.status_code == 200
    assert raw_response.status_code == 200
    assert without_analysis_id(upload_response.json()) == without_analysis_id(raw_response.json())


def test_empty_raw_email_returns_422(client: TestClient):
    response = client.post("/api/analyze/raw", json={"raw_email": ""})

    assert response.status_code == 422


def test_oversized_raw_email_returns_413(client: TestClient):
    oversized = "A" * (MAX_EMAIL_SIZE_BYTES + 1)
    response = client.post("/api/analyze/raw", json={"raw_email": oversized})

    assert response.status_code == 413
    assert "maximum allowed size" in response.json()["detail"]
