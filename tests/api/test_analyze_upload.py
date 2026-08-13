"""Tests for POST /api/analyze (multipart .eml upload)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.domain.parser import MAX_EMAIL_SIZE_BYTES
from tests.api.conftest import load_fixture, without_analysis_id


def test_upload_simple_plain_fixture(client: TestClient):
    response = client.post(
        "/api/analyze",
        files={"file": ("simple_plain.eml", load_fixture("simple_plain.eml"), "message/rfc822")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["analysis_id"]
    assert len(payload["iocs"]) == 9
    assert payload["findings"] == []
    assert payload["risk_score"]["score"] == 0
    assert payload["risk_score"]["level"] == "low"


def test_upload_phishing_fixture(client: TestClient):
    response = client.post(
        "/api/analyze",
        files={
            "file": (
                "phishing_duplicate_iocs.eml",
                load_fixture("phishing_duplicate_iocs.eml"),
                "message/rfc822",
            )
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["analysis_id"]
    assert len(payload["iocs"]) == 10
    assert len(payload["findings"]) == 5
    assert payload["risk_score"]["score"] == 100
    assert payload["risk_score"]["level"] == "critical"


def test_upload_multipart_fixture(client: TestClient):
    response = client.post(
        "/api/analyze",
        files={
            "file": (
                "multipart_with_attachment.eml",
                load_fixture("multipart_with_attachment.eml"),
                "message/rfc822",
            )
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert len(payload["iocs"]) == 9
    assert len(payload["findings"]) == 2
    assert payload["risk_score"]["score"] == 66
    assert payload["risk_score"]["level"] == "high"
    assert len(payload["parsed_email"]["attachments"]) == 1


def test_upload_malformed_headers_fixture(client: TestClient):
    response = client.post(
        "/api/analyze",
        files={
            "file": (
                "malformed_headers.eml",
                load_fixture("malformed_headers.eml"),
                "message/rfc822",
            )
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert len(payload["iocs"]) == 6
    assert len(payload["findings"]) == 1
    assert payload["risk_score"]["score"] == 2
    assert payload["findings"][0]["rule_id"] == "auth_results_missing"


def test_empty_file_returns_400(client: TestClient):
    response = client.post(
        "/api/analyze",
        files={"file": ("empty.eml", b"", "message/rfc822")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Uploaded file is empty."


def test_wrong_extension_returns_400(client: TestClient):
    response = client.post(
        "/api/analyze",
        files={"file": ("notes.txt", load_fixture("simple_plain.eml"), "text/plain")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Only .eml files are accepted."


def test_oversized_file_returns_413(client: TestClient):
    oversized = b"A" * (MAX_EMAIL_SIZE_BYTES + 1)
    response = client.post(
        "/api/analyze",
        files={"file": ("large.eml", oversized, "message/rfc822")},
    )

    assert response.status_code == 413
    assert "maximum allowed size" in response.json()["detail"]


def test_same_upload_produces_identical_json(client: TestClient):
    raw = load_fixture("phishing_duplicate_iocs.eml")
    files = {"file": ("phishing_duplicate_iocs.eml", raw, "message/rfc822")}

    first = client.post("/api/analyze", files=files)
    second = client.post("/api/analyze", files=files)

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["analysis_id"] != second.json()["analysis_id"]
    assert without_analysis_id(first.json()) == without_analysis_id(second.json())
