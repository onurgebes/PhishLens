"""Tests for analysis history endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.api.conftest import load_fixture, without_analysis_id


def test_list_history_empty(client: TestClient):
    response = client.get("/api/history")

    assert response.status_code == 200
    payload = response.json()
    assert payload["items"] == []
    assert payload["total"] == 0
    assert payload["limit"] == 20
    assert payload["offset"] == 0


def test_list_history_after_analyze(client: TestClient):
    upload = client.post(
        "/api/analyze",
        files={"file": ("simple_plain.eml", load_fixture("simple_plain.eml"), "message/rfc822")},
    )
    assert upload.status_code == 200
    analysis_id = upload.json()["analysis_id"]

    response = client.get("/api/history")
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert len(payload["items"]) == 1

    item = payload["items"][0]
    assert item["analysis_id"] == analysis_id
    assert item["source_type"] == "upload"
    assert item["source_filename"] == "simple_plain.eml"
    assert item["ioc_count"] == 9
    assert item["finding_count"] == 0
    assert item["risk_score"] == 0
    assert item["risk_level"] == "low"


def test_get_history_item_returns_full_analysis(client: TestClient):
    upload = client.post(
        "/api/analyze",
        files={
            "file": (
                "phishing_duplicate_iocs.eml",
                load_fixture("phishing_duplicate_iocs.eml"),
                "message/rfc822",
            )
        },
    )
    assert upload.status_code == 200
    analysis_id = upload.json()["analysis_id"]

    response = client.get(f"/api/history/{analysis_id}")
    assert response.status_code == 200
    assert without_analysis_id(response.json()) == without_analysis_id(upload.json())
    assert response.json()["analysis_id"] == analysis_id


def test_get_history_item_not_found(client: TestClient):
    response = client.get("/api/history/00000000-0000-0000-0000-000000000000")

    assert response.status_code == 404
    assert response.json()["detail"] == "Analysis not found."


def test_history_pagination(client: TestClient):
    for _ in range(3):
        client.post(
            "/api/analyze/raw",
            json={"raw_email": load_fixture("simple_plain.eml").decode("utf-8")},
        )

    response = client.get("/api/history?limit=2&offset=1")
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 3
    assert len(payload["items"]) == 2
    assert payload["limit"] == 2
    assert payload["offset"] == 1


def test_failed_analyze_is_not_persisted(client: TestClient):
    before = client.get("/api/history")
    assert before.status_code == 200
    assert before.json()["total"] == 0

    response = client.post(
        "/api/analyze",
        files={"file": ("notes.txt", b"hello", "text/plain")},
    )
    assert response.status_code == 400

    after = client.get("/api/history")
    assert after.status_code == 200
    assert after.json()["total"] == 0
