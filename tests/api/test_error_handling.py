"""Tests for API error handling and JSON safety."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from tests.api.conftest import load_fixture


def test_attachment_content_is_never_exposed(client: TestClient):
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
    attachment = payload["parsed_email"]["attachments"][0]
    assert set(attachment.keys()) == {"filename", "content_type", "size_bytes"}
    assert attachment["filename"] == "invoice.txt"
    assert "content" not in attachment

    raw_json = json.dumps(payload)
    assert "SW52b2ljZSAjMDAx" not in raw_json  # base64 payload from fixture


def test_enum_fields_are_serialized_as_strings(client: TestClient):
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

    for ioc in payload["iocs"]:
        assert isinstance(ioc["ioc_type"], str)

    for finding in payload["findings"]:
        assert isinstance(finding["category"], str)
        assert isinstance(finding["severity"], str)

    assert isinstance(payload["risk_score"]["level"], str)
    for contribution in payload["risk_score"]["contributions"]:
        assert isinstance(contribution["severity"], str)


def test_error_responses_do_not_expose_tracebacks(client: TestClient):
    response = client.post(
        "/api/analyze",
        files={"file": ("notes.txt", b"hello", "text/plain")},
    )

    assert response.status_code == 400
    body = response.json()
    assert set(body.keys()) == {"detail"}
    assert "Traceback" not in body["detail"]
