"""
Unit tests for AttachmentAnalyzer (Phase 3).
"""

from __future__ import annotations

import pytest

from app.domain.analyzers.attachment_analyzer import AttachmentAnalyzer
from app.domain.models import Attachment, FindingCategory, FindingSeverity
from tests.unit.conftest import empty_email, extract_iocs, findings_by_rule, load_and_parse


@pytest.fixture
def analyzer() -> AttachmentAnalyzer:
    return AttachmentAnalyzer()


def attachment(
    filename: str | None,
    content_type: str,
    content: bytes = b"payload",
) -> Attachment:
    return Attachment(
        filename=filename,
        content_type=content_type,
        size_bytes=len(content),
        content=content,
    )


class TestDangerousExtension:
    def test_triggers_for_executable_extension(self, analyzer: AttachmentAnalyzer):
        email = empty_email(
            attachments=[attachment("malware.exe", "application/octet-stream")]
        )
        findings = analyzer.analyze(email, [])

        hits = findings_by_rule(findings, "attachment_dangerous_extension")
        assert len(hits) == 1
        assert hits[0].severity == FindingSeverity.CRITICAL
        assert hits[0].category == FindingCategory.ATTACHMENT
        assert hits[0].evidence["extension"] == "exe"
        assert hits[0].evidence["filename"] == "malware.exe"

    def test_clean_for_safe_text_attachment(self, analyzer: AttachmentAnalyzer):
        parsed = load_and_parse("multipart_with_attachment.eml")
        findings = analyzer.analyze(parsed, extract_iocs(parsed))
        assert findings_by_rule(findings, "attachment_dangerous_extension") == []


class TestDoubleExtension:
    def test_triggers_for_disguised_executable(self, analyzer: AttachmentAnalyzer):
        email = empty_email(
            attachments=[attachment("invoice.pdf.exe", "application/octet-stream")]
        )
        findings = analyzer.analyze(email, [])

        hits = findings_by_rule(findings, "attachment_double_extension")
        assert len(hits) == 1
        assert hits[0].severity == FindingSeverity.HIGH
        assert hits[0].evidence["visible_extension"] == "pdf"
        assert hits[0].evidence["real_extension"] == "exe"

    def test_clean_for_single_extension(self, analyzer: AttachmentAnalyzer):
        email = empty_email(
            attachments=[attachment("report.pdf", "application/pdf")]
        )
        findings = analyzer.analyze(email, [])
        assert findings_by_rule(findings, "attachment_double_extension") == []


class TestMacroEnabled:
    def test_triggers_for_macro_enabled_office_file(self, analyzer: AttachmentAnalyzer):
        email = empty_email(
            attachments=[
                attachment(
                    "macro.docm",
                    "application/vnd.ms-word.document.macroEnabled.12",
                )
            ]
        )
        findings = analyzer.analyze(email, [])

        hits = findings_by_rule(findings, "attachment_macro_enabled")
        assert len(hits) == 1
        assert hits[0].severity == FindingSeverity.MEDIUM
        assert hits[0].evidence["extension"] == "docm"

    def test_clean_for_regular_docx(self, analyzer: AttachmentAnalyzer):
        email = empty_email(
            attachments=[
                attachment(
                    "report.docx",
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                )
            ]
        )
        findings = analyzer.analyze(email, [])
        assert findings_by_rule(findings, "attachment_macro_enabled") == []


class TestExtensionMimeMismatch:
    def test_triggers_when_extension_and_mime_disagree(self, analyzer: AttachmentAnalyzer):
        email = empty_email(
            attachments=[attachment("document.pdf", "text/plain")]
        )
        findings = analyzer.analyze(email, [])

        hits = findings_by_rule(findings, "attachment_extension_mime_mismatch")
        assert len(hits) == 1
        assert hits[0].severity == FindingSeverity.MEDIUM
        assert hits[0].evidence["extension"] == "pdf"
        assert hits[0].evidence["content_type"] == "text/plain"
        assert "application/pdf" in hits[0].evidence["expected_content_types"]

    def test_clean_when_extension_and_mime_match(self, analyzer: AttachmentAnalyzer):
        email = empty_email(
            attachments=[attachment("notes.txt", "text/plain")]
        )
        findings = analyzer.analyze(email, [])
        assert findings_by_rule(findings, "attachment_extension_mime_mismatch") == []


class TestMissingFilename:
    def test_triggers_when_filename_is_absent(self, analyzer: AttachmentAnalyzer):
        email = empty_email(
            attachments=[attachment(None, "application/octet-stream")]
        )
        findings = analyzer.analyze(email, [])

        hits = findings_by_rule(findings, "attachment_missing_filename")
        assert len(hits) == 1
        assert hits[0].severity == FindingSeverity.LOW
        assert hits[0].evidence["filename"] == ""

    def test_clean_when_filename_is_present(self, analyzer: AttachmentAnalyzer):
        parsed = load_and_parse("multipart_with_attachment.eml")
        findings = analyzer.analyze(parsed, extract_iocs(parsed))
        assert findings_by_rule(findings, "attachment_missing_filename") == []


class TestMalformedAndEmptyInput:
    def test_no_attachments_produces_no_findings(self, analyzer: AttachmentAnalyzer):
        findings = analyzer.analyze(empty_email(), [])
        assert findings == []

    def test_empty_filename_string_does_not_crash(self, analyzer: AttachmentAnalyzer):
        email = empty_email(
            attachments=[attachment("", "application/octet-stream")]
        )
        findings = analyzer.analyze(email, [])
        assert isinstance(findings, list)

    def test_wrong_email_type_raises_type_error(self, analyzer: AttachmentAnalyzer):
        with pytest.raises(TypeError):
            analyzer.analyze("bad", [])  # type: ignore[arg-type]

    def test_wrong_ioc_type_raises_type_error(self, analyzer: AttachmentAnalyzer):
        with pytest.raises(TypeError):
            analyzer.analyze(empty_email(), "bad")  # type: ignore[arg-type]


class TestDeterministicOutput:
    def test_same_input_produces_identical_findings(self, analyzer: AttachmentAnalyzer):
        email = empty_email(
            attachments=[
                attachment("invoice.pdf.exe", "application/octet-stream"),
                attachment("macro.docm", "application/vnd.ms-word.document.macroEnabled.12"),
            ]
        )

        first = analyzer.analyze(email, [])
        second = analyzer.analyze(email, [])
        assert [(f.rule_id, f.evidence) for f in first] == [
            (f.rule_id, f.evidence) for f in second
        ]
