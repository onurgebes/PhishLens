"""
Phase 3: attachment metadata analysis.

Inspects filenames and declared MIME types only — never opens or executes
attachment content (hashing already happened in Phase 2).
"""

from __future__ import annotations

from pathlib import PurePosixPath

from app.domain.models import Attachment, Finding, FindingCategory, FindingSeverity, IOC, ParsedEmail

_DANGEROUS_EXTENSIONS = frozenset(
    {
        "exe",
        "scr",
        "bat",
        "cmd",
        "com",
        "pif",
        "vbs",
        "js",
        "jse",
        "wsf",
        "wsh",
        "ps1",
        "msi",
        "dll",
        "hta",
        "cpl",
    }
)

_MACRO_EXTENSIONS = frozenset({"docm", "xlsm", "pptm", "dotm", "xltm", "potm"})

_EXTENSION_TO_MIME: dict[str, set[str]] = {
    "pdf": {"application/pdf"},
    "doc": {"application/msword"},
    "docx": {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    },
    "xls": {"application/vnd.ms-excel"},
    "xlsx": {
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    },
    "txt": {"text/plain"},
    "zip": {"application/zip", "application/x-zip-compressed"},
    "exe": {"application/x-msdownload", "application/octet-stream"},
}


class AttachmentAnalyzer:
    """Stateless analyzer for dangerous attachment patterns."""

    def analyze(self, email: ParsedEmail, iocs: list[IOC]) -> list[Finding]:
        if not isinstance(email, ParsedEmail):
            raise TypeError("AttachmentAnalyzer.analyze() expects a ParsedEmail")
        if not isinstance(iocs, list):
            raise TypeError("AttachmentAnalyzer.analyze() expects a list of IOC")

        findings: list[Finding] = []
        for attachment in email.attachments:
            findings.extend(self._analyze_attachment(attachment))

        return sorted(
            findings,
            key=lambda finding: (
                finding.category.value,
                finding.severity.value,
                finding.rule_id,
                str(finding.evidence.get("filename", "")),
            ),
        )

    def _analyze_attachment(self, attachment: Attachment) -> list[Finding]:
        findings: list[Finding] = []
        filename = attachment.filename or ""
        extension = self._file_extension(filename)

        finding = self._check_missing_filename(attachment)
        if finding:
            findings.append(finding)

        if extension in _DANGEROUS_EXTENSIONS:
            findings.append(
                Finding(
                    rule_id="attachment_dangerous_extension",
                    category=FindingCategory.ATTACHMENT,
                    severity=FindingSeverity.CRITICAL,
                    title="Attachment has a dangerous file extension",
                    description=(
                        f"Files with the .{extension} extension can execute "
                        "code or scripts on a victim's machine."
                    ),
                    evidence={
                        "filename": filename,
                        "extension": extension,
                        "content_type": attachment.content_type,
                        "size_bytes": attachment.size_bytes,
                    },
                )
            )

        double_ext = self._double_extension(filename)
        if double_ext is not None:
            findings.append(
                Finding(
                    rule_id="attachment_double_extension",
                    category=FindingCategory.ATTACHMENT,
                    severity=FindingSeverity.HIGH,
                    title="Attachment uses a double extension",
                    description=(
                        "Double extensions (e.g. invoice.pdf.exe) are used to "
                        "disguise executable files as documents."
                    ),
                    evidence={
                        "filename": filename,
                        "visible_extension": double_ext[0],
                        "real_extension": double_ext[1],
                        "content_type": attachment.content_type,
                    },
                )
            )

        if extension in _MACRO_EXTENSIONS:
            findings.append(
                Finding(
                    rule_id="attachment_macro_enabled",
                    category=FindingCategory.ATTACHMENT,
                    severity=FindingSeverity.MEDIUM,
                    title="Attachment is a macro-enabled Office document",
                    description=(
                        "Macro-enabled Office files can run embedded scripts "
                        "when opened."
                    ),
                    evidence={
                        "filename": filename,
                        "extension": extension,
                        "content_type": attachment.content_type,
                    },
                )
            )

        mismatch = self._extension_mime_mismatch(extension, attachment.content_type)
        if mismatch:
            findings.append(
                Finding(
                    rule_id="attachment_extension_mime_mismatch",
                    category=FindingCategory.ATTACHMENT,
                    severity=FindingSeverity.MEDIUM,
                    title="Attachment extension does not match declared content type",
                    description=(
                        "The filename extension suggests one file type, but "
                        "the MIME type header declares another."
                    ),
                    evidence={
                        "filename": filename,
                        "extension": extension,
                        "content_type": attachment.content_type,
                        "expected_content_types": sorted(mismatch),
                    },
                )
            )

        return findings

    @staticmethod
    def _file_extension(filename: str) -> str:
        if not filename:
            return ""
        return PurePosixPath(filename).suffix.lstrip(".").lower()

    @staticmethod
    def _double_extension(filename: str) -> tuple[str, str] | None:
        if not filename or filename.count(".") < 2:
            return None
        parts = PurePosixPath(filename).name.split(".")
        if len(parts) < 3:
            return None
        visible = parts[-2].lower()
        real = parts[-1].lower()
        if real not in _DANGEROUS_EXTENSIONS:
            return None
        return visible, real

    @staticmethod
    def _check_missing_filename(attachment: Attachment) -> Finding | None:
        if attachment.filename:
            return None
        return Finding(
            rule_id="attachment_missing_filename",
            category=FindingCategory.ATTACHMENT,
            severity=FindingSeverity.LOW,
            title="Attachment has no filename",
            description=(
                "Attachments without filenames are unusual in legitimate "
                "business email and can hinder inspection."
            ),
            evidence={
                "filename": "",
                "content_type": attachment.content_type,
                "size_bytes": attachment.size_bytes,
            },
        )

    @staticmethod
    def _extension_mime_mismatch(
        extension: str, content_type: str
    ) -> set[str] | None:
        if not extension or extension not in _EXTENSION_TO_MIME:
            return None
        expected = _EXTENSION_TO_MIME[extension]
        normalized = content_type.split(";", 1)[0].strip().lower()
        if normalized in expected:
            return None
        return expected
