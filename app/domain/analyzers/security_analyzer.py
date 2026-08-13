"""
Phase 3: email authentication header analysis.

Parses Authentication-Results headers already captured by Phase 1.
No live SPF/DKIM/DMARC DNS lookups — header values only.
"""

from __future__ import annotations

import re

from app.domain.models import Finding, FindingCategory, FindingSeverity, IOC, ParsedEmail

_SPF_RE = re.compile(
    r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE,
)
_DKIM_RE = re.compile(
    r"\bdkim=(pass|fail|none|neutral|temperror|permerror)\b",
    re.IGNORECASE,
)
_DMARC_RE = re.compile(
    r"\bdmarc=(pass|fail|none|temperror|permerror)\b",
    re.IGNORECASE,
)


class SecurityAnalyzer:
    """Stateless analyzer for SPF / DKIM / DMARC header results."""

    def analyze(self, email: ParsedEmail, iocs: list[IOC]) -> list[Finding]:
        if not isinstance(email, ParsedEmail):
            raise TypeError("SecurityAnalyzer.analyze() expects a ParsedEmail")
        if not isinstance(iocs, list):
            raise TypeError("SecurityAnalyzer.analyze() expects a list of IOC")

        findings: list[Finding] = []
        auth_headers = email.authentication_results or []

        if not auth_headers and email.from_address:
            findings.append(
                Finding(
                    rule_id="auth_results_missing",
                    category=FindingCategory.AUTHENTICATION,
                    severity=FindingSeverity.LOW,
                    title="Authentication-Results header is missing",
                    description=(
                        "No Authentication-Results header was present to "
                        "report SPF, DKIM, or DMARC outcomes."
                    ),
                    evidence={"authentication_results": []},
                )
            )
            return self._sorted(findings)

        combined = " ".join(auth_headers)
        findings.extend(self._check_spf(combined, auth_headers))
        findings.extend(self._check_dkim(combined, auth_headers))
        findings.extend(self._check_dmarc(combined, auth_headers))

        return self._sorted(findings)

    @staticmethod
    def _sorted(findings: list[Finding]) -> list[Finding]:
        return sorted(
            findings,
            key=lambda finding: (
                finding.category.value,
                finding.severity.value,
                finding.rule_id,
            ),
        )

    def _check_spf(self, combined: str, auth_headers: list[str]) -> list[Finding]:
        matches = _SPF_RE.findall(combined)
        if not matches:
            return []
        if not any(result.lower() == "fail" for result in matches):
            if any(result.lower() == "softfail" for result in matches):
                return [
                    Finding(
                        rule_id="auth_spf_softfail",
                        category=FindingCategory.AUTHENTICATION,
                        severity=FindingSeverity.MEDIUM,
                        title="SPF softfail reported",
                        description=(
                            "The receiving server reported SPF softfail, "
                            "meaning the sender may not be authorized."
                        ),
                        evidence={
                            "spf_results": matches,
                            "authentication_results": list(auth_headers),
                        },
                    )
                ]
            return []

        return [
            Finding(
                rule_id="auth_spf_fail",
                category=FindingCategory.AUTHENTICATION,
                severity=FindingSeverity.HIGH,
                title="SPF fail reported",
                description=(
                    "The receiving server reported SPF fail, indicating the "
                    "sender IP is not authorized for the From domain."
                ),
                evidence={
                    "spf_results": matches,
                    "authentication_results": list(auth_headers),
                },
            )
        ]

    def _check_dkim(self, combined: str, auth_headers: list[str]) -> list[Finding]:
        matches = _DKIM_RE.findall(combined)
        if not matches:
            return []
        if not any(result.lower() == "fail" for result in matches):
            return []
        return [
            Finding(
                rule_id="auth_dkim_fail",
                category=FindingCategory.AUTHENTICATION,
                severity=FindingSeverity.HIGH,
                title="DKIM fail reported",
                description=(
                    "The receiving server reported DKIM signature validation "
                    "failure."
                ),
                evidence={
                    "dkim_results": matches,
                    "authentication_results": list(auth_headers),
                },
            )
        ]

    def _check_dmarc(self, combined: str, auth_headers: list[str]) -> list[Finding]:
        matches = _DMARC_RE.findall(combined)
        if not matches:
            return []
        if not any(result.lower() == "fail" for result in matches):
            return []
        return [
            Finding(
                rule_id="auth_dmarc_fail",
                category=FindingCategory.AUTHENTICATION,
                severity=FindingSeverity.HIGH,
                title="DMARC fail reported",
                description=(
                    "The receiving server reported DMARC policy failure, "
                    "meaning the message failed domain alignment checks."
                ),
                evidence={
                    "dmarc_results": matches,
                    "authentication_results": list(auth_headers),
                },
            )
        ]
