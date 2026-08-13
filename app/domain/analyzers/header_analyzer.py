"""
Phase 3: header-based phishing heuristics.

Inspects structured header fields from ParsedEmail — no network calls.
"""

from __future__ import annotations

from app.domain.analyzers.brand_reference import (
    brands_mentioned_in_text,
    email_domain,
    extract_display_name,
    extract_email_address,
    is_legitimate_brand_domain,
)
from app.domain.models import Finding, FindingCategory, FindingSeverity, IOC, ParsedEmail


class HeaderAnalyzer:
    """Stateless analyzer for From / Reply-To / Return-Path mismatches."""

    def analyze(self, email: ParsedEmail, iocs: list[IOC]) -> list[Finding]:
        if not isinstance(email, ParsedEmail):
            raise TypeError("HeaderAnalyzer.analyze() expects a ParsedEmail")
        if not isinstance(iocs, list):
            raise TypeError("HeaderAnalyzer.analyze() expects a list of IOC")

        findings: list[Finding] = []
        findings.extend(self._check_reply_to_mismatch(email))
        findings.extend(self._check_return_path_mismatch(email))
        findings.extend(self._check_display_name_brand_spoofing(email))
        findings.extend(self._check_missing_message_id(email))

        return sorted(
            findings,
            key=lambda finding: (
                finding.category.value,
                finding.severity.value,
                finding.rule_id,
            ),
        )

    def _check_reply_to_mismatch(self, email: ParsedEmail) -> list[Finding]:
        from_addr = extract_email_address(email.from_address)
        reply_addr = extract_email_address(email.reply_to)
        if not from_addr or not reply_addr:
            return []

        from_domain = email_domain(from_addr)
        reply_domain = email_domain(reply_addr)
        if not from_domain or not reply_domain or from_domain == reply_domain:
            return []

        return [
            Finding(
                rule_id="header_reply_to_domain_mismatch",
                category=FindingCategory.HEADER,
                severity=FindingSeverity.HIGH,
                title="Reply-To domain differs from From domain",
                description=(
                    "The Reply-To address uses a different domain than the "
                    "From address, which is a common phishing tactic."
                ),
                evidence={
                    "from_address": from_addr,
                    "reply_to": reply_addr,
                    "from_domain": from_domain,
                    "reply_to_domain": reply_domain,
                },
            )
        ]

    def _check_return_path_mismatch(self, email: ParsedEmail) -> list[Finding]:
        from_addr = extract_email_address(email.from_address)
        return_addr = extract_email_address(email.return_path)
        if not from_addr or not return_addr:
            return []

        from_domain = email_domain(from_addr)
        return_domain = email_domain(return_addr)
        if not from_domain or not return_domain or from_domain == return_domain:
            return []

        return [
            Finding(
                rule_id="header_return_path_mismatch",
                category=FindingCategory.HEADER,
                severity=FindingSeverity.MEDIUM,
                title="Return-Path domain differs from From domain",
                description=(
                    "The Return-Path envelope sender domain does not match "
                    "the visible From domain."
                ),
                evidence={
                    "from_address": from_addr,
                    "return_path": return_addr,
                    "from_domain": from_domain,
                    "return_path_domain": return_domain,
                },
            )
        ]

    def _check_display_name_brand_spoofing(self, email: ParsedEmail) -> list[Finding]:
        display_name = extract_display_name(email.from_address)
        from_addr = extract_email_address(email.from_address)
        if not display_name or not from_addr:
            return []

        from_dom = email_domain(from_addr)
        if not from_dom:
            return []

        findings: list[Finding] = []
        for brand in brands_mentioned_in_text(display_name):
            if is_legitimate_brand_domain(brand, from_dom):
                continue
            findings.append(
                Finding(
                    rule_id="header_display_name_brand_spoofing",
                    category=FindingCategory.HEADER,
                    severity=FindingSeverity.HIGH,
                    title="Display name references a brand but sender domain is unrelated",
                    description=(
                        f"The From display name mentions {brand.name}, but the "
                        "sender domain is not an official domain for that brand."
                    ),
                    evidence={
                        "display_name": display_name,
                        "from_address": from_addr,
                        "from_domain": from_dom,
                        "brand": brand.name,
                    },
                )
            )
        return findings

    def _check_missing_message_id(self, email: ParsedEmail) -> list[Finding]:
        if email.message_id:
            return []
        return [
            Finding(
                rule_id="header_missing_message_id",
                category=FindingCategory.HEADER,
                severity=FindingSeverity.LOW,
                title="Message-ID header is missing",
                description=(
                    "Legitimate mail systems usually include a Message-ID. "
                    "Its absence may indicate a manually crafted message."
                ),
                evidence={"message_id": ""},
            )
        ]
