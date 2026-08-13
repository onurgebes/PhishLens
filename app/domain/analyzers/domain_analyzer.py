"""
Phase 3: domain-based phishing heuristics.

Operates on DOMAIN IOCs from Phase 2 — no DNS or WHOIS lookups.
"""

from __future__ import annotations

from app.domain.analyzers.brand_reference import (
    brand_suggested_by_domain,
    is_legitimate_brand_domain,
    normalize_domain,
)
from app.domain.models import Finding, FindingCategory, FindingSeverity, IOC, IOCType, ParsedEmail

_SUSPICIOUS_TLDS = frozenset(
    {
        "xyz",
        "top",
        "click",
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "pw",
        "buzz",
        "rest",
        "zip",
        "mov",
    }
)


class DomainAnalyzer:
    """Stateless analyzer for suspicious domain patterns."""

    def analyze(self, email: ParsedEmail, iocs: list[IOC]) -> list[Finding]:
        if not isinstance(email, ParsedEmail):
            raise TypeError("DomainAnalyzer.analyze() expects a ParsedEmail")
        if not isinstance(iocs, list):
            raise TypeError("DomainAnalyzer.analyze() expects a list of IOC")

        domain_iocs = [ioc for ioc in iocs if ioc.ioc_type == IOCType.DOMAIN]
        findings: list[Finding] = []
        seen_rules: set[tuple[str, str]] = set()

        for ioc in domain_iocs:
            domain = normalize_domain(ioc.value)
            self._maybe_add(
                findings,
                seen_rules,
                self._check_brand_impersonation(domain, ioc.sources),
            )
            self._maybe_add(
                findings,
                seen_rules,
                self._check_suspicious_tld(domain, ioc.sources),
            )
            self._maybe_add(
                findings,
                seen_rules,
                self._check_punycode(domain, ioc.sources),
            )

        return sorted(
            findings,
            key=lambda finding: (
                finding.category.value,
                finding.severity.value,
                finding.rule_id,
                str(finding.evidence.get("domain", "")),
            ),
        )

    @staticmethod
    def _maybe_add(
        findings: list[Finding],
        seen: set[tuple[str, str]],
        finding: Finding | None,
    ) -> None:
        if finding is None:
            return
        key = (finding.rule_id, str(finding.evidence.get("domain", "")))
        if key in seen:
            return
        seen.add(key)
        findings.append(finding)

    def _check_brand_impersonation(
        self, domain: str, sources: list[str]
    ) -> Finding | None:
        brand = brand_suggested_by_domain(domain)
        if brand is None or is_legitimate_brand_domain(brand, domain):
            return None
        return Finding(
            rule_id="domain_brand_impersonation",
            category=FindingCategory.DOMAIN,
            severity=FindingSeverity.HIGH,
            title="Domain appears to impersonate a well-known brand",
            description=(
                f"The domain name resembles {brand.name} but is not an "
                "official domain for that brand."
            ),
            evidence={
                "domain": domain,
                "brand": brand.name,
                "sources": list(sources),
            },
        )

    def _check_suspicious_tld(
        self, domain: str, sources: list[str]
    ) -> Finding | None:
        if "." not in domain:
            return None
        tld = domain.rsplit(".", 1)[-1]
        if tld not in _SUSPICIOUS_TLDS:
            return None
        return Finding(
            rule_id="domain_suspicious_tld",
            category=FindingCategory.DOMAIN,
            severity=FindingSeverity.MEDIUM,
            title="Domain uses a commonly abused top-level domain",
            description=f"The domain uses the .{tld} TLD, which is frequently seen in phishing.",
            evidence={"domain": domain, "tld": tld, "sources": list(sources)},
        )

    def _check_punycode(self, domain: str, sources: list[str]) -> Finding | None:
        if "xn--" not in domain.lower():
            return None
        return Finding(
            rule_id="domain_punycode",
            category=FindingCategory.DOMAIN,
            severity=FindingSeverity.HIGH,
            title="Domain uses punycode (internationalized domain name)",
            description=(
                "Punycode domains can visually mimic ASCII brand names "
                "using look-alike Unicode characters."
            ),
            evidence={"domain": domain, "sources": list(sources)},
        )
