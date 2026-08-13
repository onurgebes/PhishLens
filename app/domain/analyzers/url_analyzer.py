"""
Phase 3: URL-based phishing heuristics.

Operates on URL IOCs already extracted in Phase 2 — no fetching URLs.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

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

_URL_SHORTENER_DOMAINS = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
    }
)

_AT_IN_URL_RE = re.compile(r"https?://[^/\s]*@[^/\s]", re.IGNORECASE)


class URLAnalyzer:
    """Stateless analyzer for suspicious URL patterns."""

    def analyze(self, email: ParsedEmail, iocs: list[IOC]) -> list[Finding]:
        if not isinstance(email, ParsedEmail):
            raise TypeError("URLAnalyzer.analyze() expects a ParsedEmail")
        if not isinstance(iocs, list):
            raise TypeError("URLAnalyzer.analyze() expects a list of IOC")

        url_iocs = [ioc for ioc in iocs if ioc.ioc_type == IOCType.URL]
        findings: list[Finding] = []
        seen_rules: set[tuple[str, str]] = set()

        for ioc in url_iocs:
            url = ioc.value
            parsed = urlparse(url)
            host = parsed.hostname or ""

            self._maybe_add(
                findings,
                seen_rules,
                self._check_ip_literal_host(url, host, ioc.sources),
            )
            self._maybe_add(
                findings,
                seen_rules,
                self._check_url_shortener(url, host, ioc.sources),
            )
            self._maybe_add(
                findings,
                seen_rules,
                self._check_at_symbol(url, ioc.sources),
            )
            self._maybe_add(
                findings,
                seen_rules,
                self._check_suspicious_tld(url, host, ioc.sources),
            )
            self._maybe_add(
                findings,
                seen_rules,
                self._check_excessive_subdomains(url, host, ioc.sources),
            )

        return sorted(
            findings,
            key=lambda finding: (
                finding.category.value,
                finding.severity.value,
                finding.rule_id,
                str(finding.evidence.get("url", "")),
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
        key = (finding.rule_id, str(finding.evidence.get("url", "")))
        if key in seen:
            return
        seen.add(key)
        findings.append(finding)

    @staticmethod
    def _is_ip_host(host: str) -> bool:
        if not host:
            return False
        try:
            ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            return False
        return True

    def _check_ip_literal_host(
        self, url: str, host: str, sources: list[str]
    ) -> Finding | None:
        if not self._is_ip_host(host):
            return None
        return Finding(
            rule_id="url_ip_literal_host",
            category=FindingCategory.URL,
            severity=FindingSeverity.HIGH,
            title="URL uses an IP address instead of a domain name",
            description=(
                "Phishing links often use raw IP addresses to evade domain "
                "reputation checks."
            ),
            evidence={"url": url, "host": host, "sources": list(sources)},
        )

    def _check_url_shortener(
        self, url: str, host: str, sources: list[str]
    ) -> Finding | None:
        normalized_host = host.lower()
        if normalized_host not in _URL_SHORTENER_DOMAINS:
            return None
        return Finding(
            rule_id="url_shortener",
            category=FindingCategory.URL,
            severity=FindingSeverity.MEDIUM,
            title="URL uses a link shortener",
            description=(
                "Shortened URLs hide the final destination and are commonly "
                "used in phishing campaigns."
            ),
            evidence={"url": url, "host": normalized_host, "sources": list(sources)},
        )

    def _check_at_symbol(self, url: str, sources: list[str]) -> Finding | None:
        if not _AT_IN_URL_RE.search(url):
            return None
        return Finding(
            rule_id="url_at_symbol",
            category=FindingCategory.URL,
            severity=FindingSeverity.HIGH,
            title="URL contains an @ symbol",
            description=(
                "An @ in a URL can trick users into believing they are visiting "
                "one site while the browser navigates to another."
            ),
            evidence={"url": url, "sources": list(sources)},
        )

    def _check_suspicious_tld(
        self, url: str, host: str, sources: list[str]
    ) -> Finding | None:
        if not host or "." not in host:
            return None
        tld = host.rsplit(".", 1)[-1].lower()
        if tld not in _SUSPICIOUS_TLDS:
            return None
        return Finding(
            rule_id="url_suspicious_tld",
            category=FindingCategory.URL,
            severity=FindingSeverity.MEDIUM,
            title="URL uses a commonly abused top-level domain",
            description=f"The URL host uses the .{tld} TLD, which is frequently seen in phishing.",
            evidence={"url": url, "host": host, "tld": tld, "sources": list(sources)},
        )

    def _check_excessive_subdomains(
        self, url: str, host: str, sources: list[str]
    ) -> Finding | None:
        if not host:
            return None
        labels = host.split(".")
        if len(labels) <= 5:
            return None
        return Finding(
            rule_id="url_excessive_subdomains",
            category=FindingCategory.URL,
            severity=FindingSeverity.LOW,
            title="URL has an unusually long subdomain chain",
            description=(
                "Very long subdomain chains are sometimes used to mimic "
                "legitimate-looking URLs."
            ),
            evidence={
                "url": url,
                "host": host,
                "label_count": len(labels),
                "sources": list(sources),
            },
        )
