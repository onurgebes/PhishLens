"""
Known brand references for display-name and domain impersonation checks.

This is a static, offline lookup table — no WHOIS, DNS, or network calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from email.utils import getaddresses

_LEET_TRANSLATION = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "@": "a",
    }
)


@dataclass(frozen=True)
class BrandReference:
    name: str
    keywords: tuple[str, ...]
    legitimate_domains: frozenset[str]


BRAND_REFERENCES: tuple[BrandReference, ...] = (
    BrandReference(
        name="PayPal",
        keywords=("paypal", "pay pal"),
        legitimate_domains=frozenset({"paypal.com", "paypal.me"}),
    ),
    BrandReference(
        name="Microsoft",
        keywords=("microsoft", "outlook", "office365", "office 365"),
        legitimate_domains=frozenset(
            {"microsoft.com", "outlook.com", "live.com", "office.com", "microsoftonline.com"}
        ),
    ),
    BrandReference(
        name="Google",
        keywords=("google", "gmail"),
        legitimate_domains=frozenset({"google.com", "gmail.com", "googlemail.com"}),
    ),
    BrandReference(
        name="Apple",
        keywords=("apple", "icloud"),
        legitimate_domains=frozenset({"apple.com", "icloud.com"}),
    ),
    BrandReference(
        name="Amazon",
        keywords=("amazon",),
        legitimate_domains=frozenset({"amazon.com", "amazon.co.uk", "amazon.de"}),
    ),
    BrandReference(
        name="Netflix",
        keywords=("netflix",),
        legitimate_domains=frozenset({"netflix.com"}),
    ),
    BrandReference(
        name="DHL",
        keywords=("dhl",),
        legitimate_domains=frozenset({"dhl.com", "dhl.de"}),
    ),
)


def normalize_domain(domain: str) -> str:
    return domain.lower().strip().strip(".")


def normalize_leet(text: str) -> str:
    return text.lower().translate(_LEET_TRANSLATION)


def extract_email_address(header_value: str | None) -> str | None:
    if not header_value:
        return None
    for _, addr in getaddresses([header_value]):
        if addr:
            return addr
    return None


def extract_display_name(header_value: str | None) -> str | None:
    if not header_value:
        return None
    for name, addr in getaddresses([header_value]):
        if addr and name:
            return name
    return None


def email_domain(email: str) -> str | None:
    if "@" not in email:
        return None
    return normalize_domain(email.rsplit("@", 1)[-1])


def is_legitimate_brand_domain(brand: BrandReference, domain: str) -> bool:
    normalized = normalize_domain(domain)
    for legit in brand.legitimate_domains:
        if normalized == legit or normalized.endswith("." + legit):
            return True
    return False


def brands_mentioned_in_text(text: str) -> list[BrandReference]:
    if not text:
        return []
    lowered = text.lower()
    normalized = normalize_leet(text)
    hits: list[BrandReference] = []
    for brand in BRAND_REFERENCES:
        for keyword in brand.keywords:
            key = keyword.lower()
            if key in lowered or key in normalized:
                hits.append(brand)
                break
    return hits


def brand_suggested_by_domain(domain: str) -> BrandReference | None:
    normalized = normalize_leet(normalize_domain(domain))
    for brand in BRAND_REFERENCES:
        for keyword in brand.keywords:
            key = normalize_leet(keyword.replace(" ", ""))
            compact = normalized.replace("-", "").replace(".", "")
            if key in compact:
                return brand
    return None
