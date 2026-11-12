"""
Domain helpers shared by the sender and URL analyzers.

Key ideas, explained:

* Normalisation: "PayPal.COM." and "paypal.com" are the same domain.
  We lower-case, strip trailing dots and convert punycode ("xn--...") to
  Unicode so humans can see what the domain really looks like.

* Registrable domain: for "login.secure.example.co.uk" the part someone
  actually registered is "example.co.uk". Comparing registrable domains
  avoids flagging "mail.paypal.com" as different from "paypal.com".

* Skeleton: we map look-alike characters to plain Latin letters
  ("раypal" with Cyrillic letters -> "paypal"). If a domain's skeleton
  equals a brand but the domain itself is different, that's a homograph.

Nothing here does DNS lookups or network access.
"""

from __future__ import annotations

import ipaddress
import unicodedata

from core.reference_data import (
    ASCII_LOOKALIKES,
    BRANDS,
    CONFUSABLES,
    FREE_EMAIL_PROVIDERS,
    MULTI_LABEL_SUFFIXES,
    Brand,
)


def normalize_domain(domain: str) -> str:
    """Lower-case, strip dots/whitespace, decode punycode to Unicode."""
    d = (domain or "").strip().strip(".").lower()
    if "xn--" in d:
        try:
            d = d.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            pass  # keep the raw form; is_punycode() will still flag it
    return d


def to_ascii(domain: str) -> str:
    """Unicode domain -> punycode form, as it would appear on the wire."""
    try:
        return domain.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return domain


def is_punycode(domain: str) -> bool:
    return any(label.startswith("xn--") for label in (domain or "").lower().split("."))


def has_non_ascii(domain: str) -> bool:
    return any(ord(ch) > 127 for ch in domain)


def scripts_in(text: str) -> set[str]:
    """Unicode scripts of the letters in `text`, e.g. {"LATIN", "CYRILLIC"}."""
    scripts = set()
    for ch in text:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            scripts.add(name.split(" ")[0] if name else "UNKNOWN")
    return scripts


def is_mixed_script(domain: str) -> bool:
    """True if any single label mixes alphabets (classic homograph sign)."""
    return any(len(scripts_in(label)) > 1 for label in domain.split("."))


def registrable_domain(domain: str) -> str:
    """Approximate the registered domain (see MULTI_LABEL_SUFFIXES note)."""
    labels = [label for label in normalize_domain(domain).split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def main_label(domain: str) -> str:
    """'login.paypa1.co.uk' -> 'paypa1'."""
    return registrable_domain(domain).split(".")[0] if domain else ""


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def skeleton(text: str) -> str:
    """Map look-alike characters to Latin so 'pаypa1' and 'paypal' compare equal."""
    t = unicodedata.normalize("NFKC", text.lower())
    t = "".join(CONFUSABLES.get(ch, ch) for ch in t)
    for fake, real in ASCII_LOOKALIKES:
        t = t.replace(fake, real)
    return t


def edit_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein distance (insert, delete, substitute, swap)."""
    rows = len(a) + 1
    cols = len(b) + 1
    d = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        d[i][0] = i
    for j in range(cols):
        d[0][j] = j
    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def is_official_domain(domain: str, brand: Brand) -> bool:
    """True if `domain` is (a subdomain of) one of the brand's listed domains."""
    d = normalize_domain(domain)
    return any(d == od or d.endswith("." + od) for od in brand.official_domains)


def is_free_provider(domain: str) -> bool:
    return registrable_domain(domain) in FREE_EMAIL_PROVIDERS


def brands_claimed_in(text: str) -> list[Brand]:
    """Brands whose name appears in `text` (e.g. a display name)."""
    return [b for b in BRANDS if b.claim_pattern.search(text or "")]


def find_lookalike_brand(domain: str) -> tuple[Brand, str] | None:
    """Return (brand, reason) if `domain` imitates a known brand.

    A domain that IS an official brand domain never matches.
    Reasons:
      * "homograph"  - skeleton equals the brand but characters differ
      * "typo"       - one or two characters away from the brand name
      * "embedded"   - brand name used inside an unrelated domain,
                        e.g. paypal-secure-login.com or paypal.com.evil.net
    """
    d = normalize_domain(domain)
    if not d or is_ip_address(d):
        return None
    for brand in BRANDS:
        if is_official_domain(d, brand):
            return None  # official domain of some brand: not a lookalike
    label = main_label(d)
    # Check the whole label and each hyphen/dot-separated part, so that
    # "paypa1-support.com" is compared as "paypa1" and "support".
    tokens = [t for t in d.replace("-", ".").split(".") if t]
    parts = [label] + [t for t in tokens if t != label]
    for brand in BRANDS:
        for brand_label in brand.labels:
            for part in parts:
                if part == brand_label:
                    continue
                if skeleton(part) == brand_label:
                    return brand, "homograph" if has_non_ascii(part) else "typo"
                # Edit distance only on the registered label: applying it to every
                # token would flag ordinary words ("apply" vs "apple").
                if part == label and len(brand_label) >= 5 and abs(len(part) - len(brand_label)) <= 2:
                    limit = 1 if len(brand_label) < 8 else 2
                    if edit_distance(part, brand_label) <= limit:
                        return brand, "typo"
            # Brand appears as a whole token (paypal-login.com, paypal.com.evil.net)
            if brand_label in tokens or (
                len(brand_label) >= 5 and brand_label in label and label != brand_label
            ):
                return brand, "embedded"
    return None


__all__ = [
    "FREE_EMAIL_PROVIDERS",
    "brands_claimed_in",
    "edit_distance",
    "find_lookalike_brand",
    "has_non_ascii",
    "is_free_provider",
    "is_ip_address",
    "is_mixed_script",
    "is_official_domain",
    "is_punycode",
    "main_label",
    "normalize_domain",
    "registrable_domain",
    "skeleton",
    "to_ascii",
]
