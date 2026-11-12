"""
Curated reference lists used by the analyzers.

IMPORTANT LIMITATIONS (also shown in the README):
* These lists are small, hand-maintained and NOT exhaustive.
* Being on the brand list does not mean a company is trustworthy, and a
  domain missing from `official_domains` is not proof that it is fake:
  companies own many domains. That is why brand mismatches are reported
  as "Suspicious indicator" / "Needs verification", not as confirmed fraud.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Brand:
    name: str
    # Regex matched (case-insensitive unless noted) against display names
    # and body text to detect that the email *claims* to be this brand.
    claim_pattern: re.Pattern[str]
    official_domains: frozenset[str]
    # Labels used for lookalike-domain comparison, e.g. "paypal".
    labels: frozenset[str]


def _brand(name: str, pattern: str, domains: set[str], labels: set[str], flags: int = re.I) -> Brand:
    return Brand(name, re.compile(pattern, flags), frozenset(domains), frozenset(labels))


BRANDS: tuple[Brand, ...] = (
    _brand("PayPal", r"\bpay\s?pal\b", {"paypal.com", "paypal.me", "paypal-communication.com"}, {"paypal"}),
    _brand("Microsoft", r"\b(microsoft|office\s?365|microsoft\s?365|outlook|onedrive|sharepoint)\b",
           {"microsoft.com", "office.com", "office365.com", "outlook.com", "live.com", "microsoftonline.com",
            "sharepoint.com", "onmicrosoft.com", "onedrive.com", "microsoft365.com"},
           {"microsoft", "office365", "outlook", "onedrive", "sharepoint"}),
    _brand("Apple", r"\b(apple|icloud|itunes)\b", {"apple.com", "icloud.com", "me.com"}, {"apple", "icloud"}),
    _brand("Amazon", r"\bamazon\b",
           {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "amazon.ca", "amazon.fr",
            "amazonaws.com", "amazon.es", "amazon.it", "amazon.co.jp"}, {"amazon"}),
    _brand("Google", r"\b(google|gmail)\b", {"google.com", "gmail.com", "googlemail.com", "youtube.com", "goo.gl"},
           {"google", "gmail"}),
    _brand("Netflix", r"\bnetflix\b", {"netflix.com"}, {"netflix"}),
    _brand("DHL", r"\bDHL\b", {"dhl.com", "dhl.de"}, {"dhl"}, flags=0),
    _brand("FedEx", r"\bfed\s?ex\b", {"fedex.com"}, {"fedex"}),
    _brand("UPS", r"\bUPS\b", {"ups.com"}, {"ups"}, flags=0),
    _brand("USPS", r"\bUSPS\b", {"usps.com"}, {"usps"}, flags=0),
    _brand("LinkedIn", r"\blinked\s?in\b", {"linkedin.com", "lnkd.in"}, {"linkedin"}),
    _brand("Indeed", r"\bindeed\.com\b|\bindeed\s+(team|jobs|hiring|recruit)", {"indeed.com"}, {"indeed"}),
    _brand("DocuSign", r"\bdocu\s?sign\b", {"docusign.com", "docusign.net"}, {"docusign"}),
    _brand("Dropbox", r"\bdropbox\b", {"dropbox.com", "dropboxmail.com"}, {"dropbox"}),
    _brand("Facebook", r"\b(facebook|instagram)\b",
           {"facebook.com", "facebookmail.com", "instagram.com", "meta.com"}, {"facebook", "instagram"}),
    _brand("Coinbase", r"\bcoinbase\b", {"coinbase.com"}, {"coinbase"}),
    _brand("Chase", r"\bchase\s+(bank|online|alert|card)\b|\bjpmorgan\s+chase\b", {"chase.com"}, {"chase"}),
    _brand("Wells Fargo", r"\bwells\s?fargo\b", {"wellsfargo.com"}, {"wellsfargo"}),
    _brand("Bank of America", r"\bbank\s+of\s+america\b", {"bankofamerica.com", "bofa.com"}, {"bankofamerica"}),
    _brand("Adobe", r"\badobe\b", {"adobe.com"}, {"adobe"}),
    _brand("IRS", r"\bIRS\b|\binternal\s+revenue\s+service\b", {"irs.gov"}, {"irs"}),
)

# Consumer mailbox providers. Using one is NOT malicious by itself; it only
# matters when the email claims to come from a company.
FREE_EMAIL_PROVIDERS: frozenset[str] = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "yahoo.co.uk", "ymail.com", "aol.com", "icloud.com", "me.com", "mail.com",
    "gmx.com", "gmx.de", "gmx.net", "proton.me", "protonmail.com", "zoho.com", "yandex.com",
    "yandex.ru", "qq.com", "163.com", "tutanota.com", "mail.ru",
})

URL_SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id", "v.gd",
    "shorturl.com", "tiny.one",
})

# Two-label public suffixes for a basic "registrable domain" calculation.
# A full implementation would use the Public Suffix List; this covers the
# common cases and is documented as a limitation.
MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in", "co.jp",
    "com.br", "co.nz", "co.za", "com.mx", "com.sg", "com.cn", "co.kr", "com.tr", "com.hk",
})

# Common look-alike characters from other scripts -> the Latin letter they
# imitate. Covers frequent homograph attacks; not the full Unicode list.
CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
    "ј": "j", "ԁ": "d", "һ": "h", "ӏ": "l", "ѕ": "s", "ԛ": "q", "ԝ": "w", "ь": "b",
    # Greek
    "ο": "o", "α": "a", "ι": "i", "κ": "k", "ν": "v", "τ": "t", "ρ": "p", "υ": "u",
    # Latin variants
    "ı": "i", "ł": "l", "ɩ": "i", "ɡ": "g", "ⅼ": "l",
}

# ASCII tricks used in typosquatting: digit-for-letter and letter pairs.
ASCII_LOOKALIKES: tuple[tuple[str, str], ...] = (
    ("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"),
)
