"""
URL investigation - performed entirely OFFLINE.

PhishLens never visits, resolves (DNS) or follows any URL. Visiting a
phishing link from a server can confirm to the attacker that the address
is live, trigger downloads, or be abused to reach internal systems (SSRF).
Instead we take the URL apart as a string and inspect its structure.

For each URL we record what we found (hostname, port, ...) and flag:
  * raw IP addresses instead of domain names
  * user:password@ tricks  (http://paypal.com@evil.example/)
  * unusual ports
  * URL shorteners (destination hidden)
  * punycode / non-Latin domains and lookalike brand domains
  * open-redirect style parameters (?url=https://...)
  * HTML links whose visible text shows a different domain than the target
  * javascript:/data: links
  * plain-HTTP links (not encrypted)

`defang()` makes a URL safe to display: "https://evil.com" becomes
"hxxps://evil[.]com", which no app will turn into a clickable link.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

from core import domain_utils as du
from core.reference_data import URL_SHORTENERS
from models.email_data import ExtractedURL, ParsedEmail
from models.findings import AnalyzerResult, Category, EvidenceType, Finding, Limitation, Severity

SECTION = "links"
_STANDARD_PORTS = {None, 80, 443}
_REDIRECT_PARAMS = {"url", "redirect", "redirect_uri", "redirect_url", "next", "goto", "target",
                    "dest", "destination", "continue", "return", "returnurl", "return_to", "r", "u", "link"}
_URLISH_ANCHOR = re.compile(r"(?i)^(?:https?://)?(?:www\.)?([a-z0-9¡-￿-]+(?:\.[a-z0-9¡-￿-]+)+)")


@dataclass
class URLDetails:
    """Everything we learned about one URL, shown in the 'technical details'."""

    original: str
    defanged: str
    scheme: str = ""
    hostname: str = ""
    normalized_host: str = ""
    ascii_host: str = ""
    port: int | None = None
    has_credentials: bool = False
    is_ip: bool = False
    is_shortener: bool = False
    is_punycode: bool = False
    sources: set[str] = field(default_factory=set)
    anchor_texts: set[str] = field(default_factory=set)
    flags: list[str] = field(default_factory=list)
    parse_error: str = ""


def defang(url: str) -> str:
    """Neutralise a URL for display so it cannot be clicked or auto-linked."""
    s = re.sub(r"(?i)^http", "hxxp", url.strip())
    s = s.replace("://", "[://]")
    return s.replace(".", "[.]")


def _decode_int_ip(host: str) -> str | None:
    """Detect hosts like '3232235777' or '0xC0A80001' (an IP written as a number)."""
    try:
        if re.fullmatch(r"0x[0-9a-f]+", host, re.I):
            value = int(host, 16)
        elif re.fullmatch(r"\d{8,10}", host):
            value = int(host)
        else:
            return None
        return str(ipaddress.IPv4Address(value))
    except (ValueError, ipaddress.AddressValueError):
        return None


def inspect_url(url: str) -> URLDetails:
    """Pure string analysis of a single URL. No network access."""
    details = URLDetails(original=url, defanged=defang(url))
    candidate = url.strip()
    schemeless = candidate.lower().startswith("www.")
    if schemeless:
        candidate = "http://" + candidate  # only so urlsplit can find the host
    try:
        parts = urlsplit(candidate)
        # A bare "www." link has no scheme; don't pretend we know it is http.
        details.scheme = "" if schemeless else parts.scheme.lower()
        details.hostname = parts.hostname or ""
        details.port = parts.port  # raises ValueError for invalid ports
    except ValueError as exc:
        details.parse_error = f"Could not parse URL ({exc.__class__.__name__})"
        return details
    details.has_credentials = bool(parts.username or parts.password) or "@" in parts.netloc
    details.normalized_host = du.normalize_domain(details.hostname)
    details.ascii_host = du.to_ascii(details.normalized_host)
    details.is_ip = du.is_ip_address(details.hostname) or _decode_int_ip(details.hostname) is not None
    details.is_shortener = du.registrable_domain(details.normalized_host) in URL_SHORTENERS
    details.is_punycode = du.is_punycode(details.hostname) or du.has_non_ascii(details.normalized_host)
    return details


def analyze_urls(parsed: ParsedEmail) -> tuple[AnalyzerResult, list[URLDetails]]:
    out = AnalyzerResult()
    by_url: dict[str, URLDetails] = {}
    occurrences: dict[str, list[ExtractedURL]] = {}
    for item in parsed.urls:
        occurrences.setdefault(item.url, []).append(item)

    if not occurrences:
        out.findings.append(Finding(
            rule_id="url.none_found",
            title="No links found",
            category=Category.TECHNICAL,
            evidence_type=EvidenceType.NO_EVIDENCE,
            severity=Severity.INFO,
            explanation="PhishLens did not find any web links in the message.",
            section=SECTION,
        ))
        return out, []

    for url, items in occurrences.items():
        d = inspect_url(url)
        d.sources = {i.source for i in items}
        d.anchor_texts = {i.anchor_text for i in items if i.anchor_text}
        by_url[url] = d
        _apply_url_rules(d, items, out)

    flagged = [d for d in by_url.values() if d.flags]
    if not flagged:
        out.findings.append(Finding(
            rule_id="url.no_issues",
            title="No suspicious link structures detected",
            category=Category.TECHNICAL,
            evidence_type=EvidenceType.NO_EVIDENCE,
            severity=Severity.INFO,
            explanation="The links' structure looks ordinary. PhishLens did not check whether the "
                        "destination websites are malicious; that requires an external reputation "
                        "service.",
            section=SECTION,
        ))
    out.limitations.append(Limitation(
        "Links",
        "Links were analysed as text only. PhishLens did not open them, follow redirects or check "
        "the destination's reputation (unless you enabled an external check).",
    ))
    return out, list(by_url.values())


def _apply_url_rules(d: URLDetails, items: list[ExtractedURL], out: AnalyzerResult) -> None:
    host = d.normalized_host
    ev = (f"Link: {d.defanged}",)

    def add(rule: str, title: str, severity: Severity, explanation: str,
            evidence_type: EvidenceType = EvidenceType.CONFIRMED_TECHNICAL,
            extra: tuple[str, ...] = (), root: str = "") -> None:
        d.flags.append(title)
        out.findings.append(Finding(
            rule_id=rule, title=title, category=Category.TECHNICAL, evidence_type=evidence_type,
            severity=severity, explanation=explanation, section=SECTION, evidence=ev + extra,
            # One root cause per (rule, host) so 10 links to the same bad host count once.
            root_cause=root or f"{rule}:{host or d.original[:60]}",
        ))

    if d.parse_error:
        add("url.malformed", "Malformed link", Severity.LOW,
            "This link could not be parsed normally. Malformed links are sometimes used to confuse "
            "security filters.", EvidenceType.SUSPICIOUS_INDICATOR)
        return

    if d.scheme in ("javascript", "data", "vbscript"):
        add("url.script_scheme", f"Link uses the '{d.scheme}:' scheme", Severity.HIGH,
            "This link would run code or open embedded content instead of going to a website. "
            "Legitimate emails essentially never do this.")
        return

    if d.has_credentials:
        add("url.credentials_in_url", "Link hides its real destination using '@'", Severity.HIGH,
            "Text before an '@' in a web address is ignored by the browser. "
            "'https://paypal.com@evil.example' actually goes to evil.example. This is a "
            "deliberate deception technique.")

    if d.is_ip:
        add("url.ip_host", "Link points to a raw IP address", Severity.HIGH,
            "The link uses a numeric server address instead of a company name. Legitimate "
            "organisations almost always use their domain name in emails.")

    if d.port not in _STANDARD_PORTS:
        add("url.unusual_port", f"Link uses an unusual port ({d.port})", Severity.MODERATE,
            "Websites normally use the standard ports. A custom port can indicate a temporary or "
            "improvised server.")

    if d.is_shortener:
        add("url.shortener", "Link uses a URL shortener", Severity.MODERATE,
            "Shortened links hide the real destination, so you cannot see where they go before "
            "clicking. Shorteners have legitimate uses, but they're common in phishing.",
            EvidenceType.NEEDS_VERIFICATION)

    if d.is_punycode:
        mixed = du.is_mixed_script(host)
        add("url.idn_host", "Link domain uses international (non-Latin) characters",
            Severity.HIGH if mixed else Severity.MODERATE,
            "Domains with non-Latin characters can be crafted to look identical to well-known "
            "sites (homograph attack)." + (" This one mixes alphabets in a single name." if mixed else ""),
            extra=(f"Actual (punycode) form: {d.ascii_host}",), root=f"lookalike:{host}")

    if not d.is_ip:
        match = du.find_lookalike_brand(host)
        if match:
            brand, reason = match
            add("url.lookalike_domain", f"Link domain may imitate {brand.name}",
                Severity.MODERATE if reason == "embedded" else Severity.HIGH,
                f"The domain '{host}' resembles {brand.name} but is not one of its known domains. "
                f"Fake login pages are often hosted on domains like this.",
                EvidenceType.SUSPICIOUS_INDICATOR,
                extra=(f"Known {brand.name} domains: {', '.join(sorted(brand.official_domains)[:4])}",),
                root=f"lookalike:{host}")

    try:
        query = parse_qsl(urlsplit(d.original).query, keep_blank_values=True)
    except ValueError:
        query = []
    for key, value in query:
        if key.lower() in _REDIRECT_PARAMS and re.match(r"(?i)(https?:|//|www\.)", value):
            add("url.redirect_param", "Link contains an embedded redirect to another address",
                Severity.MODERATE,
                "The link carries a second web address in its parameters. Attackers use trusted "
                "sites' redirect features to bounce victims to a malicious page.",
                EvidenceType.SUSPICIOUS_INDICATOR, extra=(f"Embedded target: {defang(value[:120])}",))
            break

    if d.scheme == "http" and not d.is_ip:
        add("url.not_https", "Link is not encrypted (http)", Severity.LOW,
            "The link uses plain HTTP. Any page asking for a password over HTTP is unsafe. "
            "On its own, this is weak evidence.", EvidenceType.SUSPICIOUS_INDICATOR)

    # Misleading HTML: visible text shows one domain, the link goes elsewhere.
    for item in items:
        if item.source != "html_href" or not item.anchor_text:
            continue
        m = _URLISH_ANCHOR.match(item.anchor_text.strip())
        if not m:
            continue
        shown = du.normalize_domain(m.group(1))
        if "." in shown and host and du.registrable_domain(shown) != du.registrable_domain(host):
            add("url.anchor_mismatch", "Link text shows a different website than the real destination",
                Severity.HIGH,
                "The email displays one web address but the link actually goes to another. "
                "This is one of the clearest signs of a deceptive link.",
                extra=(f"Text shown: {defang(item.anchor_text[:120])}",))
            break

    if any(i.source == "html_form" for i in items):
        add("url.html_form", "Email contains a form that submits data to a website", Severity.HIGH,
            "Forms inside emails can send whatever you type (such as passwords) straight to a "
            "remote server. Legitimate companies ask you to log in on their own website instead.")
