"""
Email authentication analysis: SPF, DKIM, DMARC.

Background, in plain terms
--------------------------
* SPF  - "Is this server allowed to send mail for the envelope domain?"
* DKIM - "Was the message signed by a domain's key, and unchanged since?"
* DMARC - "Do SPF/DKIM pass for a domain that matches the visible From:?"

These checks are performed by the RECEIVING mail server, which writes the
outcome into an `Authentication-Results` header. PhishLens does not
re-run them (that would need DNS lookups and the original SMTP session).
It READS what the header claims.

Trust limitation (shown to the user)
------------------------------------
Anyone can type an Authentication-Results header. A result is only
meaningful if it was added by YOUR mail provider. So every result here is
labelled "as reported in the headers", never "verified".

Authentication != legitimacy: a scammer can pass SPF/DKIM/DMARC for a
domain they own. And a failure can be innocent (forwarding, mailing lists).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from core.domain_utils import registrable_domain
from models.email_data import ParsedEmail
from models.findings import AnalyzerResult, Category, EvidenceType, Finding, Limitation, Severity

KNOWN_RESULTS = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy", "bestguesspass"}

_METHOD_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)
_PROP_RE = re.compile(r"\b(smtp\.mailfrom|header\.from|header\.d|header\.i)\s*=\s*([^\s;()]+)", re.I)
_RECEIVED_SPF_RE = re.compile(r"^\s*([a-z]+)", re.I)


@dataclass(frozen=True)
class AuthResult:
    """One authentication result as reported by a header."""

    method: str          # "spf" | "dkim" | "dmarc"
    result: str          # "pass", "fail", ... or "unknown"
    domain: str = ""     # the domain the result applies to, if stated
    source_header: str = "Authentication-Results"


@dataclass
class AuthSummary:
    """Per-method outcome shown in the report. 'Not available' means the
    input contained no result for that method."""

    spf: str = "Not available"
    dkim: str = "Not available"
    dmarc: str = "Not available"
    results: tuple[AuthResult, ...] = ()
    from_domain: str = ""
    spf_domain: str = ""
    dkim_domains: tuple[str, ...] = ()
    hops: int = 0


def parse_auth_results(parsed: ParsedEmail) -> list[AuthResult]:
    """Extract every spf=/dkim=/dmarc= result from the headers."""
    results: list[AuthResult] = []
    for header in parsed.authentication_results:
        # A header can hold several results separated by ';'. We pair each
        # method with the property (domain) that follows it in its segment.
        for segment in header.split(";"):
            m = _METHOD_RE.search(segment)
            if not m:
                continue
            method, value = m.group(1).lower(), m.group(2).lower()
            props = {k.lower(): v.strip("<>\"'") for k, v in _PROP_RE.findall(segment)}
            domain = ""
            if method == "spf":
                domain = props.get("smtp.mailfrom", "")
            elif method == "dkim":
                domain = props.get("header.d", "") or props.get("header.i", "")
            elif method == "dmarc":
                domain = props.get("header.from", "")
            if "@" in domain:
                domain = domain.rsplit("@", 1)[1]
            results.append(AuthResult(method, value if value in KNOWN_RESULTS else "unknown", domain.lower()))
    for header in parsed.received_spf:
        m = _RECEIVED_SPF_RE.match(header)
        if m:
            value = m.group(1).lower()
            results.append(AuthResult("spf", value if value in KNOWN_RESULTS else "unknown", "", "Received-SPF"))
    return results


def summarize(parsed: ParsedEmail) -> AuthSummary:
    results = parse_auth_results(parsed)
    summary = AuthSummary(results=tuple(results), hops=len(parsed.received))
    summary.from_domain = parsed.from_addr.domain if parsed.from_addr else ""
    for method in ("spf", "dkim", "dmarc"):
        values = [r.result for r in results if r.method == method]
        if values:
            # If headers disagree, show the worst reported value.
            setattr(summary, method, _worst(values).capitalize())
    spf_domains = [r.domain for r in results if r.method == "spf" and r.domain]
    summary.spf_domain = spf_domains[0] if spf_domains else ""
    summary.dkim_domains = tuple(sorted({r.domain for r in results if r.method == "dkim" and r.domain}))
    return summary


_SEVERITY_ORDER = ["fail", "permerror", "softfail", "temperror", "neutral", "none", "unknown", "policy", "bestguesspass", "pass"]


def _worst(values: list[str]) -> str:
    return min(values, key=lambda v: _SEVERITY_ORDER.index(v) if v in _SEVERITY_ORDER else 6)


def analyze_headers(parsed: ParsedEmail) -> tuple[AnalyzerResult, AuthSummary]:
    out = AnalyzerResult()
    summary = summarize(parsed)
    section = "authentication"
    trust_note = (
        " This result was read from the email's headers. PhishLens cannot "
        "independently confirm it: a header is only reliable if your own mail "
        "provider added it."
    )

    if not summary.results:
        out.limitations.append(Limitation(
            "Authentication",
            "No SPF, DKIM or DMARC results were found in the input, so sender "
            "authentication could not be assessed. This is normal for pasted "
            "text; upload the original .eml file to include headers.",
        ))
        out.findings.append(Finding(
            rule_id="auth.not_available",
            title="Sender authentication results not available",
            category=Category.CONTEXT,
            evidence_type=EvidenceType.NOT_CHECKED,
            severity=Severity.INFO,
            explanation="Without authentication headers, PhishLens cannot tell whether the "
                        "sending server was authorised to send for the sender's domain.",
            section=section,
        ))
        return out, summary

    # --- DMARC is the most meaningful single signal, check it first.
    if summary.dmarc.lower() == "fail":
        out.findings.append(Finding(
            rule_id="auth.dmarc_fail",
            title="DMARC failed according to the headers",
            category=Category.TECHNICAL,
            evidence_type=EvidenceType.SUSPICIOUS_INDICATOR,
            severity=Severity.HIGH,
            explanation="DMARC checks that the visible sender domain is backed by SPF or DKIM. "
                        "A failure means the message could not prove it came from the domain shown "
                        "in the From line, which is common in spoofing." + trust_note,
            section=section,
            evidence=_evidence(summary.results, "dmarc"),
            root_cause="auth.domain_not_authenticated",
        ))

    for method, label in (("spf", "SPF"), ("dkim", "DKIM")):
        value = getattr(summary, method).lower()
        if value in ("fail", "permerror"):
            out.findings.append(Finding(
                rule_id=f"auth.{method}_fail",
                title=f"{label} failed according to the headers",
                category=Category.TECHNICAL,
                evidence_type=EvidenceType.SUSPICIOUS_INDICATOR,
                severity=Severity.MODERATE,
                explanation=(
                    f"{label} failing means the sender could not be authenticated by this method. "
                    "There are innocent causes (email forwarding, mailing lists, misconfiguration), "
                    "so this needs to be weighed with other evidence." + trust_note
                ),
                section=section,
                evidence=_evidence(summary.results, method),
                # SPF/DKIM failures are symptoms of the same root issue as a DMARC
                # failure; the risk engine counts them once.
                root_cause="auth.domain_not_authenticated",
            ))
        elif value == "softfail":
            out.findings.append(Finding(
                rule_id=f"auth.{method}_softfail",
                title=f"{label} soft-failed according to the headers",
                category=Category.TECHNICAL,
                evidence_type=EvidenceType.SUSPICIOUS_INDICATOR,
                severity=Severity.LOW,
                explanation=f"A soft-fail means the domain owner says this server is probably not "
                            f"authorised, but asked receivers not to reject it outright." + trust_note,
                section=section,
                evidence=_evidence(summary.results, method),
                root_cause="auth.domain_not_authenticated",
            ))

    # --- Alignment: does an authenticated domain match the visible From domain?
    from_reg = registrable_domain(summary.from_domain) if summary.from_domain else ""
    if from_reg and summary.dmarc.lower() not in ("pass", "fail"):
        aligned = []
        if summary.spf.lower() == "pass" and summary.spf_domain:
            aligned.append(registrable_domain(summary.spf_domain) == from_reg)
        for d in summary.dkim_domains:
            if summary.dkim.lower() == "pass":
                aligned.append(registrable_domain(d) == from_reg)
        if aligned and not any(aligned):
            out.findings.append(Finding(
                rule_id="auth.not_aligned",
                title="Authenticated domain does not match the visible sender",
                category=Category.TECHNICAL,
                evidence_type=EvidenceType.CONFIRMED_TECHNICAL,
                severity=Severity.MODERATE,
                explanation="SPF/DKIM passed, but for a different domain than the one shown in the "
                            "From line. Email marketing services cause this legitimately; spoofers "
                            "also rely on it.",
                section=section,
                evidence=(f"From domain: {summary.from_domain}",
                          f"SPF domain: {summary.spf_domain or 'none'}",
                          f"DKIM domains: {', '.join(summary.dkim_domains) or 'none'}"),
            ))

    all_pass = all(getattr(summary, m).lower() == "pass" for m in ("spf", "dkim", "dmarc"))
    if all_pass:
        out.findings.append(Finding(
            rule_id="auth.all_pass",
            title="SPF, DKIM and DMARC pass according to the headers",
            category=Category.TECHNICAL,
            evidence_type=EvidenceType.NO_EVIDENCE,
            severity=Severity.INFO,
            explanation="The headers report that the sending domain was authenticated. This only "
                        "means the email really came from that domain. It does NOT mean the "
                        "domain or the message is trustworthy: scammers can authenticate their "
                        "own domains." + trust_note,
            section=section,
        ))

    for method in ("spf", "dkim", "dmarc"):
        if getattr(summary, method) == "Not available":
            out.limitations.append(Limitation(
                "Authentication", f"No {method.upper()} result was present in the headers."
            ))

    out.limitations.append(Limitation(
        "Authentication",
        "Authentication results were read from the provided headers and not independently "
        "verified. Headers can be forged unless they were added by your own mail provider.",
    ))
    return out, summary


def _evidence(results: tuple[AuthResult, ...], method: str) -> tuple[str, ...]:
    return tuple(
        f"{r.source_header}: {r.method}={r.result}" + (f" (domain: {r.domain})" if r.domain else "")
        for r in results if r.method == method
    )[:3]
