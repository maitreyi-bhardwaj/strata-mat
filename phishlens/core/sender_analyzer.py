"""
Sender identity analysis.

Questions this module answers:
1. Does the display name claim a brand that the address doesn't belong to?
   ("PayPal Support" <alerts@random-site.biz>)
2. Does the display name contain a *different* email address?
   ("security@paypal.com" <x@evil.example>) - a classic trick, because
   many phone mail apps show only the display name.
3. Will replies go somewhere other than the sender? (Reply-To mismatch)
4. Does the envelope sender (Return-Path) use a different domain?
5. Does the sender domain imitate a known brand (typos, homographs)?
6. Is a free mailbox (Gmail, Outlook.com...) used for a message that
   claims to come from a company?

Design rule: a free mail provider or a mismatch is a WARNING to verify,
never proof of fraud. Plenty of real recruiters and small businesses use
Gmail, and marketing platforms legitimately change Return-Path.
"""

from __future__ import annotations

import re

from core import domain_utils as du
from models.email_data import ParsedEmail
from models.findings import AnalyzerResult, Category, EvidenceType, Finding, Limitation, Severity

_EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_COMPANY_CLAIM = re.compile(
    r"\b(on behalf of|hiring team|talent acquisition|recruitment team|hr department|"
    r"human resources|customer support|security team|billing department|accounts? team)\b",
    re.I,
)
SECTION = "sender"


def detect_claimed_organization(parsed: ParsedEmail) -> str | None:
    """Best-effort guess of the organisation the email claims to represent.

    Uses the display name first (strongest claim), then subject + body.
    Returns None if nothing recognisable is claimed. This is a claim, not
    a verified identity.
    """
    if parsed.from_addr and parsed.from_addr.display_name:
        brands = du.brands_claimed_in(parsed.from_addr.display_name)
        if brands:
            return brands[0].name
    text = parsed.combined_text
    counts = {b.name: len(b.claim_pattern.findall(text)) for b in du.brands_claimed_in(text)}
    if counts:
        return max(sorted(counts), key=lambda name: counts[name])
    return None


def analyze_sender(parsed: ParsedEmail) -> AnalyzerResult:
    out = AnalyzerResult()
    sender = parsed.from_addr

    if sender is None or not sender.domain:
        out.limitations.append(Limitation(
            "Sender", "No valid sender (From) address was provided, so sender checks were skipped."
        ))
        out.findings.append(Finding(
            rule_id="sender.missing",
            title="Sender address not available",
            category=Category.CONTEXT,
            evidence_type=EvidenceType.NOT_CHECKED,
            severity=Severity.INFO,
            explanation="Include the From line (or upload the .eml file) to enable sender checks.",
            section=SECTION,
        ))
        return out

    domain = du.normalize_domain(sender.domain)
    display = sender.display_name
    from_is_free = du.is_free_provider(domain)

    # 1. Display name contains a different email address.
    embedded = [e.lower() for e in _EMAIL_IN_TEXT.findall(display)]
    if any(e != sender.email for e in embedded):
        out.findings.append(Finding(
            rule_id="sender.display_name_address_mismatch",
            title="The sender's name contains a different email address",
            category=Category.SENDER,
            evidence_type=EvidenceType.CONFIRMED_TECHNICAL,
            severity=Severity.HIGH,
            explanation="The name shown to you includes an email address that is not the real "
                        "sending address. Many mail apps display only the name, so this hides the "
                        "true sender. Legitimate senders rarely do this.",
            section=SECTION,
            evidence=(f"Display name: {display}", f"Actual address: {sender.email}"),
            root_cause="sender.impersonation",
        ))

    # 2. Display name claims a brand the address doesn't belong to.
    for brand in du.brands_claimed_in(display):
        if du.is_official_domain(domain, brand) and not from_is_free:
            continue
        out.findings.append(Finding(
            rule_id="sender.display_name_brand_mismatch",
            title=f"Sender name mentions {brand.name}, but the address is not a known {brand.name} domain",
            category=Category.SENDER,
            evidence_type=EvidenceType.SUSPICIOUS_INDICATOR,
            severity=Severity.HIGH,
            explanation=f"Anyone can set their display name to \"{brand.name}\". The actual address "
                        f"uses '{domain}', which is not on PhishLens' list of {brand.name} domains. "
                        f"Companies do use additional domains, so verify independently, but treat "
                        f"this as a strong warning sign.",
            section=SECTION,
            evidence=(f"Display name: {display}", f"Sender domain: {domain}",
                      f"Known {brand.name} domains: {', '.join(sorted(brand.official_domains)[:4])}"),
            root_cause="sender.impersonation",
        ))
        break  # one brand claim is enough

    # 3. Lookalike / homograph sender domain.
    _check_domain_lookalike(domain, sender.domain, out)

    # 4. Reply-To mismatch.
    if parsed.reply_to and parsed.reply_to.domain:
        reply_domain = du.normalize_domain(parsed.reply_to.domain)
        if du.registrable_domain(reply_domain) != du.registrable_domain(domain):
            reply_free = du.is_free_provider(reply_domain)
            severity = Severity.HIGH if (reply_free and not from_is_free) else Severity.MODERATE
            out.findings.append(Finding(
                rule_id="sender.reply_to_mismatch",
                title="Replies would go to a different domain than the sender",
                category=Category.SENDER,
                evidence_type=EvidenceType.CONFIRMED_TECHNICAL,
                severity=severity,
                explanation="If you press Reply, your answer goes to a different organisation than "
                            "the one that appears to have sent the email. This is used to collect "
                            "replies at an address the scammer controls. Some ticketing and "
                            "marketing systems do this legitimately."
                            + (" Here, replies go to a free personal mailbox, which is unusual for "
                               "an organisation." if severity == Severity.HIGH else ""),
                section=SECTION,
                evidence=(f"From: {sender.email}", f"Reply-To: {parsed.reply_to.email}"),
            ))
            _check_domain_lookalike(reply_domain, parsed.reply_to.domain, out, label="Reply-To")

    # 5. Return-Path mismatch (low weight: very common for legitimate bulk mail).
    if parsed.return_path and "@" in parsed.return_path:
        rp_domain = du.normalize_domain(parsed.return_path.rsplit("@", 1)[1])
        if du.registrable_domain(rp_domain) != du.registrable_domain(domain):
            out.findings.append(Finding(
                rule_id="sender.return_path_mismatch",
                title="Envelope sender (Return-Path) uses a different domain",
                category=Category.SENDER,
                evidence_type=EvidenceType.NEEDS_VERIFICATION,
                severity=Severity.LOW,
                explanation="The technical 'bounce' address differs from the visible sender. This is "
                            "normal for newsletters and services that send on a company's behalf, so "
                            "on its own it is weak evidence.",
                section=SECTION,
                evidence=(f"From domain: {domain}", f"Return-Path domain: {rp_domain}"),
            ))

    # 6. Free mailbox + organisational claim.
    claims_org = bool(du.brands_claimed_in(display)) or bool(_COMPANY_CLAIM.search(display + " " + parsed.combined_text[:2000]))
    if from_is_free and claims_org:
        out.findings.append(Finding(
            rule_id="sender.free_provider_org_claim",
            title="Organisation-style message sent from a free personal mailbox",
            category=Category.SENDER,
            evidence_type=EvidenceType.NEEDS_VERIFICATION,
            severity=Severity.MODERATE,
            explanation=f"The email presents itself as coming from an organisation or team, but was "
                        f"sent from a free {du.registrable_domain(domain)} account. Small businesses "
                        f"and individual recruiters sometimes do this, but established companies "
                        f"normally use their own domain. Confirm through the organisation's "
                        f"official website.",
            section=SECTION,
            evidence=(f"Sender: {sender.email}",),
            root_cause="sender.free_provider_org_claim",
        ))

    if not out.findings:
        out.findings.append(Finding(
            rule_id="sender.no_issues",
            title="No sender inconsistencies detected",
            category=Category.SENDER,
            evidence_type=EvidenceType.NO_EVIDENCE,
            severity=Severity.INFO,
            explanation="The checks PhishLens runs on the sender found nothing unusual. This does "
                        "not prove the sender is who they claim to be.",
            section=SECTION,
        ))

    out.limitations.append(Limitation(
        "Sender",
        "Sender domain reputation and age were not checked (no external lookups). Brand checks use a "
        "small built-in list and cannot confirm whether an unknown company is real.",
    ))
    return out


def _check_domain_lookalike(domain: str, raw_domain: str, out: AnalyzerResult, label: str = "Sender") -> None:
    rule_prefix = "sender" if label == "Sender" else "reply_to"
    if du.is_punycode(raw_domain) or du.has_non_ascii(domain):
        mixed = du.is_mixed_script(domain)
        out.findings.append(Finding(
            rule_id=f"{rule_prefix}.idn_domain",
            title=f"{label} domain uses international (non-Latin) characters",
            category=Category.SENDER,
            evidence_type=EvidenceType.CONFIRMED_TECHNICAL,
            severity=Severity.HIGH if mixed else Severity.MODERATE,
            explanation="The domain contains characters outside the basic Latin alphabet. This is "
                        "legitimate for many languages, but is also used to create domains that look "
                        "identical to real ones (homograph attack)."
                        + (" This domain mixes alphabets within one name, which is a strong warning "
                           "sign." if mixed else ""),
            section=SECTION,
            evidence=(f"Displayed as: {domain}", f"Actual (punycode) form: {du.to_ascii(domain)}"),
            root_cause=f"{rule_prefix}.lookalike",
        ))
    match = du.find_lookalike_brand(domain)
    if match:
        brand, reason = match
        reasons = {
            "homograph": "uses look-alike characters to imitate",
            "typo": "is a near-miss spelling of",
            "embedded": "includes the brand name but is not an official domain of",
        }
        out.findings.append(Finding(
            rule_id=f"{rule_prefix}.lookalike_domain",
            title=f"{label} domain may imitate {brand.name}",
            category=Category.SENDER,
            evidence_type=EvidenceType.SUSPICIOUS_INDICATOR,
            severity=Severity.HIGH if reason in ("homograph", "typo") else Severity.MODERATE,
            explanation=f"'{domain}' {reasons[reason]} {brand.name}. Scammers register domains like "
                        f"this so a quick glance looks right.",
            section=SECTION,
            evidence=(f"Domain: {domain}", f"Known {brand.name} domains: "
                      f"{', '.join(sorted(brand.official_domains)[:4])}"),
            root_cause=f"{rule_prefix}.lookalike",
        ))
