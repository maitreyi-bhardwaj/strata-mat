"""
Language and social-engineering analysis using explainable rules.

How a rule works
----------------
A `Rule` is a named regular expression plus a severity and a plain-English
explanation. `run_rules()` searches the email text and, for each rule that
matches, produces ONE finding containing up to three short quotes from the
email as evidence. You can read every rule below and know exactly why
something was flagged - there is no hidden model.

Deliberate choices
------------------
* All language findings are "Suspicious indicator", never "confirmed":
  wording alone cannot prove fraud. The risk engine caps the impact of
  language-only evidence (see risk_engine.py).
* No rules about spelling or grammar. Poor writing is not evidence of
  fraud (many legitimate senders write in a second language), and good
  writing is not evidence of safety.
* Simple negation handling: "We will NEVER ask for your password" does
  not trigger the password-request rule.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from models.email_data import ParsedEmail
from models.findings import AnalyzerResult, Category, EvidenceType, Finding, Severity

_NEGATION = re.compile(r"\b(never|not|no|don'?t|do not|won'?t|will not|cannot|can'?t|nobody)\b[^.!?\n]*$", re.I)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    explanation: str
    section: str = "social"
    evidence_type: EvidenceType = EvidenceType.SUSPICIOUS_INDICATOR
    negatable: bool = False
    root_cause: str = ""


def _r(rule_id: str, title: str, pattern: str, severity: Severity, explanation: str, **kw: object) -> Rule:
    return Rule(rule_id, title, re.compile(pattern, re.I), severity, explanation, **kw)  # type: ignore[arg-type]


def snippet(text: str, start: int, end: int, width: int = 50) -> str:
    """A short quote around a match, on one line, for use as evidence."""
    a, b = max(0, start - width), min(len(text), end + width)
    s = " ".join(text[a:b].split())
    return ("…" if a > 0 else "") + s + ("…" if b < len(text) else "")


def run_rules(rules: tuple[Rule, ...], text: str, category: Category = Category.SOCIAL_ENGINEERING) -> list[Finding]:
    """Apply rules to text. Deterministic: same input -> same findings."""
    findings: list[Finding] = []
    for rule in rules:
        quotes: list[str] = []
        for m in rule.pattern.finditer(text):
            if rule.negatable and _is_negated(text, m.start()):
                continue
            quotes.append(snippet(text, m.start(), m.end()))
            if len(quotes) == 3:
                break
        if quotes:
            findings.append(Finding(
                rule_id=rule.rule_id, title=rule.title, category=category,
                evidence_type=rule.evidence_type, severity=rule.severity,
                explanation=rule.explanation, section=rule.section,
                evidence=tuple(f"“{q}”" for q in quotes),
                root_cause=rule.root_cause or rule.rule_id,
            ))
    return findings


def _is_negated(text: str, start: int) -> bool:
    """True if a negation word appears earlier in the same sentence (within 60 chars)."""
    window = text[max(0, start - 60):start]
    return bool(_NEGATION.search(window))


LANGUAGE_RULES: tuple[Rule, ...] = (
    _r("lang.urgency", "Pressure to act quickly",
       r"\b(urgent(ly)?|immediately|right away|act now|within (\d+|twenty[- ]four|forty[- ]eight) hours|"
       r"expires? (today|soon|in \d+)|final (notice|warning|reminder)|last chance|time[- ]sensitive|"
       r"as soon as possible|before it'?s too late)\b",
       Severity.LOW,
       "Scams create time pressure so you act before thinking. Real deadlines exist too, so this is "
       "only a mild signal on its own."),
    _r("lang.account_threat", "Threat to suspend or close an account",
       r"\b((account|access|mailbox|service|card)s? (will be|has been|have been|is being|may be|is) "
       r"(suspended|closed|locked|disabled|terminated|deactivated|restricted|deleted|on hold)|"
       r"unusual (sign[- ]?in|login|log[- ]in) (activity|attempt)|verify your (account|identity|mailbox)|"
       r"(confirm|update|validate) your (account|billing|payment|login) (details|information|info))\b",
       Severity.MODERATE,
       "Messages claiming your account is about to be closed are a common way to push people onto "
       "fake login pages. Check by going to the service's website yourself, not through the email.",
       negatable=True),
    _r("lang.credential_request", "Request for a password or verification code",
       r"\b(enter|provide|send|confirm|share|verify|reply with|give us|type)\b[^.\n]{0,40}\b(password|passcode|"
       r"verification code|one[- ]time (code|password|pin)|\bOTP\b|\bPIN\b|security code|2fa code|"
       r"login credentials|authentication code)",
       Severity.HIGH,
       "Legitimate organisations do not ask you to send passwords or one-time codes by email or "
       "reply. Anyone holding these can take over your account.",
       negatable=True, root_cause="se.credential_request"),
    _r("lang.gift_card_crypto", "Payment requested in gift cards or cryptocurrency",
       r"\b((buy|purchase|pay|send|deposit|transfer|get)\b[^.\n]{0,60}\b(gift ?cards?|itunes cards?|"
       r"google play cards?|steam cards?|bitcoin|\bBTC\b|USDT|crypto(currency)?|ethereum)|"
       r"(gift card|bitcoin|crypto(currency)?) (payment|codes?|wallet( address)?))\b",
       Severity.HIGH,
       "Gift cards and cryptocurrency are hard to trace and almost impossible to reverse, which is "
       "why scammers ask for them. Real businesses and government agencies don't take payment this way.",
       negatable=True, root_cause="se.untraceable_payment"),
    _r("lang.unusual_payment", "Unusual payment or banking instructions",
       r"\b(wire transfer|western union|moneygram|(new|updated|changed?) (bank|banking|account|payment) "
       r"(details|information|info|number)|change (of|in|to) (our )?(bank|payment) details|"
       r"pay (the|this) invoice (immediately|today|urgently)|overdue invoice|outstanding (payment|balance))\b",
       Severity.MODERATE,
       "Requests to pay or to change where payments go are a common business email scam. Always confirm "
       "payment changes by phone using a number you already know, not one from the email."),
    _r("lang.messaging_platform", "Asked to move the conversation to a chat app",
       r"\b((contact|message|text|chat|add|reach|move|continue|connect|interview)\b[^.\n]{0,60}\b"
       r"(telegram|whatsapp|wickr|viber|signal app|on signal)\b|\b(telegram|whatsapp)\b[^.\n]{0,30}"
       r"(@\w+|\+\d|number|\bid\b|handle|username))",
       Severity.MODERATE,
       "Moving to WhatsApp, Telegram or similar apps takes the conversation away from company systems "
       "and email filters. Legitimate employers and companies rarely require this.",
       root_cause="se.messaging_platform"),
    _r("lang.prize", "Prize, refund or windfall claim",
       r"\b(you('ve| have) (won|been selected to receive)|claim your (prize|reward|refund|winnings|funds)|"
       r"lottery|inheritance|unclaimed (funds|package|reward))\b",
       Severity.MODERATE,
       "Unexpected money or prizes are a classic lure to collect personal details or fees."),
    _r("lang.delivery", "Delivery problem or fee",
       r"\b((package|parcel|shipment|delivery) (is |was |has been )?(on hold|held|suspended|failed|"
       r"undeliverable|could not be delivered)|(redelivery|customs|shipping|delivery|release) fee|"
       r"reschedule (your )?delivery)\b",
       Severity.MODERATE,
       "Fake delivery notices ask for small fees or card details. Track parcels on the courier's own "
       "website using the tracking number from your original order."),
    _r("lang.document_lure", "Prompt to open a shared or secure document",
       r"\b(shared (a |an )?(document|file|folder) with you|(view|open|review|access) (the )?(secure |"
       r"shared |encrypted )?(document|file|invoice|pdf)|you have (a |\d+ )?(new )?(secure|encrypted) "
       r"(message|document)|pending (documents?|messages?))\b",
       Severity.LOW,
       "Fake 'document shared with you' messages lead to look-alike login pages. If you were expecting "
       "a document, open it from the service directly.",
       evidence_type=EvidenceType.NEEDS_VERIFICATION),
    _r("lang.attachment_pressure", "Asked to open an attachment",
       r"\b((open|see|review|download|check|view) (the )?(attached|attachment)|find attached|"
       r"attached (invoice|document|file|form))\b",
       Severity.LOW,
       "Attachments can carry malware. Only open attachments you were expecting from a sender you "
       "have verified."),
    _r("lang.secrecy", "Asked to keep the request secret",
       r"\b(keep (this|it) (confidential|between us|private|quiet)|do not (tell|discuss|inform)|"
       r"don'?t tell (anyone|your))\b",
       Severity.MODERATE,
       "Scammers ask for secrecy to stop you from checking with colleagues, family or the real company."),
    _r("lang.ai_directed_text", "Text that tries to instruct AI tools",
       r"\b(ignore (all |any )?(previous|prior|above|earlier) (instructions|rules)|disregard (your|all|the) "
       r"(rules|instructions)|system prompt|you are (now )?(an? )?(ai|assistant|language model)|"
       r"(classify|mark|label|treat) this (email|message) as (safe|legitimate|not (spam|phishing))|"
       r"(ai|assistant|language model)s?,? (must|should) (ignore|mark|treat|say))\b",
       Severity.MODERATE,
       "The email contains instructions aimed at AI assistants or automated filters. Legitimate emails "
       "do not do this; it is an attempt to manipulate tools that read your mail. PhishLens' rules "
       "ignore such instructions."),
)


def analyze_language(parsed: ParsedEmail) -> AnalyzerResult:
    out = AnalyzerResult()
    text = parsed.combined_text
    if not text.strip():
        return out
    out.findings.extend(run_rules(LANGUAGE_RULES, text))
    if not out.findings:
        out.findings.append(Finding(
            rule_id="lang.no_issues",
            title="No common pressure or scam phrases detected",
            category=Category.SOCIAL_ENGINEERING,
            evidence_type=EvidenceType.NO_EVIDENCE,
            severity=Severity.INFO,
            explanation="PhishLens' wording rules found nothing. Well-written scams can avoid these "
                        "phrases, so this is not proof of safety.",
            section="social",
        ))
    return out
