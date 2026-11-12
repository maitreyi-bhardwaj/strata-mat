"""
Recruitment and job-scam analysis.

Job scams target students, job seekers and freelancers. The money is
made by charging "fees", stealing identity documents for fraud, sending
fake cheques, or "task" schemes where victims deposit money to unlock
paid work. The rules below encode those patterns.

Important fairness points
-------------------------
* Remote work, AI training, data annotation and microtask platforms are
  real industries. Mentioning them is never flagged by itself. What gets
  flagged is the scam MECHANISM (paying to start, depositing to unlock
  tasks, sending ID before any verifiable hiring step).
* PhishLens has no database of real companies or recruiters. It never
  says a company is real or fake; it says what could not be verified.

The rules only run when the email looks like a job/work message
(at least two distinct recruitment terms), which avoids false alarms
on, e.g., a bank email that mentions "PIN".
"""

from __future__ import annotations

import re

from core.language_analyzer import Rule, run_rules
from models.email_data import ParsedEmail
from models.findings import AnalyzerResult, Category, EvidenceType, Finding, Limitation, Severity

SECTION = "recruitment"

_CONTEXT_TERMS = re.compile(
    r"\b(job|position|role|vacanc\w*|hiring|hire[ds]?|recruit\w*|interview\w*|offer letter|onboarding|"
    r"salary|compensation|resume|\bcv\b|candidate|employment|remote work|work from home|part[- ]time|"
    r"full[- ]time|freelanc\w*|contractor|data annotation|annotation|ai training|microtask\w*|"
    r"task platform|commission)\b",
    re.I,
)

_LOW_SKILL = re.compile(
    r"\b(no experience|entry[- ]level|part[- ]time|data entry|simple tasks?|from home|annotation|"
    r"flexible hours|few hours|no skills?|anyone can)\b", re.I)
_PAY = re.compile(
    r"(?:\$|usd\s?|£|€)\s?(\d[\d,]*(?:\.\d+)?)\s*(?:usd)?\s*(?:/|per|an|a|each)\s*(hour|hr|day|week)\b", re.I)
_PAY_THRESHOLDS = {"hour": 45, "hr": 45, "day": 400, "week": 2000}


def _r(rule_id: str, title: str, pattern: str, severity: Severity, explanation: str, **kw: object) -> Rule:
    return Rule(rule_id, title, re.compile(pattern, re.I), severity, explanation, section=SECTION, **kw)  # type: ignore[arg-type]


RECRUITMENT_RULES: tuple[Rule, ...] = (
    _r("rec.upfront_fee", "Job requires you to pay a fee",
       r"\b((registration|application|training|onboarding|processing|certification|enrol?lment|starter kit|"
       r"background check|visa|activation|membership|placement) (fee|charge|payment|deposit)|"
       r"pay (a |the )?(small |one[- ]time |refundable )?(fee|deposit) (to|before|for) "
       r"(start|begin|secure|confirm|activate|join|unlock)|(fee|deposit) (is )?(required|needed) "
       r"(to|before) (start|begin|join|activate|secure))\b",
       Severity.CRITICAL,
       "Legitimate employers pay you; they do not charge you to apply, train or start. A fee "
       "requested as part of hiring is one of the most reliable signs of a job scam.",
       negatable=True),
    _r("rec.task_deposit", "Deposit required to unlock tasks or earnings",
       r"\b((deposit|recharge|top[- ]?up|prepay|pay)\b[^.\n]{0,60}\b(unlock|activate|access|receive|withdraw)\b"
       r"[^.\n]{0,40}\b(tasks?|orders?|assignments?|commissions?|earnings)|negative balance|"
       r"(complete|finish) (\d+ )?(tasks?|orders?) to (unlock|withdraw|earn))\b",
       Severity.CRITICAL,
       "'Task' scams (often disguised as AI training, data annotation, app rating or product boosting "
       "jobs) show fake earnings, then require deposits to 'unlock' more tasks or withdraw. Real "
       "annotation and microtask platforms do not ask workers to deposit money.",
       negatable=True),
    _r("rec.check_scam", "Cheque or overpayment arrangement",
       r"\b((send|mail|issue) (you )?(a )?(cheque|check|money order) (for|to|of)|deposit (the |this |our )?"
       r"(cheque|check|money order)|(return|refund|send back|wire back|forward) (the )?(excess|difference|"
       r"remaining (amount|funds)|overpayment|extra (funds|money))|overpay(ment|ed))\b",
       Severity.CRITICAL,
       "In fake-cheque scams you receive a cheque, are asked to send part of the money elsewhere (for "
       "'equipment' or 'excess'), and the cheque later bounces, leaving you liable for the full amount."),
    _r("rec.equipment_purchase", "Asked to buy equipment through a specified vendor",
       r"\b((purchase|buy|order)\b[^.\n]{0,60}\b(equipment|laptop|computer|software|office supplies|"
       r"devices?|macbook|iphone)\b[^.\n]{0,80}\b(vendor|supplier|reimburs\w+)|(approved|designated|"
       r"preferred|certified) (vendor|supplier))\b",
       Severity.HIGH,
       "Scammers ask new 'hires' to buy equipment from a vendor they control, promising reimbursement "
       "that never comes. Real employers ship equipment or buy it directly."),
    _r("rec.sensitive_documents", "Asks for bank details or ID documents",
       r"\b(send|provide|upload|submit|share|email|attach|fill in)\b[^.\n]{0,60}\b(bank (account|details|"
       r"statement)|routing number|account number|social security|\bSSN\b|passport|driver'?s licen[cs]e|"
       r"national id|id card|copy of (your )?id|tax id|credit card)",
       Severity.HIGH,
       "Employers do need some of this information, but only after a verifiable offer, usually through "
       "an official HR system. Sending it by email to an unverified recruiter enables identity theft.",
       negatable=True),
    _r("rec.no_interview", "Job offered without a real interview",
       r"\b(no interview (is )?(required|needed|necessary)|without (an |any )?interview|you('ve| have) been "
       r"(hired|approved) (for|without)|hired immediately|immediate(ly)? hired|instant(ly)? hired)\b",
       Severity.HIGH,
       "Real employers assess candidates before hiring. An offer without any interview or skills "
       "check is a common sign of a fake job."),
    _r("rec.chat_interview", "Interview held only by text chat",
       r"\b(interview|screening|onboarding)\b[^.\n]{0,40}\b(via|over|on|through) (telegram|whatsapp|text|"
       r"chat|signal|google hangouts|wickr|teams chat)\b",
       Severity.HIGH,
       "Text-only 'interviews' on chat apps let scammers impersonate real companies without showing "
       "their face or company accounts.",
       root_cause="se.messaging_platform"),
    _r("rec.unsolicited", "Unsolicited offer or shortlisting",
       r"\b((we )?(found|came across|saw|reviewed) your (resume|cv|profile)|your (resume|cv|profile) "
       r"(was|has been) (shortlisted|selected|recommended)|you('ve| have) been (shortlisted|pre-?selected|"
       r"selected) for)\b",
       Severity.LOW,
       "Recruiters do contact people directly, but if you never applied, check that the recruiter and "
       "the job are listed on the company's official careers page.",
       evidence_type=EvidenceType.NEEDS_VERIFICATION),
    _r("rec.remote_access_tool", "Asked to install remote-access software",
       r"\b(anydesk|teamviewer|ultraviewer|rustdesk|supremo|quick ?assist|screenconnect|connectwise)\b",
       Severity.HIGH,
       "Remote-access tools give another person control of your computer. Scammers use them to steal "
       "banking details or install malware. Onboarding never requires a stranger to control your device.",
       root_cause="rec.install_software"),
    _r("rec.install_software", "Asked to download or install software",
       r"\b(download|install)\b[^.\n]{0,40}\b(app|application|software|program|extension|apk|\.exe|client)\b",
       Severity.MODERATE,
       "Installing unknown software at the request of an unverified recruiter can infect your device. "
       "Check the software is required by the company's official onboarding process.",
       root_cause="rec.install_software"),
)


def is_recruitment_context(text: str) -> bool:
    terms = {m.group(0).lower() for m in _CONTEXT_TERMS.finditer(text)}
    return len(terms) >= 2


def analyze_recruitment(parsed: ParsedEmail) -> tuple[AnalyzerResult, bool]:
    """Returns (result, is_recruitment_email)."""
    out = AnalyzerResult()
    text = parsed.combined_text
    if not is_recruitment_context(text):
        return out, False

    out.findings.extend(run_rules(RECRUITMENT_RULES, text))
    pay = _unrealistic_pay(text)
    if pay:
        out.findings.append(pay)

    if not out.findings:
        out.findings.append(Finding(
            rule_id="rec.no_issues",
            title="No common job-scam patterns detected",
            category=Category.SOCIAL_ENGINEERING,
            evidence_type=EvidenceType.NO_EVIDENCE,
            severity=Severity.INFO,
            explanation="This looks like a work or recruitment email, and none of PhishLens' job-scam "
                        "rules matched. That does not confirm the job or recruiter is real.",
            section=SECTION,
        ))
    out.limitations.append(Limitation(
        "Recruitment",
        "PhishLens cannot verify that a company, job or recruiter exists. Confirm the role on the "
        "company's official careers page and contact the company using details you find yourself.",
    ))
    return out, True


def _unrealistic_pay(text: str) -> Finding | None:
    """Flag high pay for low-skill work. Thresholds are heuristics, not market data."""
    if not _LOW_SKILL.search(text):
        return None
    hits = []
    for m in _PAY.finditer(text):
        amount = float(m.group(1).replace(",", ""))
        unit = m.group(2).lower()
        if amount >= _PAY_THRESHOLDS[unit]:
            hits.append(m.group(0).strip())
    if not hits:
        return None
    return Finding(
        rule_id="rec.unrealistic_pay",
        title="Unusually high pay for low-skill or no-experience work",
        category=Category.SOCIAL_ENGINEERING,
        evidence_type=EvidenceType.SUSPICIOUS_INDICATOR,
        severity=Severity.MODERATE,
        explanation="The offer combines high pay with little or no experience required. Scams use "
                    "attractive pay to lower your guard. (Thresholds used: $45/hour, $400/day or "
                    "$2,000/week; these are rough heuristics, not market data.)",
        section=SECTION,
        evidence=tuple(f"“{h}”" for h in hits[:3]),
    )
