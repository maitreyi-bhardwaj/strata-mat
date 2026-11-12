"""
Report generation: findings + assessment  ->  InvestigationReport.

The report is a plain data object. The Streamlit UI renders it, the
Markdown exporter writes it to text, and the optional AI layer receives
a reduced, structured version of it. Keeping one report object means all
three always agree.

Untrusted text (subject, sender, evidence quotes) is stored as-is here;
escaping happens at the edge where it is displayed or exported.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from core.header_analyzer import AuthSummary
from core.risk_engine import Assessment, RiskLevel
from core.url_analyzer import URLDetails, defang
from models.email_data import AttachmentInfo, ParsedEmail
from models.findings import Finding, Limitation, Severity

SECTION_TITLES = {
    "sender": "Sender investigation",
    "links": "Link investigation",
    "authentication": "Authentication",
    "social": "Social engineering findings",
    "recruitment": "Recruitment scam checks",
    "attachments": "Attachments",
}


@dataclass
class Overview:
    sender: str
    recipient: str
    subject: str
    date: str
    claimed_organization: str
    email_type: str


@dataclass
class InvestigationReport:
    report_id: str
    created_at: str
    source: str
    overview: Overview
    assessment: Assessment
    findings_by_section: dict[str, list[Finding]]
    auth: AuthSummary
    urls: list[URLDetails]
    attachments: list[AttachmentInfo]
    recommendations: list[str]
    limitations: list[Limitation]
    parse_warnings: list[str]
    is_recruitment: bool
    external_results: dict[str, list[dict]] = field(default_factory=dict)

    @property
    def all_findings(self) -> list[Finding]:
        return [f for fs in self.findings_by_section.values() for f in fs]


def detect_email_type(findings: list[Finding], is_recruitment: bool) -> str:
    ids = {f.rule_id for f in findings}
    if is_recruitment:
        return "Job / recruitment message"
    checks = (
        ({"lang.account_threat", "lang.credential_request"}, "Account security notice"),
        ({"lang.unusual_payment", "lang.gift_card_crypto"}, "Payment or invoice request"),
        ({"lang.delivery"}, "Delivery notification"),
        ({"lang.document_lure"}, "Document-sharing notification"),
        ({"lang.prize"}, "Prize, refund or windfall claim"),
    )
    for rules, label in checks:
        if ids & rules:
            return label
    return "General message"


def build_recommendations(findings: list[Finding], assessment: Assessment, is_recruitment: bool) -> list[str]:
    ids = {f.rule_id for f in findings if f.is_actionable}
    prefixes = {i.split(".")[0] for i in ids}
    serious_links = any(f.rule_id.startswith("url.") and f.is_actionable and f.severity >= Severity.MODERATE
                        for f in findings)
    recs: list[str] = []

    def add(text: str) -> None:
        if text not in recs:
            recs.append(text)

    if serious_links:
        add("Do not click the links in this email. If you need the service, type its address into your "
            "browser yourself or use its official app.")
    if ids & {"rec.upfront_fee", "rec.task_deposit", "rec.check_scam", "rec.equipment_purchase"}:
        add("Do not pay any fee, deposit or 'refundable' charge, and do not deposit cheques or buy equipment "
            "for this job.")
    if "rec.sensitive_documents" in ids:
        add("Do not send identity documents or bank details until you have independently confirmed the "
            "employer and received a verifiable offer.")
    if ids & {"rec.remote_access_tool", "rec.install_software"}:
        add("Do not install software or remote-access tools requested in this email.")
    if is_recruitment:
        add("Verify the job on the company's official careers page and confirm the recruiter through the "
            "company's official website or LinkedIn page.")
    if "lang.credential_request" in ids:
        add("Never share passwords or one-time codes. No legitimate organisation asks for them by email.")
    if ids & {"lang.gift_card_crypto", "lang.unusual_payment"}:
        add("Do not send money or change payment details based on this email. Confirm by phone using a "
            "number you already know.")
    if "sender" in prefixes or "reply_to" in prefixes or "auth" in prefixes:
        add("Contact the organisation using contact details you find independently (official website, "
            "your account, the back of your card), not the details in this email.")
    if "att" in prefixes:
        add("Do not open the attachment.")
    if "se.messaging_platform" in {f.root_cause for f in findings} or "lang.messaging_platform" in ids:
        add("Keep communication on official company channels; be wary of moving to WhatsApp or Telegram.")
    if assessment.level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MODERATE):
        add("Report the email as phishing using your email provider's 'Report phishing' or 'Report spam' option.")
        add("If you already clicked a link or shared information: change the affected passwords, enable "
            "two-factor authentication, and contact your bank if you shared financial details.")
    if assessment.level == RiskLevel.LOW:
        add("No strong warning signs were found. Still verify any unexpected request for money, "
            "documents or logins through an independent channel.")
    if assessment.level == RiskLevel.INSUFFICIENT:
        add("Provide more of the email (sender, full text, or the original .eml file) for a meaningful check.")
    return recs


def build_report(
    parsed: ParsedEmail,
    findings: list[Finding],
    limitations: list[Limitation],
    assessment: Assessment,
    auth: AuthSummary,
    urls: list[URLDetails],
    claimed_org: str | None,
    is_recruitment: bool,
) -> InvestigationReport:
    by_section: dict[str, list[Finding]] = {key: [] for key in SECTION_TITLES}
    for f in sorted(findings, key=lambda f: (-f.severity, f.rule_id)):
        by_section.setdefault(f.section, []).append(f)

    unique_limits: list[Limitation] = []
    for lim in limitations:
        if lim not in unique_limits:
            unique_limits.append(lim)

    overview = Overview(
        sender=parsed.from_addr.raw if parsed.from_addr else "Not provided",
        recipient=", ".join(parsed.to) if parsed.to else "Not provided",
        subject=parsed.subject or "Not provided",
        date=parsed.date or "Not provided",
        claimed_organization=claimed_org or "None detected",
        email_type=detect_email_type(findings, is_recruitment),
    )
    return InvestigationReport(
        report_id=uuid.uuid4().hex[:10],
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        source=parsed.source,
        overview=overview,
        assessment=assessment,
        findings_by_section=by_section,
        auth=auth,
        urls=urls,
        attachments=list(parsed.attachments),
        recommendations=build_recommendations(findings, assessment, is_recruitment),
        limitations=unique_limits,
        parse_warnings=list(parsed.parse_warnings),
        is_recruitment=is_recruitment,
    )


# ---------------------------------------------------------------------------
# Markdown export (safe: escaped and defanged)
# ---------------------------------------------------------------------------

def _md_escape(text: str) -> str:
    """Escape Markdown/HTML control characters and defang anything URL-like."""
    text = text.replace("\\", "\\\\")
    for ch in "`*_{}[]()<>#+!|":
        text = text.replace(ch, "\\" + ch)
    return text.replace("://", "[://]").replace("www.", "www[.]")


def to_markdown(report: InvestigationReport) -> str:
    a = report.assessment
    o = report.overview
    lines = [
        "# PhishLens investigation report",
        f"Report {report.report_id} - {report.created_at}",
        "",
        f"## Overall assessment: {a.level.value}",
        f"Rule {a.rule}: {a.rule_description}",
        f"Confidence: {a.confidence}. {a.confidence_note}",
        "",
        "## Email overview",
        f"- Sender: {_md_escape(o.sender)}",
        f"- Recipient: {_md_escape(o.recipient)}",
        f"- Subject: {_md_escape(o.subject)}",
        f"- Date: {_md_escape(o.date)}",
        f"- Claimed organisation: {_md_escape(o.claimed_organization)}",
        f"- Detected email type: {o.email_type}",
        "",
        "## Authentication (as reported in headers, not independently verified)",
        f"- SPF: {report.auth.spf}",
        f"- DKIM: {report.auth.dkim}",
        f"- DMARC: {report.auth.dmarc}",
    ]
    for key, title in SECTION_TITLES.items():
        items = report.findings_by_section.get(key) or []
        if not items:
            continue
        lines += ["", f"## {title}"]
        for f in items:
            lines.append(f"- **[{f.evidence_type.value} | {f.severity.label}] {f.title}**")
            lines.append(f"  {f.explanation}")
            for e in f.evidence:
                lines.append(f"  - Evidence: {_md_escape(e)}")
    if report.urls:
        lines += ["", "## Extracted links (defanged, not visited)"]
        lines += [f"- {_md_escape(defang(u.original))}" for u in report.urls]
    lines += ["", "## Recommended actions"] + [f"- {r}" for r in report.recommendations]
    lines += ["", "## Investigation limitations"] + [f"- {lim.area}: {lim.description}" for lim in report.limitations]
    return "\n".join(lines) + "\n"
