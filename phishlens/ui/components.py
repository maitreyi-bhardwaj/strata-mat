"""
Reusable Streamlit components for rendering an InvestigationReport.

XSS / link-safety rules applied throughout this file
----------------------------------------------------
1. Text that came from the email (subject, sender, evidence quotes, URLs)
   is shown with `st.code(...)`, which displays literal text: no HTML, no
   Markdown, and no auto-linking.
2. Our own trusted strings (titles, explanations) may use `st.markdown`.
3. `unsafe_allow_html=True` is used only for the static CSS and for badges
   whose text comes from our own enums, passed through `html.escape`.
4. AI output is escaped with `escape_markdown()` before display.
"""

from __future__ import annotations

import html

import pandas as pd
import streamlit as st

from core.email_parser import BIDI_CONTROLS
from core.report_generator import SECTION_TITLES, InvestigationReport, to_markdown
from core.risk_engine import RiskLevel
from core.url_analyzer import defang
from models.findings import Finding, Severity

LEVEL_TONE = {
    RiskLevel.CRITICAL: "critical",
    RiskLevel.HIGH: "red",
    RiskLevel.MODERATE: "amber",
    RiskLevel.LOW: "neutral",
    RiskLevel.INSUFFICIENT: "neutral",
}
SEVERITY_TONE = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "red",
    Severity.MODERATE: "amber",
    Severity.LOW: "neutral",
    Severity.INFO: "neutral",
}


def escape_markdown(text: str) -> str:
    """Make arbitrary text inert for st.markdown: escape syntax, defang links,
    and break e-mail auto-links."""
    text = text.replace("\\", "\\\\")
    for ch in "`*_{}[]()<>#+!|~":
        text = text.replace(ch, "\\" + ch)
    text = text.replace("://", "[://]").replace("www.", "www[.]").replace("@", " [at] ")
    return text


def visible_controls(text: str) -> str:
    """Show hidden direction-control characters instead of letting them
    reorder the text on screen."""
    return "".join(f"[U+{ord(ch):04X}]" if ch in BIDI_CONTROLS else ch for ch in text)


def literal(value: str) -> None:
    """Display untrusted text literally (never as HTML/Markdown/link)."""
    st.code(visible_controls(value) or "-", language=None, wrap_lines=True)


def pill(text: str, tone: str = "neutral") -> str:
    return f'<span class="pl-pill {html.escape(tone)}">{html.escape(text)}</span>'


def risk_banner(report: InvestigationReport) -> None:
    a = report.assessment
    tone = LEVEL_TONE[a.level]
    st.markdown(
        f'<div class="pl-banner {tone}">'
        f'<p class="lvl">{html.escape(a.level.value)}</p>'
        f'<p class="desc">{html.escape(a.rule_description)} '
        f'<span style="opacity:.6">(rule {html.escape(a.rule)})</span></p>'
        f'<p class="conf">Confidence: {html.escape(a.confidence)}. {html.escape(a.confidence_note)}</p>'
        f"</div>",
        unsafe_allow_html=True,
    )


def main_reasons(report: InvestigationReport) -> None:
    reasons = report.assessment.main_reasons
    st.markdown("##### Main reasons")
    if not reasons:
        st.markdown("No warning signs were found by PhishLens' checks. This is not proof of safety.")
        return
    for f in reasons:
        st.markdown(
            pill(f.severity.label, SEVERITY_TONE[f.severity]) + pill(f.evidence_type.value)
            + " " + html.escape(f.title),
            unsafe_allow_html=True,
        )
    if report.assessment.related:
        st.caption(
            f"{len(report.assessment.related)} related finding(s) describe the same underlying issue as "
            "one above and were counted once."
        )


def overview(report: InvestigationReport) -> None:
    o = report.overview
    with st.container(border=True):
        st.markdown("##### Email overview")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown('<p class="pl-label">Sender</p>', unsafe_allow_html=True)
            literal(o.sender)
            st.markdown('<p class="pl-label">Subject</p>', unsafe_allow_html=True)
            literal(o.subject)
            st.markdown('<p class="pl-label">Claimed organisation</p>', unsafe_allow_html=True)
            literal(o.claimed_organization)
        with c2:
            st.markdown('<p class="pl-label">Recipient</p>', unsafe_allow_html=True)
            literal(o.recipient)
            st.markdown('<p class="pl-label">Date</p>', unsafe_allow_html=True)
            literal(o.date)
            st.markdown('<p class="pl-label">Detected email type (heuristic)</p>', unsafe_allow_html=True)
            literal(o.email_type)


def recommendations(report: InvestigationReport) -> None:
    with st.container(border=True):
        st.markdown("##### Recommended actions")
        for r in report.recommendations:
            st.markdown(f"- {r}")


def finding_card(f: Finding) -> None:
    open_by_default = f.severity >= Severity.HIGH and f.is_actionable
    label = f"{f.severity.label.upper()} · {f.title}" if f.is_actionable else f.title
    with st.expander(label, expanded=open_by_default):
        st.markdown(
            pill(f.evidence_type.value, "neutral") + pill(f"Severity: {f.severity.label}", SEVERITY_TONE[f.severity])
            + pill(f.category.value),
            unsafe_allow_html=True,
        )
        st.markdown(f.explanation)
        if f.evidence:
            st.caption("Evidence (quoted from the email, links disabled)")
            literal("\n".join(f.evidence))
        st.caption(f"Rule: {f.rule_id}")


def findings_sections(report: InvestigationReport) -> None:
    for key, title in SECTION_TITLES.items():
        items = report.findings_by_section.get(key) or []
        if key == "recruitment" and not report.is_recruitment:
            continue
        if key == "attachments" and not items and not report.attachments:
            continue
        st.markdown(f"#### {title}")
        if key == "authentication":
            auth_table(report)
        if key == "links" and report.urls:
            url_table(report)
        if key == "attachments" and report.attachments:
            st.dataframe(
                pd.DataFrame([{"Filename": visible_controls(a.filename), "Declared type": a.content_type, "Size (bytes)": a.size_bytes}
                              for a in report.attachments]),
                hide_index=True, width="stretch",
            )
        if not items:
            st.caption("No findings in this category.")
        for f in items:
            finding_card(f)


def auth_table(report: InvestigationReport) -> None:
    c1, c2, c3 = st.columns(3)
    c1.metric("SPF", report.auth.spf)
    c2.metric("DKIM", report.auth.dkim)
    c3.metric("DMARC", report.auth.dmarc)
    st.caption(
        "Values are read from the email's own headers and are not independently verified. Headers can be "
        "forged unless your mail provider added them. Passing authentication shows where an email came "
        "from, not whether it is honest."
    )


def url_table(report: InvestigationReport) -> None:
    rows = []
    for u in report.urls:
        rows.append({
            "Link (defanged, not clickable)": defang(u.original),
            "Host shown": u.normalized_host or "-",
            "Host on the wire (punycode)": u.ascii_host or "-",
            "Found in": ", ".join(sorted(u.sources)),
            "Warnings": "; ".join(u.flags) or "none",
        })
    with st.expander(f"Technical details: {len(rows)} extracted link(s)", expanded=False):
        st.caption("PhishLens did not open any of these links.")
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")


def external_results(report: InvestigationReport) -> None:
    if not report.external_results:
        return
    st.markdown("#### External reputation checks")
    for provider, results in report.external_results.items():
        st.dataframe(
            pd.DataFrame([{"Link (defanged)": defang(r["url"]), "Result": r["label"]} for r in results]),
            hide_index=True, width="stretch",
        )
        st.caption(f"Source: {provider}. 'Unknown' or 'unavailable' is not the same as clean.")


def limitations(report: InvestigationReport) -> None:
    with st.container(border=True):
        st.markdown("##### What PhishLens could not check")
        for lim in report.limitations:
            st.markdown(f"- **{lim.area}:** {lim.description}")
        if report.parse_warnings:
            st.markdown("**Parsing notes**")
            for w in report.parse_warnings:
                st.markdown(f"- {escape_markdown(w)}")


def download_button(report: InvestigationReport) -> None:
    st.download_button(
        "Download report (Markdown)", data=to_markdown(report),
        file_name=f"phishlens-report-{report.report_id}.md", mime="text/markdown",
    )


def render_report(report: InvestigationReport) -> None:
    risk_banner(report)
    left, right = st.columns([3, 2])
    with left:
        main_reasons(report)
    with right:
        recommendations(report)
    overview(report)
    findings_sections(report)
    external_results(report)
    limitations(report)
    download_button(report)

