"""
PhishLens - Streamlit entry point.

Run with:  streamlit run app.py

This file is only the user interface. It:
  1. collects input (paste / upload / headers),
  2. calls core.email_parser to parse it,
  3. calls core.investigation.investigate() for the deterministic report,
  4. optionally runs integrations the user enabled and consented to,
  5. renders the report with ui.components.

No investigation logic lives here, so the engine can be tested and reused
(e.g. later from an Outlook add-in or an API) without Streamlit.
"""

from __future__ import annotations

import logging

import streamlit as st

from core.email_parser import InputValidationError, parse_eml_bytes, parse_header_block, parse_pasted_text
from core.investigation import investigate
from core.report_generator import InvestigationReport
from integrations import claude_client, virustotal_client
from models.email_data import ParsedEmail
from ui import components as ui
from ui.styles import CSS

# Log format contains no email content; modules log counts and statuses only.
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("phishlens.app")

st.set_page_config(page_title="PhishLens", page_icon="🔍", layout="wide")
st.markdown(CSS, unsafe_allow_html=True)

PAGES = ("Investigate Email", "Recent Investigations", "How It Works", "Settings")
MAX_RECENT = 10


def init_state() -> None:
    defaults = {
        "report": None,
        "recent": [],
        "keep_history": True,
        "enable_virustotal": False,
        "enable_ai": False,
        "ai_answers": {},
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

def sidebar() -> str:
    with st.sidebar:
        st.markdown('<p class="pl-brand">PhishLens</p>', unsafe_allow_html=True)
        st.markdown('<p class="pl-tagline">Don\'t trust the email. Verify it.</p>', unsafe_allow_html=True)
        page = st.radio("Navigation", PAGES, label_visibility="collapsed")
        st.markdown(
            '<div class="pl-privacy"><b>Privacy</b><br>'
            "Emails are analysed in memory and not saved. Links are never opened. "
            "External services are off unless you enable them in Settings.</div>",
            unsafe_allow_html=True,
        )
    return page


# ---------------------------------------------------------------------------
# Investigate page
# ---------------------------------------------------------------------------

def page_investigate() -> None:
    st.title("Investigate an email")
    st.markdown(
        "Submit a suspicious email to get an evidence-based report: what looks wrong, how sure "
        "PhishLens is, what it couldn't check, and what to do next."
    )

    tab_paste, tab_upload, tab_headers = st.tabs(["Paste email", "Upload .eml / .txt", "Analyze headers"])
    parsed: ParsedEmail | None = None

    with tab_paste:
        with st.form("paste_form"):
            text = st.text_area(
                "Email content", height=260,
                placeholder="From: Recruiter <jobs@example.com>\nSubject: Remote job offer\n\nHello, ...",
                help="Include the From, Reply-To and Subject lines if you can. Missing parts are fine.",
            )
            submitted = st.form_submit_button("Analyze email", type="primary")
        if submitted:
            parsed = _safe_parse(lambda: parse_pasted_text(text), empty=not text.strip())

    with tab_upload:
        with st.form("upload_form"):
            uploaded = st.file_uploader(
                "Email file", type=["eml", "txt"],
                help="In most mail apps: open the email, then 'Download' or 'Save as' (.eml). Max 5 MB.",
            )
            st.caption("Attachments inside the file are listed but never opened.")
            submitted = st.form_submit_button("Analyze file", type="primary")
        if submitted:
            if uploaded is None:
                st.error("Choose a .eml or .txt file first.")
            else:
                data = uploaded.getvalue()
                parsed = _safe_parse(lambda: parse_eml_bytes(data, uploaded.name))

    with tab_headers:
        st.info(
            "Headers can be forged. Authentication results (SPF, DKIM, DMARC) are only trustworthy if "
            "they were added by your own mail provider, usually the top-most Authentication-Results header."
        )
        with st.form("header_form"):
            headers = st.text_area("Full email headers", height=220,
                                   placeholder="Received: from ...\nAuthentication-Results: ...\nFrom: ...")
            body = st.text_area("Email body (optional)", height=120)
            submitted = st.form_submit_button("Analyze headers", type="primary")
        if submitted:
            parsed = _safe_parse(lambda: parse_header_block(headers, body), empty=not headers.strip())

    if parsed is not None:
        with st.spinner("Running checks…"):
            report = investigate(parsed)
            _run_external_checks(report)
        st.session_state.report = report
        st.session_state.ai_answers = {}
        if st.session_state.keep_history:
            st.session_state.recent = ([report] + st.session_state.recent)[:MAX_RECENT]
        del parsed  # the parsed email (including the body) is not kept

    report = st.session_state.report
    if report is not None:
        st.divider()
        ui.render_report(report)
        _ai_section(report)


def _safe_parse(fn, empty: bool = False) -> ParsedEmail | None:  # type: ignore[no-untyped-def]
    if empty:
        st.error("Paste some email content first.")
        return None
    try:
        return fn()
    except InputValidationError as exc:
        st.error(str(exc))
    except Exception as exc:
        # Unexpected parser failure: show a safe message and log the type only.
        logger.exception("Parser failure: %s", type(exc).__name__)
        st.error("PhishLens could not read this input. Check that it is a text email and try again.")
    return None


def _run_external_checks(report: InvestigationReport) -> None:
    if not (st.session_state.enable_virustotal and virustotal_client.is_configured()):
        return
    urls = [u.original for u in report.urls if u.hostname]
    if not urls:
        return
    results = virustotal_client.lookup_urls(urls)
    report.external_results["VirusTotal"] = [
        {"url": r.url, "status": r.status, "label": r.label} for r in results
    ]
    skipped = len(set(urls)) - len(results)
    if skipped > 0:
        report.external_results["VirusTotal"].append(
            {"url": f"({skipped} more link(s))", "status": "not_checked",
             "label": f"Not checked: limit of {virustotal_client.MAX_URLS_PER_INVESTIGATION} per investigation"}
        )


def _ai_section(report: InvestigationReport) -> None:
    if not st.session_state.enable_ai:
        return
    st.markdown("#### AI explanation (optional)")
    if not claude_client.is_configured():
        st.caption("Not available: set ANTHROPIC_API_KEY and install the 'anthropic' package.")
        return
    st.caption(
        "Sends the structured findings and short evidence quotes (not the full email) to Anthropic. "
        "The AI explains the findings; it cannot change them."
    )
    consent = st.checkbox("I agree to send this report summary to Anthropic", key=f"ai_consent_{report.report_id}")
    question = st.text_input("Optional question about this report",
                             placeholder="Why is the Reply-To address a problem?")
    if st.button("Explain with AI", disabled=not consent):
        with st.spinner("Asking Claude…"):
            try:
                st.session_state.ai_answers[report.report_id] = claude_client.explain(report, question or None)
            except claude_client.ClaudeUnavailable as exc:
                st.error(str(exc))
    answer = st.session_state.ai_answers.get(report.report_id)
    if answer:
        with st.container(border=True):
            st.markdown(ui.escape_markdown(answer))
            st.caption("AI-generated explanation of PhishLens' findings. The findings above are authoritative.")


# ---------------------------------------------------------------------------
# Other pages
# ---------------------------------------------------------------------------

def page_recent() -> None:
    st.title("Recent investigations")
    st.caption("Kept only in this browser session's memory and cleared when you close the tab. "
               "Email bodies are not kept, only the reports.")
    recent: list[InvestigationReport] = st.session_state.recent
    if not recent:
        st.info("No investigations yet in this session.")
        return
    labels = [f"{r.created_at} · {r.assessment.level.value} · {r.overview.subject[:60]}" for r in recent]
    choice = st.selectbox("Choose a report", range(len(recent)), format_func=lambda i: labels[i])
    st.divider()
    ui.render_report(recent[choice])


def page_how() -> None:
    st.title("How PhishLens works")
    st.markdown("""
PhishLens runs **documented, rule-based checks** on your email. It does not ask an AI whether the
email "seems" like a scam.

**1. Parse.** The email is split into sender, reply address, headers, text, links and attachment names.
HTML is converted to plain text and never rendered. Attachments are never opened.

**2. Check.** Independent modules examine:
- **Sender:** brand impersonation in the display name, look-alike domains, Reply-To and Return-Path mismatches.
- **Links:** raw IP addresses, hidden destinations, shorteners, look-alike or international domains,
  redirect parameters, link text that shows a different site than the real target. Links are **never visited**.
- **Authentication:** SPF, DKIM and DMARC results *as written in the headers*.
- **Language:** pressure tactics, requests for passwords, codes, gift cards or crypto.
- **Recruitment:** job fees, deposits to unlock tasks, fake cheques, ID requests, chat-only interviews.
- **Attachments:** dangerous file types and disguised names.

**3. Assess.** Findings are de-duplicated by root cause and classified by ordered rules:
""")
    st.table({
        "Rule": ["C1", "C2", "H1", "H2", "M1", "M2", "I1", "L1"],
        "Result": ["Critical", "Critical", "High", "High", "Moderate", "Moderate", "Insufficient information", "Low"],
        "When": [
            "Any critical indicator (e.g. job fee, executable attachment)",
            "Serious technical/sender evidence AND serious scam language",
            "Serious technical or sender evidence",
            "Two serious language patterns, or one backed by a technical/sender warning",
            "One serious language pattern only (wording alone is capped here)",
            "Any moderate warning",
            "Too little content to judge",
            "Nothing above low. Not proof of safety.",
        ],
    })
    st.markdown("""
**Evidence labels**
- **Confirmed technical finding:** a fact PhishLens computed from the email (e.g. the reply address uses another domain).
- **Suspicious indicator:** a pattern common in scams that also appears in genuine mail.
- **Needs verification:** something you should confirm through an independent channel.
- **No evidence found:** a check ran and found nothing. Not proof of safety.
- **Not checked:** the data needed wasn't available.

**Optional extras** (off by default, require API keys and your consent): VirusTotal link reputation
(sends single URLs only) and an AI explanation (sends the structured findings, not the email).
""")


def page_settings() -> None:
    st.title("Settings")
    st.markdown("##### Privacy")
    st.session_state.keep_history = st.toggle(
        "Keep recent reports for this session", value=st.session_state.keep_history,
        help="Reports stay in memory only until you close the tab. Email bodies are never kept.",
    )
    if st.button("Clear recent investigations"):
        st.session_state.recent = []
        st.session_state.report = None
        st.success("Cleared.")

    st.markdown("##### External link reputation (VirusTotal)")
    vt_ok = virustotal_client.is_configured()
    st.caption("Status: " + ("API key configured." if vt_ok else "Not configured (set VIRUSTOTAL_API_KEY)."))
    st.session_state.enable_virustotal = st.toggle(
        "Check extracted links with VirusTotal", value=st.session_state.enable_virustotal and vt_ok,
        disabled=not vt_ok,
        help="Sends each link (max 4 per email) to VirusTotal's lookup API. The email itself is not sent. "
             "Turning this on is your consent for those lookups.",
    )

    st.markdown("##### AI explanation (Claude)")
    ai_ok = claude_client.is_configured()
    st.caption("Status: " + ("API key configured." if ai_ok else
                             "Not configured (set ANTHROPIC_API_KEY and install 'anthropic')."))
    st.session_state.enable_ai = st.toggle(
        "Show the AI explanation option on reports", value=st.session_state.enable_ai and ai_ok,
        disabled=not ai_ok,
        help="You will still be asked to confirm before anything is sent.",
    )
    st.caption("API keys are read from environment variables or Streamlit secrets and are never displayed.")


def main() -> None:
    init_state()
    page = sidebar()
    {
        "Investigate Email": page_investigate,
        "Recent Investigations": page_recent,
        "How It Works": page_how,
        "Settings": page_settings,
    }[page]()


main()
