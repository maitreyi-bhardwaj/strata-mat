"""
The investigation pipeline: ParsedEmail -> InvestigationReport.

This is the single function the UI calls. It runs every deterministic
analyzer in a fixed order, collects their findings and limitations, asks
the risk engine for an assessment, and builds the report.

Everything here is local and offline. Optional integrations (VirusTotal,
Claude) run AFTER this, only if the user enables them, and never change
these findings.
"""

from __future__ import annotations

import logging
import time

from core.attachment_analyzer import analyze_attachments
from core.header_analyzer import analyze_headers
from core.language_analyzer import analyze_language
from core.recruitment_analyzer import analyze_recruitment
from core.report_generator import InvestigationReport, build_report
from core.risk_engine import assess
from core.sender_analyzer import analyze_sender, detect_claimed_organization
from core.url_analyzer import analyze_urls
from models.email_data import ParsedEmail
from models.findings import AnalyzerResult, Limitation

logger = logging.getLogger(__name__)


def investigate(parsed: ParsedEmail) -> InvestigationReport:
    started = time.perf_counter()
    combined = AnalyzerResult()

    header_result, auth_summary = analyze_headers(parsed)
    url_result, url_details = analyze_urls(parsed)
    recruitment_result, is_recruitment = analyze_recruitment(parsed)

    for result in (
        analyze_sender(parsed),
        header_result,
        url_result,
        analyze_language(parsed),
        recruitment_result,
        analyze_attachments(parsed),
    ):
        combined.extend(result)

    if parsed.html_body_present:
        combined.limitations.append(Limitation(
            "Content", "The HTML version of the email was converted to plain text and was not rendered."))
    combined.limitations.append(Limitation(
        "Scope", "PhishLens applies documented rules. Novel or well-crafted scams may not match any rule, "
                 "so a low result is not a guarantee of safety."))

    assessment = assess(combined.findings, parsed)
    report = build_report(
        parsed=parsed,
        findings=combined.findings,
        limitations=combined.limitations,
        assessment=assessment,
        auth=auth_summary,
        urls=url_details,
        claimed_org=detect_claimed_organization(parsed),
        is_recruitment=is_recruitment,
    )
    # Metadata only: never log email content.
    logger.info(
        "Investigation %s complete: level=%s rule=%s findings=%d urls=%d duration_ms=%.0f",
        report.report_id, assessment.level.name, assessment.rule, len(combined.findings),
        len(url_details), (time.perf_counter() - started) * 1000,
    )
    return report
