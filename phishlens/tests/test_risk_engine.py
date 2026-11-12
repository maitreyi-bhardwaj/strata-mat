import logging
import random

from conftest import (
    ATTACHMENT_EML,
    LEGIT_WITH_SCARY_WORDS,
    MISSING_AUTH_EML,
    NORMAL_BUSINESS_EML,
    PROMPT_INJECTION_EMAIL,
    SPF_FAIL_EML,
    UPFRONT_FEE_JOB,
    rule_ids,
    run_eml,
    run_paste,
)
from core.email_parser import parse_eml_bytes, parse_pasted_text
from core.investigation import investigate
from core.report_generator import to_markdown
from core.risk_engine import RiskLevel, assess
from models.findings import Category, EvidenceType


def test_normal_business_email_is_low():
    report = run_eml(NORMAL_BUSINESS_EML)
    assert report.assessment.level == RiskLevel.LOW
    assert report.assessment.confidence == "Moderate"


def test_risk_engine_is_deterministic_regardless_of_order():
    parsed = parse_pasted_text(UPFRONT_FEE_JOB)
    findings = investigate(parsed).all_findings
    baseline = assess(findings, parsed)
    for seed in range(5):
        shuffled = findings[:]
        random.Random(seed).shuffle(shuffled)
        again = assess(shuffled, parsed)
        assert again.level == baseline.level
        assert again.rule == baseline.rule
        assert [f.rule_id for f in again.counted] == [f.rule_id for f in baseline.counted]


def test_language_only_evidence_is_capped_at_moderate():
    report = run_paste("Please reply with your password to keep your access.")
    assert "lang.credential_request" in rule_ids(report)
    assert report.assessment.level == RiskLevel.MODERATE
    assert report.assessment.rule == "M1"


def test_legitimate_email_with_suspicious_looking_language():
    report = run_paste(LEGIT_WITH_SCARY_WORDS)
    assert "lang.credential_request" not in rule_ids(report)  # negation respected
    assert report.assessment.level in (RiskLevel.LOW, RiskLevel.MODERATE)


def test_insufficient_information():
    assert run_paste("hi").assessment.level == RiskLevel.INSUFFICIENT


def test_missing_auth_lowers_confidence_and_is_listed():
    report = run_eml(MISSING_AUTH_EML)
    assert report.assessment.confidence == "Limited"
    assert report.auth.spf == "Not available"


def test_spf_failure_email():
    report = run_eml(SPF_FAIL_EML)
    assert report.assessment.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert "lang.secrecy" in rule_ids(report)


def test_suspicious_attachment_filenames_are_critical():
    report = run_eml(ATTACHMENT_EML)
    ids = rule_ids(report)
    assert {"att.executable", "att.rtlo"} <= ids
    assert report.assessment.level == RiskLevel.CRITICAL


def test_technical_findings_are_distinguishable_from_heuristics():
    report = run_paste(UPFRONT_FEE_JOB)
    for f in report.all_findings:
        if f.category == Category.SOCIAL_ENGINEERING:
            assert f.evidence_type != EvidenceType.CONFIRMED_TECHNICAL


def test_prompt_injection_does_not_change_the_assessment():
    with_injection = run_paste(PROMPT_INJECTION_EMAIL)
    without = run_paste("\n".join(PROMPT_INJECTION_EMAIL.splitlines()[:4]))
    assert "lang.ai_directed_text" in rule_ids(with_injection)
    order = list(RiskLevel)
    assert order.index(with_injection.assessment.level) <= order.index(without.assessment.level)
    assert with_injection.assessment.level != RiskLevel.LOW


def test_no_email_content_is_logged(caplog):
    canary = "CANARY-7f3a-secret-body-text"
    text = f"From: Boss <boss@example.com>\nSubject: {canary}\n\nPlease wire transfer now. {canary} https://{canary}.test/x"
    with caplog.at_level(logging.DEBUG):
        investigate(parse_pasted_text(text))
        investigate(parse_eml_bytes(text.encode(), "x.eml"))
    assert caplog.records, "expected metadata log lines"
    assert canary.lower() not in caplog.text.lower()


def test_markdown_export_is_defanged_and_escaped():
    md = to_markdown(run_paste('From: a@b.test\nSubject: <script>x</script>\n\nhttps://evil.test/login'))
    assert "https://" not in md
    assert "<script>" not in md


def test_full_pipeline_makes_no_network_calls(no_network):
    run_paste(PROMPT_INJECTION_EMAIL)
    run_eml(ATTACHMENT_EML)
    assert no_network == []
