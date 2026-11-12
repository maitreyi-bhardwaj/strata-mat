from conftest import MISSING_AUTH_EML, NORMAL_BUSINESS_EML, SPF_FAIL_EML, run_eml
from core.email_parser import parse_eml_bytes, parse_header_block
from core.header_analyzer import analyze_headers
from core.risk_engine import deduplicate
from models.findings import EvidenceType


def test_spf_fail_reported_as_unverified_indicator():
    result, summary = analyze_headers(parse_eml_bytes(SPF_FAIL_EML))
    assert summary.spf == "Fail"
    assert summary.dmarc == "Fail"
    assert summary.dkim == "None"
    spf = next(f for f in result.findings if f.rule_id == "auth.spf_fail")
    # A header claim is never presented as a confirmed fact.
    assert spf.evidence_type == EvidenceType.SUSPICIOUS_INDICATOR
    assert "cannot independently confirm" in spf.explanation


def test_spf_and_dmarc_failures_count_as_one_root_cause():
    result, _ = analyze_headers(parse_eml_bytes(SPF_FAIL_EML))
    counted, related = deduplicate(result.findings)
    auth_counted = [f for f in counted if f.root_cause == "auth.domain_not_authenticated"]
    assert len(auth_counted) == 1 and auth_counted[0].rule_id == "auth.dmarc_fail"
    assert any(s.rule_id == "auth.spf_fail" for s, _ in related)


def test_missing_authentication_is_not_invented():
    result, summary = analyze_headers(parse_eml_bytes(MISSING_AUTH_EML))
    assert (summary.spf, summary.dkim, summary.dmarc) == ("Not available",) * 3
    assert summary.results == ()
    rule = next(f for f in result.findings if f.rule_id == "auth.not_available")
    assert rule.evidence_type == EvidenceType.NOT_CHECKED
    assert not any(f.rule_id.endswith(("_fail", "all_pass")) for f in result.findings)
    assert any("No SPF, DKIM or DMARC" in lim.description for lim in result.limitations)


def test_all_pass_is_not_presented_as_proof_of_legitimacy():
    result, summary = analyze_headers(parse_eml_bytes(NORMAL_BUSINESS_EML))
    assert (summary.spf, summary.dkim, summary.dmarc) == ("Pass", "Pass", "Pass")
    f = next(f for f in result.findings if f.rule_id == "auth.all_pass")
    assert f.evidence_type == EvidenceType.NO_EVIDENCE
    assert "does NOT mean" in f.explanation


def test_alignment_mismatch_detected_when_no_dmarc():
    p = parse_header_block(
        "From: Shop <news@shop.example>\n"
        "Authentication-Results: mx.test; spf=pass smtp.mailfrom=bounce@mailer.test; dkim=pass header.d=mailer.test"
    )
    result, _ = analyze_headers(p)
    assert any(f.rule_id == "auth.not_aligned" for f in result.findings)


def test_unknown_result_values_are_marked_unknown():
    p = parse_header_block("From: a@example.com\nAuthentication-Results: mx.test; spf=weird")
    _, summary = analyze_headers(p)
    assert summary.spf == "Unknown"


def test_report_shows_trust_limitation():
    report = run_eml(SPF_FAIL_EML)
    assert any("not independently verified" in lim.description for lim in report.limitations)
