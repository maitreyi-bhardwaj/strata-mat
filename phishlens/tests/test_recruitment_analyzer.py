from conftest import FAKE_REMOTE_AI_TASK_JOB, LEGIT_ANNOTATION_JOB, UPFRONT_FEE_JOB, rule_ids, run_paste
from core.email_parser import parse_pasted_text
from core.recruitment_analyzer import analyze_recruitment
from core.risk_engine import RiskLevel
from models.findings import Severity


def rec_ids(text):
    result, is_rec = analyze_recruitment(parse_pasted_text(text))
    return {f.rule_id for f in result.findings}, is_rec


def test_upfront_fee_job_scam():
    report = run_paste(UPFRONT_FEE_JOB)
    ids = rule_ids(report)
    assert {"rec.upfront_fee", "rec.no_interview", "rec.sensitive_documents", "rec.unrealistic_pay"} <= ids
    assert report.assessment.level == RiskLevel.CRITICAL
    assert report.is_recruitment
    fee = next(f for f in report.all_findings if f.rule_id == "rec.upfront_fee")
    assert fee.severity == Severity.CRITICAL
    assert any("pay any fee" in r for r in report.recommendations)


def test_fake_remote_ai_task_job():
    report = run_paste(FAKE_REMOTE_AI_TASK_JOB)
    ids = rule_ids(report)
    assert "rec.task_deposit" in ids
    assert "rec.chat_interview" in ids
    assert report.assessment.level == RiskLevel.CRITICAL


def test_legitimate_annotation_job_is_not_flagged_for_its_industry():
    ids, is_rec = rec_ids(LEGIT_ANNOTATION_JOB)
    assert is_rec
    assert ids == {"rec.no_issues"}
    report = run_paste(LEGIT_ANNOTATION_JOB)
    assert report.assessment.level in (RiskLevel.LOW, RiskLevel.MODERATE)
    assert any("cannot verify that a company" in lim.description for lim in report.limitations)


def test_negated_fee_is_not_flagged():
    ids, _ = rec_ids("Job offer for the remote position. There is no registration fee and we never "
                     "charge candidates. Interview next week with the hiring manager.")
    assert "rec.upfront_fee" not in ids


def test_fake_cheque_and_equipment_vendor():
    text = ("Congratulations on your new remote job position. We will send you a check for $3,000. Deposit the "
            "check and buy your laptop and software from our approved vendor, then send back the remaining funds.")
    ids, _ = rec_ids(text)
    assert {"rec.check_scam", "rec.equipment_purchase"} <= ids


def test_remote_access_tool_request():
    ids, _ = rec_ids("For onboarding in your new job position please install AnyDesk so our hiring team can help.")
    assert "rec.remote_access_tool" in ids


def test_non_recruitment_email_skips_job_rules():
    ids, is_rec = rec_ids("Your parcel is on its way. Track it in the app.")
    assert not is_rec and ids == set()
