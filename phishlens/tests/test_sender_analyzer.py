from conftest import REPLY_TO_MISMATCH, UNICODE_LOOKALIKE
from core.email_parser import parse_pasted_text
from core.sender_analyzer import analyze_sender, detect_claimed_organization
from models.findings import EvidenceType, Severity


def findings_for(text):
    return {f.rule_id: f for f in analyze_sender(parse_pasted_text(text)).findings}


def test_reply_to_mismatch_is_confirmed_and_escalated_for_free_mailbox():
    f = findings_for(REPLY_TO_MISMATCH)["sender.reply_to_mismatch"]
    assert f.evidence_type == EvidenceType.CONFIRMED_TECHNICAL
    assert f.severity == Severity.HIGH  # corporate From, free-mail Reply-To


def test_reply_to_mismatch_between_two_companies_is_moderate():
    f = findings_for("From: a@shop.example\nReply-To: b@helpdesk.test\n\nhi")["sender.reply_to_mismatch"]
    assert f.severity == Severity.MODERATE


def test_display_name_brand_impersonation():
    fs = findings_for('From: "PayPal Service" <notice@account-help.test>\n\nhello')
    assert "sender.display_name_brand_mismatch" in fs


def test_display_name_with_hidden_different_address():
    fs = findings_for('From: "security@paypal.com" <x@random.test>\n\nhello')
    assert fs["sender.display_name_address_mismatch"].evidence_type == EvidenceType.CONFIRMED_TECHNICAL


def test_official_brand_domain_not_flagged():
    fs = findings_for('From: "PayPal" <service@paypal.com>\n\nYour receipt')
    assert "sender.display_name_brand_mismatch" not in fs
    assert "sender.lookalike_domain" not in fs


def test_free_mailbox_alone_is_not_flagged():
    fs = findings_for("From: Sam <sam.smith@gmail.com>\n\nAre we still on for lunch?")
    assert "sender.free_provider_org_claim" not in fs
    assert "sender.no_issues" in fs


def test_free_mailbox_with_org_claim_needs_verification():
    fs = findings_for("From: Recruitment Team <jobs.acme@gmail.com>\n\nThe hiring team at Acme invites you")
    f = fs["sender.free_provider_org_claim"]
    assert f.evidence_type == EvidenceType.NEEDS_VERIFICATION


def test_unicode_homograph_sender_domain():
    fs = findings_for(UNICODE_LOOKALIKE)
    assert "sender.idn_domain" in fs
    assert fs["sender.lookalike_domain"].severity == Severity.HIGH
    assert "xn--" in " ".join(fs["sender.idn_domain"].evidence)


def test_typosquat_sender_domain():
    fs = findings_for("From: Support <help@paypa1-support.test>\n\nhi")
    assert "sender.lookalike_domain" in fs


def test_missing_sender_is_not_checked_not_invented():
    fs = findings_for("Just some body text with no headers")
    assert fs["sender.missing"].evidence_type == EvidenceType.NOT_CHECKED


def test_claimed_organization_detection():
    assert detect_claimed_organization(parse_pasted_text('From: "Microsoft 365" <a@b.test>\n\nx')) == "Microsoft"
    assert detect_claimed_organization(parse_pasted_text("From: a@b.test\n\nhello")) is None
