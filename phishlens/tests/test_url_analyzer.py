from conftest import MISLEADING_HTML_EML, MULTI_URL_EMAIL, SUSPICIOUS_URL_EMAIL, rule_ids, run_eml, run_paste
from core.email_parser import parse_pasted_text
from core.url_analyzer import analyze_urls, defang, inspect_url
from models.findings import EvidenceType


def ids_for(text):
    result, _ = analyze_urls(parse_pasted_text(text))
    return {f.rule_id for f in result.findings}


def test_ip_address_and_unusual_port():
    ids = ids_for(SUSPICIOUS_URL_EMAIL)
    assert {"url.ip_host", "url.unusual_port"} <= ids


def test_credentials_trick():
    assert "url.credentials_in_url" in ids_for("see https://paypal.com@evil.test/login")
    assert inspect_url("https://paypal.com@evil.test/login").normalized_host == "evil.test"


def test_integer_ip_host():
    assert inspect_url("http://3232235777/x").is_ip


def test_multiple_urls_each_analysed():
    ids = ids_for(MULTI_URL_EMAIL)
    assert {"url.shortener", "url.lookalike_domain", "url.redirect_param", "url.idn_host"} <= ids
    _, details = analyze_urls(parse_pasted_text(MULTI_URL_EMAIL))
    assert len(details) == 5


def test_punycode_homograph_is_decoded_for_display():
    d = inspect_url("https://xn--pple-43d.com/id")
    assert d.is_punycode
    assert d.ascii_host == "xn--pple-43d.com"
    assert d.normalized_host != d.ascii_host  # shown in Unicode


def test_misleading_html_link_text_and_javascript_and_form():
    report = run_eml(MISLEADING_HTML_EML)
    ids = rule_ids(report)
    assert {"url.anchor_mismatch", "url.script_scheme", "url.html_form"} <= ids
    mismatch = next(f for f in report.all_findings if f.rule_id == "url.anchor_mismatch")
    assert mismatch.evidence_type == EvidenceType.CONFIRMED_TECHNICAL


def test_normal_link_has_no_warnings():
    ids = ids_for("Read more at https://www.example.com/news")
    assert ids == {"url.no_issues"}


def test_malformed_url_does_not_crash():
    result, details = analyze_urls(parse_pasted_text("odd link http://[::1 and http://example.com:99999/"))
    assert details  # handled, not raised


def test_defang_prevents_clickable_links():
    out = defang("https://evil.example/login")
    assert "://" not in out.replace("[://]", "")
    assert not out.startswith("http")
    assert "[.]" in out


def test_no_url_is_ever_fetched(no_network):
    run_paste(MULTI_URL_EMAIL)
    run_eml(MISLEADING_HTML_EML)
    assert no_network == []


def test_schemeless_www_link_is_not_flagged_as_http():
    assert ids_for("Visit www.example.com/account today") == {"url.no_issues"}
