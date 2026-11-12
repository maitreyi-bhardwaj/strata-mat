import pytest

from conftest import ATTACHMENT_EML, MISLEADING_HTML_EML, MULTI_URL_EMAIL, NORMAL_BUSINESS_EML
from core.email_parser import (
    MAX_EML_BYTES,
    InputValidationError,
    parse_eml_bytes,
    parse_header_block,
    parse_pasted_text,
)


def test_normal_eml_extracts_all_header_fields():
    p = parse_eml_bytes(NORMAL_BUSINESS_EML)
    assert p.from_addr.email == "billing@example.com"
    assert p.from_addr.display_name == "Example Billing"
    assert p.return_path == "billing@example.com"
    assert p.subject == "Your March statement is available"
    assert p.message_id == "<abc123@example.com>"
    assert p.date.startswith("Tue, 03 Mar 2026")
    assert len(p.received) == 1
    assert "dmarc=pass" in p.authentication_results[0]
    assert "March statement" in p.text_body
    assert p.html_body_present


def test_html_is_converted_to_text_and_scripts_dropped():
    p = parse_eml_bytes(MISLEADING_HTML_EML)
    assert "alert('x')" not in p.html_text
    assert "color:red" not in p.html_text
    assert "Unusual sign-in activity" in p.html_text
    hrefs = {(u.url, u.anchor_text) for u in p.urls if u.source == "html_href"}
    assert ("http://login-verify.test/session", "https://www.example.com/secure") in hrefs
    assert any(u.source == "html_form" and u.url == "https://collect.test/pw" for u in p.urls)


def test_attachments_listed_as_metadata_only():
    p = parse_eml_bytes(ATTACHMENT_EML)
    names = [a.filename for a in p.attachments]
    assert "invoice.pdf.exe" in names
    assert any("‮" in n for n in names)
    exe = next(a for a in p.attachments if a.filename == "invoice.pdf.exe")
    assert exe.size_bytes > 0  # size measured, content never interpreted
    assert "TVqQ" not in p.text_body  # attachment content is not mixed into the body


def test_paste_without_headers_is_treated_as_body():
    p = parse_pasted_text("Hello, please click https://example.com/x.")
    assert p.from_addr is None
    assert not p.has_headers
    assert p.urls[0].url == "https://example.com/x"  # trailing period stripped


def test_paste_with_headers():
    p = parse_pasted_text("From: A <a@example.com>\nReply-To: b@example.org\nSubject: Hi\n\nBody text")
    assert p.from_addr.email == "a@example.com"
    assert p.reply_to.email == "b@example.org"
    assert p.text_body == "Body text"


def test_multiple_urls_extracted():
    p = parse_pasted_text(MULTI_URL_EMAIL)
    urls = {u.url for u in p.urls}
    assert "https://bit.ly/3xYzAbc" in urls
    assert "www.example.net/deals" in urls
    assert "https://xn--pple-43d.com/id" in urls
    assert len(urls) == 5


@pytest.mark.parametrize("data", [
    b"\xff\xfe garbage \x80\x81 not an email",
    b"From: <<<>>>@@@\nSubject: =?bogus?Q?broken?=\nContent-Type: multipart/mixed; boundary=\n\n--\n",
    b"Content-Type: text/plain; charset=does-not-exist\n\n\xe9\xe8 body",
    b"From: a@example.com\nContent-Type: multipart/mixed; boundary=\"x\"\n\n--x\nContent-Type: text/html\n\n<a href='",
    b"Subject: " + b"A" * 20000 + b"\n\nbody",
])
def test_malformed_input_does_not_crash(data):
    p = parse_eml_bytes(data, "weird.eml")
    assert p is not None  # and no exception


def test_rejects_binary_oversized_and_wrong_extension():
    with pytest.raises(InputValidationError):
        parse_eml_bytes(b"MZ\x00\x00\x00binary", "a.eml")
    with pytest.raises(InputValidationError):
        parse_eml_bytes(b"a" * (MAX_EML_BYTES + 1), "a.eml")
    with pytest.raises(InputValidationError):
        parse_eml_bytes(b"From: a@example.com\n\nhi", "a.exe")
    with pytest.raises(InputValidationError):
        parse_eml_bytes(b"", "a.eml")


def test_header_block_parsing_with_optional_body():
    p = parse_header_block("From: x@example.com\nAuthentication-Results: mx; spf=pass", "body here")
    assert p.source == "headers"
    assert p.authentication_results
    assert p.text_body == "body here"


def test_header_block_requires_content():
    with pytest.raises(InputValidationError):
        parse_header_block("   ")


def test_parsing_makes_no_network_calls(no_network):
    parse_eml_bytes(MISLEADING_HTML_EML)
    parse_pasted_text(MULTI_URL_EMAIL)
    assert no_network == []
