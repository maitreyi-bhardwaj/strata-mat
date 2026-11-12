"""
Email parsing: raw input  ->  ParsedEmail.

Three entry points match the three ways a user can submit an email:

    parse_pasted_text(text)              # "Paste email" tab
    parse_eml_bytes(data, filename)      # "Upload file" tab
    parse_header_block(headers, body)    # "Analyze headers" tab

Security decisions in this module
---------------------------------
* Uses Python's standard `email` package (well tested against malformed
  input) instead of hand-written MIME parsing.
* HTML is NEVER rendered. It is converted to plain text with the standard
  `html.parser`, and <script>/<style> contents are discarded.
* Attachments are never decoded to disk, opened or executed. We read only
  the filename, declared type and size.
* URLs are extracted as strings. Nothing here performs network access.
* Size limits stop very large inputs from exhausting memory.
* Logs contain counts only, never email content.
"""

from __future__ import annotations

import logging
import re
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser, Parser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import PurePath

from models.email_data import Address, AttachmentInfo, ExtractedURL, ParsedEmail

logger = logging.getLogger(__name__)

MAX_EML_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_PASTE_CHARS = 300_000
MAX_MIME_PARTS = 200
MAX_URLS = 200
ALLOWED_UPLOAD_EXTENSIONS = {".eml", ".txt"}

# Matches http(s)://... and www.... in plain text. Trailing punctuation that
# is usually sentence punctuation (".", ")", ...) is stripped afterwards.
_URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'`]+")
_TRAILING_PUNCT = ".,;:!?)]}>'\""
_HEADER_LINE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,60}:[ \t]")
# Unicode direction-control characters. They can make text display in a
# different order than it is stored (e.g. "exe.pdf" shown as "fdp.exe").
BIDI_CONTROLS = frozenset("\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


class InputValidationError(ValueError):
    """Raised for input the app refuses to process (too large, binary...).

    The message is safe to show to the user.
    """


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def validate_upload(filename: str, data: bytes) -> None:
    """Server-side checks for an uploaded file.

    The browser's file-type filter is only a convenience; it can be bypassed,
    so the server must check again.
    """
    ext = PurePath(filename or "").suffix.lower()
    if ext not in ALLOWED_UPLOAD_EXTENSIONS:
        raise InputValidationError(
            f"Unsupported file type '{ext or 'none'}'. Upload a .eml or .txt file."
        )
    if len(data) == 0:
        raise InputValidationError("The uploaded file is empty.")
    if len(data) > MAX_EML_BYTES:
        raise InputValidationError(
            f"File is too large ({len(data) / 1_048_576:.1f} MB). The limit is "
            f"{MAX_EML_BYTES // 1_048_576} MB."
        )
    # Email files are text. NUL bytes near the start mean it's a binary file
    # (for example an executable renamed to .eml).
    if b"\x00" in data[:8192]:
        raise InputValidationError(
            "This file does not look like a text email (it contains binary data)."
        )


def parse_eml_bytes(data: bytes, filename: str = "upload.eml") -> ParsedEmail:
    """Parse an uploaded .eml / .txt file."""
    validate_upload(filename, data)
    msg = BytesParser(policy=policy.default).parsebytes(data)
    parsed = _from_message(msg, source="eml", headers_expected=True)
    logger.info(
        "Parsed upload: bytes=%d urls=%d attachments=%d warnings=%d",
        len(data), len(parsed.urls), len(parsed.attachments), len(parsed.parse_warnings),
    )
    return parsed


def parse_pasted_text(text: str) -> ParsedEmail:
    """Parse text pasted by the user.

    If the paste starts with header lines ("From: ...", "Subject: ..."), they
    are parsed as headers. Otherwise the whole paste is treated as the body.
    Incomplete input is fine: missing fields simply stay empty.
    """
    _check_text_size(text)
    text = text.replace("\r\n", "\n").lstrip("\n")
    if _looks_like_headers(text):
        msg = Parser(policy=policy.default).parsestr(text)
        parsed = _from_message(msg, source="paste", headers_expected=False)
    else:
        parsed = ParsedEmail(source="paste")
        parsed.text_body = text
        parsed.urls = _dedupe_urls(_urls_from_text(text, "text"), parsed)
    logger.info(
        "Parsed paste: chars=%d has_headers=%s urls=%d",
        len(text), parsed.has_headers, len(parsed.urls),
    )
    return parsed


def parse_header_block(headers: str, body: str = "") -> ParsedEmail:
    """Parse a block of raw headers, with an optional body."""
    _check_text_size(headers + body)
    headers = headers.replace("\r\n", "\n").strip()
    if not headers:
        raise InputValidationError("Paste at least one email header.")
    raw = headers + "\n\n" + body.replace("\r\n", "\n")
    msg = Parser(policy=policy.default).parsestr(raw)
    parsed = _from_message(msg, source="headers", headers_expected=True)
    if not parsed.has_headers:
        parsed.parse_warnings.append(
            "No recognisable email headers were found in the header field."
        )
    logger.info("Parsed header block: received_hops=%d", len(parsed.received))
    return parsed


# ---------------------------------------------------------------------------
# Message -> ParsedEmail
# ---------------------------------------------------------------------------

def _from_message(msg: Message, source: str, headers_expected: bool) -> ParsedEmail:
    parsed = ParsedEmail(source=source)  # type: ignore[arg-type]
    parsed.has_headers = len(msg.keys()) > 0

    for defect in getattr(msg, "defects", []):
        # Record the defect type name only, never the content.
        parsed.parse_warnings.append(f"Message structure issue: {type(defect).__name__}")

    parsed.from_addr = _address(msg, "From", parsed)
    parsed.reply_to = _address(msg, "Reply-To", parsed)
    parsed.to = [a for a in (_header(msg, "To", parsed) or "").split(",") if a.strip()]
    rp = _header(msg, "Return-Path", parsed)
    parsed.return_path = rp.strip().strip("<>").strip() if rp else None
    parsed.subject = _header(msg, "Subject", parsed)
    parsed.date = _header(msg, "Date", parsed)
    parsed.message_id = _header(msg, "Message-ID", parsed)
    parsed.authentication_results = _all_headers(msg, "Authentication-Results", parsed)
    parsed.received_spf = _all_headers(msg, "Received-SPF", parsed)
    parsed.received = _all_headers(msg, "Received", parsed)

    _extract_bodies(msg, parsed)

    urls = _urls_from_text(parsed.text_body, "text")
    urls += _urls_from_text(parsed.html_text, "text")
    urls += parsed.urls  # HTML hrefs/forms collected during body extraction
    parsed.urls = _dedupe_urls(urls, parsed)

    if headers_expected and not parsed.has_headers:
        parsed.parse_warnings.append("No email headers were found in the input.")
    return parsed


def _header(msg: Message, name: str, parsed: ParsedEmail) -> str | None:
    """Read one header defensively. Malformed headers become warnings."""
    try:
        value = msg.get(name)
    except Exception as exc:  # the email package can raise on hostile headers
        parsed.parse_warnings.append(f"Could not parse the {name} header ({type(exc).__name__}).")
        return None
    if value is None:
        return None
    text = str(value)
    if any(ch in BIDI_CONTROLS for ch in text):
        parsed.parse_warnings.append(
            f"The {name} header contained hidden text-direction characters; they were removed for display."
        )
    return _clean(text)


def _all_headers(msg: Message, name: str, parsed: ParsedEmail) -> list[str]:
    try:
        values = msg.get_all(name) or []
    except Exception as exc:
        parsed.parse_warnings.append(f"Could not parse {name} headers ({type(exc).__name__}).")
        return []
    return [_clean(str(v)) for v in values]


def _address(msg: Message, name: str, parsed: ParsedEmail) -> Address | None:
    raw = _header(msg, name, parsed)
    if not raw:
        return None
    display, email_addr = parseaddr(raw)
    if not email_addr or "@" not in email_addr:
        parsed.parse_warnings.append(f"The {name} header does not contain a valid email address.")
    return Address(raw=raw, display_name=display.strip(), email=email_addr.strip().lower())


def _clean(value: str, keep: frozenset[str] = frozenset()) -> str:
    """Collapse folded header whitespace and remove invisible/control
    characters that could confuse display (except those in `keep`)."""
    value = re.sub(r"\s*\n\s*", " ", value)
    return "".join(ch for ch in value if ch.isprintable() or ch == "\t" or ch in keep).strip()


def _extract_bodies(msg: Message, parsed: ParsedEmail) -> None:
    text_parts: list[str] = []
    html_parts: list[str] = []
    for count, part in enumerate(msg.walk()):
        if count >= MAX_MIME_PARTS:
            parsed.parse_warnings.append(
                f"Message has more than {MAX_MIME_PARTS} parts; the rest were skipped."
            )
            break
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()

        if disposition == "attachment" or filename:
            payload = part.get_payload(decode=True) or b""
            parsed.attachments.append(
                AttachmentInfo(
                    # Keep direction-control characters in filenames: the
                    # attachment analyzer needs them to detect disguised names.
                    filename=_clean(filename or "(no filename)", keep=BIDI_CONTROLS),
                    content_type=content_type,
                    size_bytes=len(payload),
                )
            )
            continue  # never decode attachment contents further
        if content_type == "text/plain":
            text_parts.append(_part_text(part, parsed))
        elif content_type == "text/html":
            html_parts.append(_part_text(part, parsed))

    parsed.text_body = "\n".join(t for t in text_parts if t).strip()
    if html_parts:
        parsed.html_body_present = True
        extractor = _SafeHTMLText()
        for html in html_parts:
            try:
                extractor.feed(html)
            except Exception as exc:
                parsed.parse_warnings.append(f"Malformed HTML could not be fully read ({type(exc).__name__}).")
        extractor.close()
        parsed.html_text = extractor.text()
        parsed.urls.extend(extractor.links)


def _part_text(part: Message, parsed: ParsedEmail) -> str:
    try:
        if isinstance(part, EmailMessage):
            content = part.get_content()
            return content if isinstance(content, str) else ""
        return str(part.get_payload())
    except (LookupError, UnicodeError, AssertionError, ValueError) as exc:
        # Unknown charset or bad encoding: decode leniently and record it.
        parsed.parse_warnings.append(f"A body part had an unreadable encoding ({type(exc).__name__}).")
        raw = part.get_payload(decode=True) or b""
        return raw.decode("utf-8", errors="replace")


class _SafeHTMLText(HTMLParser):
    """Turns HTML into plain text and collects link targets.

    Nothing is rendered or executed: we only read tags and text. Content of
    <script>, <style> and <head> is discarded.
    """

    _SKIP = {"script", "style", "head", "title", "noscript"}
    _BLOCK = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "table", "section"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []
        self._skip_depth = 0
        self._current_href: str | None = None
        self._anchor_chunks: list[str] = []
        self.links: list[ExtractedURL] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        if tag in self._SKIP:
            self._skip_depth += 1
        if tag in self._BLOCK:
            self._chunks.append("\n")
        if tag == "a" and attr.get("href"):
            self._current_href = attr["href"].strip()
            self._anchor_chunks = []
        elif tag == "form" and attr.get("action"):
            self.links.append(ExtractedURL(attr["action"].strip(), "html_form"))
        elif tag in ("img", "iframe", "script") and attr.get("src", "").lower().startswith(("http", "//")):
            self.links.append(ExtractedURL(attr["src"].strip(), "html_src"))

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP and self._skip_depth:
            self._skip_depth -= 1
        if tag == "a" and self._current_href is not None:
            anchor = " ".join("".join(self._anchor_chunks).split())
            self.links.append(ExtractedURL(self._current_href, "html_href", anchor))
            self._current_href = None

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        self._chunks.append(data)
        if self._current_href is not None:
            self._anchor_chunks.append(data)

    def text(self) -> str:
        lines = ("".join(self._chunks)).splitlines()
        return "\n".join(" ".join(line.split()) for line in lines if line.strip())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_text_size(text: str) -> None:
    if len(text) > MAX_PASTE_CHARS:
        raise InputValidationError(
            f"Input is too long ({len(text):,} characters). The limit is {MAX_PASTE_CHARS:,}."
        )


def _looks_like_headers(text: str) -> bool:
    first_line = text.split("\n", 1)[0]
    return bool(_HEADER_LINE_RE.match(first_line))


def _urls_from_text(text: str, source: str) -> list[ExtractedURL]:
    found = []
    for match in _URL_RE.finditer(text or ""):
        url = match.group(0).rstrip(_TRAILING_PUNCT)
        if len(url) > 4:
            found.append(ExtractedURL(url, source))
    return found


def _dedupe_urls(urls: list[ExtractedURL], parsed: ParsedEmail) -> list[ExtractedURL]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[ExtractedURL] = []
    for u in urls:
        key = (u.url, u.source, u.anchor_text)
        if key not in seen:
            seen.add(key)
            unique.append(u)
    if len(unique) > MAX_URLS:
        parsed.parse_warnings.append(f"Only the first {MAX_URLS} links were analysed.")
        unique = unique[:MAX_URLS]
    return unique
