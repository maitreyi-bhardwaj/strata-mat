"""
Data model for a parsed email.

The parser turns raw input (pasted text, .eml bytes, header blocks) into
one `ParsedEmail`. Analyzers only ever read this object, never raw input,
so parsing quirks live in exactly one place.

`None` / empty values mean "not present in the input". Analyzers must
treat missing data as unknown, never as a pass or a fail.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

InputSource = Literal["paste", "eml", "headers"]


@dataclass(frozen=True)
class ExtractedURL:
    """A URL found in the message. Never fetched, only inspected.

    Attributes:
        url: The URL exactly as written in the email.
        source: "text" (plain-text body), "html_href" (a link target),
            "html_form" (a form action), "html_src" (image/script source).
        anchor_text: For HTML links, the visible text the reader sees.
    """

    url: str
    source: str
    anchor_text: str = ""


@dataclass(frozen=True)
class AttachmentInfo:
    """Metadata only. Attachment bytes are never opened or executed."""

    filename: str
    content_type: str
    size_bytes: int


@dataclass(frozen=True)
class Address:
    """A parsed address header such as  "PayPal Support" <a@b.com>."""

    raw: str
    display_name: str
    email: str

    @property
    def domain(self) -> str:
        """Lower-cased domain part, or "" if there is no valid address."""
        if "@" not in self.email:
            return ""
        return self.email.rsplit("@", 1)[1].strip().strip(".").lower()


@dataclass
class ParsedEmail:
    source: InputSource
    from_addr: Address | None = None
    to: list[str] = field(default_factory=list)
    reply_to: Address | None = None
    return_path: str | None = None
    subject: str | None = None
    date: str | None = None
    message_id: str | None = None
    authentication_results: list[str] = field(default_factory=list)
    received_spf: list[str] = field(default_factory=list)
    received: list[str] = field(default_factory=list)
    text_body: str = ""
    html_body_present: bool = False
    html_text: str = ""
    urls: list[ExtractedURL] = field(default_factory=list)
    attachments: list[AttachmentInfo] = field(default_factory=list)
    has_headers: bool = False
    parse_warnings: list[str] = field(default_factory=list)

    @property
    def combined_text(self) -> str:
        """All human-readable body text (plain + text extracted from HTML)."""
        parts = [p for p in (self.subject or "", self.text_body, self.html_text) if p]
        return "\n".join(parts)

    @property
    def word_count(self) -> int:
        return len(self.combined_text.split())
