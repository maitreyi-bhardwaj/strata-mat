"""
Risk assessment: findings  ->  one transparent risk classification.

Why there is no numeric score
-----------------------------
A score like "87/100" looks precise but would be invented: PhishLens has no
labelled dataset to calibrate weights against. Instead, the engine applies
a short list of ordered, human-readable rules. The report shows which rule
fired and which findings it used, so every result can be explained.

Steps
-----
1. Keep only actionable findings (not "No evidence found" / "Not checked")
   with severity LOW or above.
2. De-duplicate by root cause. Several findings can be symptoms of one
   problem (e.g. SPF fail + DMARC fail = "domain not authenticated"). Only
   the most severe finding per root cause counts; the rest are listed as
   "related" so nothing is hidden.
3. Split the counted findings into evidence groups:
     strong   = technical or sender findings (computed from the message)
     language = social-engineering findings (wording heuristics)
4. Apply the first matching rule below.

Rules (first match wins)
------------------------
C1  CRITICAL  Any Critical finding (executable attachment, job fee,
              task deposit, fake-cheque pattern...).
C2  CRITICAL  A High technical/sender finding AND a High language finding
              (independent kinds of evidence agree).
H1  HIGH      Any High technical/sender finding.
H2  HIGH      Two or more different High language findings, or one High
              language finding backed by a Moderate+ technical/sender finding.
M1  MODERATE  Exactly one High language finding with no technical backing.
              Wording alone is capped at Moderate.
M2  MODERATE  Any Moderate finding.
I1  INSUFFICIENT  Very little content (under 15 words, no sender, no links)
              and nothing above Low.
L1  LOW       Everything else. "Low" never means "safe".

The engine is a pure function: same findings in, same result out.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from models.email_data import ParsedEmail
from models.findings import Category, Finding, Severity


class RiskLevel(str, Enum):
    CRITICAL = "Critical risk indicators"
    HIGH = "High risk indicators"
    MODERATE = "Moderate risk indicators"
    LOW = "Low risk indicators"
    INSUFFICIENT = "Insufficient information"


@dataclass
class Assessment:
    level: RiskLevel
    rule: str                     # e.g. "H1"
    rule_description: str        # plain-English rule that fired
    counted: list[Finding] = field(default_factory=list)
    related: list[tuple[Finding, Finding]] = field(default_factory=list)  # (suppressed, counted instead)
    confidence: str = "Limited"
    confidence_note: str = ""

    @property
    def main_reasons(self) -> list[Finding]:
        """Findings that drove the classification, most severe first."""
        return [f for f in self.counted if f.severity >= Severity.MODERATE][:5] or self.counted[:3]


_STRONG = (Category.TECHNICAL, Category.SENDER)


def deduplicate(findings: list[Finding]) -> tuple[list[Finding], list[tuple[Finding, Finding]]]:
    """Keep the most severe finding per root cause. Deterministic ordering."""
    candidates = [f for f in findings if f.is_actionable and f.severity >= Severity.LOW]
    ordered = sorted(candidates, key=lambda f: (-f.severity, f.rule_id, f.evidence))
    kept: dict[str, Finding] = {}
    related: list[tuple[Finding, Finding]] = []
    for f in ordered:
        if f.root_cause in kept:
            related.append((f, kept[f.root_cause]))
        else:
            kept[f.root_cause] = f
    return list(kept.values()), related


def assess(findings: list[Finding], parsed: ParsedEmail) -> Assessment:
    counted, related = deduplicate(findings)

    strong = [f for f in counted if f.category in _STRONG]
    language = [f for f in counted if f.category == Category.SOCIAL_ENGINEERING]
    strong_high = [f for f in strong if f.severity >= Severity.HIGH]
    strong_moderate = [f for f in strong if f.severity >= Severity.MODERATE]
    lang_high = [f for f in language if f.severity == Severity.HIGH]

    if any(f.severity == Severity.CRITICAL for f in counted):
        level, rule, desc = RiskLevel.CRITICAL, "C1", "At least one critical indicator was found."
    elif strong_high and lang_high:
        level, rule, desc = (RiskLevel.CRITICAL, "C2",
                             "A serious technical or sender problem and a serious scam-language pattern "
                             "were both found. Independent kinds of evidence point the same way.")
    elif strong_high:
        level, rule, desc = (RiskLevel.HIGH, "H1",
                             "A serious technical or sender problem was found in the message itself.")
    elif len(lang_high) >= 2 or (lang_high and strong_moderate):
        level, rule, desc = (RiskLevel.HIGH, "H2",
                             "Several serious scam-language patterns were found, or one is backed by "
                             "a technical or sender warning.")
    elif lang_high:
        level, rule, desc = (RiskLevel.MODERATE, "M1",
                             "One serious scam-language pattern was found, but nothing technical backs "
                             "it up. Wording alone is capped at Moderate.")
    elif any(f.severity == Severity.MODERATE for f in counted):
        level, rule, desc = RiskLevel.MODERATE, "M2", "At least one moderate warning was found."
    elif _insufficient(parsed):
        level, rule, desc = (RiskLevel.INSUFFICIENT, "I1",
                             "There is too little content to assess. Paste the full email including "
                             "the sender, or upload the .eml file.")
    else:
        level, rule, desc = (RiskLevel.LOW, "L1",
                             "No moderate or serious indicators were found. This is not proof that "
                             "the email is safe.")

    confidence, note = _confidence(parsed)
    return Assessment(level, rule, desc, counted, related, confidence, note)


def _insufficient(parsed: ParsedEmail) -> bool:
    return parsed.word_count < 15 and parsed.from_addr is None and not parsed.urls


def _confidence(parsed: ParsedEmail) -> tuple[str, str]:
    """How much the input allowed us to check. Never 'High': PhishLens runs
    offline and cannot verify reputation, so some uncertainty always remains."""
    missing = []
    if parsed.from_addr is None:
        missing.append("sender address")
    if not (parsed.authentication_results or parsed.received_spf):
        missing.append("authentication headers")
    if missing:
        return "Limited", "Missing: " + ", ".join(missing) + ". The assessment is based on partial information."
    return "Moderate", ("Sender and authentication data were available. Reputation of domains and links "
                        "was not checked unless you enabled external checks.")
