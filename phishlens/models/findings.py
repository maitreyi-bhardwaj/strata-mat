"""
Finding models: the common "language" every analyzer speaks.

Every check in PhishLens produces `Finding` objects. Because all analyzers
return the same shape, the risk engine and the report can treat them
uniformly, and the UI never needs to know which module produced what.

Two separate ideas are kept apart on purpose:

* `EvidenceType` answers "how sure are we that this is TRUE?"
  (a fact we computed ourselves vs. a pattern that merely looks suspicious).
* `Severity` answers "if it is true, how much does it MATTER?"

Mixing those two is the most common way security tools mislead people.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class EvidenceType(str, Enum):
    """How the finding was established. Shown to the user as a label."""

    CONFIRMED_TECHNICAL = "Confirmed technical finding"
    """A fact PhishLens computed itself from the message, e.g. "the
    Reply-To domain differs from the From domain". The fact is certain;
    what it *means* may still need judgement."""

    SUSPICIOUS_INDICATOR = "Suspicious indicator"
    """A heuristic pattern (wording, structure) that is common in scams
    but also appears in legitimate mail."""

    NEEDS_VERIFICATION = "Needs verification"
    """Something PhishLens cannot settle; the user should check it
    through an independent channel."""

    NO_EVIDENCE = "No evidence found"
    """A check ran and found nothing. This is NOT proof of safety."""

    NOT_CHECKED = "Not checked"
    """A check could not run (missing data, disabled integration)."""


class Severity(int, Enum):
    """Impact if the finding is real. Integer values allow sorting."""

    INFO = 0
    LOW = 1
    MODERATE = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()


class Category(str, Enum):
    """The four evidence groups the risk engine keeps separate."""

    TECHNICAL = "Technical evidence"
    SENDER = "Sender evidence"
    SOCIAL_ENGINEERING = "Social engineering indicators"
    CONTEXT = "Contextual uncertainty"


@dataclass(frozen=True)
class Finding:
    """One observation produced by an analyzer.

    Attributes:
        rule_id: Stable identifier, e.g. "url.ip_host". Used for tests,
            recommendations and de-duplication.
        title: Short plain-English headline.
        category: Which evidence group it belongs to.
        evidence_type: How it was established (see EvidenceType).
        severity: Impact if real.
        explanation: Plain-English "why this matters" for non-experts.
        evidence: Concrete snippets from the email that triggered the
            rule. These are UNTRUSTED text and must be escaped on display.
        root_cause: Findings sharing a root_cause describe the same
            underlying issue; the risk engine counts only the strongest one.
            Defaults to rule_id.
        section: Which report section shows it ("sender", "links", ...).
    """

    rule_id: str
    title: str
    category: Category
    evidence_type: EvidenceType
    severity: Severity
    explanation: str
    section: str
    evidence: tuple[str, ...] = ()
    root_cause: str = ""

    def __post_init__(self) -> None:
        # frozen dataclass: use object.__setattr__ for the default
        if not self.root_cause:
            object.__setattr__(self, "root_cause", self.rule_id)

    @property
    def is_actionable(self) -> bool:
        """True for findings that can influence the risk level."""
        return self.evidence_type not in (EvidenceType.NO_EVIDENCE, EvidenceType.NOT_CHECKED)


@dataclass(frozen=True)
class Limitation:
    """Something PhishLens could not check. Always shown in the report."""

    area: str
    description: str


@dataclass
class AnalyzerResult:
    """What every analyzer returns: findings plus what it couldn't check."""

    findings: list[Finding] = field(default_factory=list)
    limitations: list[Limitation] = field(default_factory=list)

    def extend(self, other: "AnalyzerResult") -> None:
        self.findings.extend(other.findings)
        self.limitations.extend(other.limitations)
