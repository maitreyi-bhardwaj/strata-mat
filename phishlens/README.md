# PhishLens

**Don't trust the email. Verify it.**

PhishLens is an email phishing and scam investigation tool. You paste or upload a suspicious email and get
a structured report: what looks wrong, the evidence for each finding, what could not be verified, how
serious it is, and what to do next.

It is built around one principle: **never call an email fraudulent just because it sounds suspicious.**
Every finding is labelled as a confirmed technical fact, a suspicious indicator, something that needs
verification, a check that found nothing, or a check that could not run.

## Why it exists

Phishing and job scams have become convincing, and most recipients have no way to check headers, links or
sender domains. Fake recruiters, "AI training" task scams, invoice fraud and look-alike login pages all rely
on people not knowing what to look for. PhishLens shows the evidence in plain English.

## Features

- Three input methods: paste an email, upload `.eml` / `.txt`, or paste raw headers.
- Offline, rule-based analysis of:
  - the sender,
  - links,
  - authentication (SPF/DKIM/DMARC),
  - pressure language,
  - job-scam patterns,
  - attachment metadata.
- A transparent risk classification that shows which rule fired and which findings were used.
- Links are **never opened**, HTML is **never rendered**, and attachments are **never opened**.
- Optional extras, both off by default and requiring your consent:
  - VirusTotal link reputation;
  - an AI explanation using the Claude API.
- Markdown export with defanged links (`hxxps[://]evil[.]com`).

## Architecture

```
phishlens/
├── app.py                     Streamlit UI only. Collects input, calls the engine, renders the report.
├── core/                      Investigation engine. Pure Python, no UI, no network access.
│   ├── email_parser.py        Raw input -> ParsedEmail (std-lib email + html.parser)
│   ├── domain_utils.py        Domain normalisation, punycode, registrable domain, look-alike detection
│   ├── reference_data.py      Curated brand / free-mail / shortener lists (small, documented)
│   ├── sender_analyzer.py     Display-name impersonation, Reply-To / Return-Path, look-alike sender
│   ├── header_analyzer.py     SPF / DKIM / DMARC as reported in headers, alignment
│   ├── url_analyzer.py        Structural link checks, defanging
│   ├── language_analyzer.py   Explainable phrase rules (+ the Rule mechanism)
│   ├── recruitment_analyzer.py Job-scam mechanisms (fees, task deposits, fake cheques, ...)
│   ├── attachment_analyzer.py Dangerous file types, double extensions, RTL-override
│   ├── risk_engine.py         Ordered rules -> risk level (no invented score)
│   ├── report_generator.py    Report object, recommendations, Markdown export
│   └── investigation.py       The pipeline: runs everything in order
├── integrations/              Optional, isolated from core
│   ├── settings.py            Reads keys from env vars / Streamlit secrets
│   ├── virustotal_client.py   URL lookup only, rate-limited, cached
│   └── claude_client.py       Explains structured findings; prompt-injection defences
├── models/                    Shared dataclasses: ParsedEmail, Finding, Severity, ...
├── ui/                        Streamlit components and the design-system CSS
└── tests/                     pytest suite, runs fully offline
```

Data flow:

```
input ──► email_parser ──► ParsedEmail ──► analyzers ──► Findings ──► risk_engine ──► Assessment
                                                             │                          │
                                                             └────► report_generator ◄──┘
                                                                          │
                                         (optional) VirusTotal / Claude ──┤
                                                                          ▼
                                                                    Streamlit UI
```

`core/` never imports Streamlit. This keeps the engine testable, and lets a future API, Outlook add-in or
Azure Function reuse it unchanged.

## Technology stack

- Python 3.11+.
- Streamlit (UI) and pandas (tables).
- Standard library `email`, `html.parser`, `urllib.parse`, `ipaddress` and `unicodedata` for parsing and analysis.
- Optional: `requests` (VirusTotal) and `anthropic` (Claude API).
- pytest.

## Installation and running locally

```bash
cd phishlens
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

Open the URL Streamlit prints (usually http://localhost:8501).

## Configuration (optional integrations)

Neither key is required. Set them as environment variables, or in `.streamlit/secrets.toml` (which is
git-ignored). See `.env.example`.

| Variable | Enables |
|---|---|
| `VIRUSTOTAL_API_KEY` | Link reputation lookups |
| `ANTHROPIC_API_KEY` | AI explanation of the report |

To use either one, enable it under **Settings** in the app. The AI explanation also asks for confirmation
before each request.

## How the analysis modules work

| Module | What it checks | Labels it uses |
|---|---|---|
| Sender | Brand named in the display name but address on another domain; a different email address hidden in the display name; Reply-To domain differs from From; Return-Path differs; look-alike or non-Latin sender domains; free mailbox used for an organisational message | Confirmed (mismatches are facts), Suspicious (brand / look-alike), Needs verification (free mailbox) |
| Links | Raw IP or integer-encoded IP hosts; `user@host` tricks; unusual ports; shorteners; punycode / mixed-script domains; look-alike brand domains; `?redirect=https://...` parameters; link text showing a different domain than the target; `javascript:` links; forms in emails; plain http | Mostly Confirmed (structure is a fact) |
| Authentication | `spf=`, `dkim=`, `dmarc=` from `Authentication-Results` and `Received-SPF`; alignment with the From domain | Always "as reported in headers", never verified |
| Language | Urgency, account threats, password/code requests, gift cards / crypto, payment changes, chat-app moves, prizes, delivery fees, document lures, secrecy, text addressed to AI tools | Suspicious indicator only. No grammar or spelling rules. Simple negation handling ("we will never ask for your password") |
| Recruitment | Runs only when at least two job terms appear. Fees to start, deposits to unlock tasks, fake cheques / overpayment, equipment from a "vendor", ID or bank details by email, no interview, chat-only interview, remote-access tools, high pay for no-experience work | Suspicious / Needs verification. Legitimate AI-training and annotation work is never flagged for its industry |
| Attachments | Executables, scripts, macro documents, HTML, disk images, double extensions, right-to-left-override names, type mismatch | Confirmed (filename facts) |

### The rule-based risk engine

There is **no numeric score**. A score such as "87/100" would imply calibration that does not exist:
PhishLens has no labelled dataset to set weights against. The engine works in four steps.

1. **Filter.** Keep findings that can influence risk. "No evidence found" and "Not checked" findings are
   dropped at this step.
2. **De-duplicate by root cause.** For example, SPF fail + DMARC fail describe one issue ("the domain was
   not authenticated"), and ten links to the same bad host are one issue. Only the most severe finding per
   root cause counts; the others are shown as "related".
3. **Separate the evidence types.**
   - *Strong evidence:* technical and sender findings, which are computed from the message.
   - *Language evidence:* findings based on wording.
4. **Apply the first matching rule:**

| Rule | Result | Condition |
|---|---|---|
| C1 | Critical | Any critical indicator (job fee, task deposit, fake cheque, executable attachment, RTL-override filename) |
| C2 | Critical | High technical/sender finding **and** high language finding |
| H1 | High | Any high technical/sender finding |
| H2 | High | Two different high language findings, or one backed by a moderate+ technical/sender finding |
| M1 | Moderate | One high language finding alone. **Wording alone is capped at Moderate.** |
| M2 | Moderate | Any moderate finding |
| I1 | Insufficient information | Under 15 words, no sender and no links, with nothing above Low |
| L1 | Low | Everything else. Low never means safe. |

**Confidence** is "Limited" when the sender or authentication headers are missing, and otherwise
"Moderate". It is never "High", because offline checks cannot confirm reputation.

**Calibration status:** the severities and rules are expert-judgement heuristics. They have not been
measured against a labelled corpus. Expect false positives (for example, a real company domain that is
missing from the brand list) and false negatives (well-written scams that use none of the patterns).

## Testing

```bash
cd phishlens
pytest
```

The suite covers the 14 required scenarios:
- a normal business email;
- an upfront-fee job;
- a fake remote AI task job;
- a suspicious URL;
- a Reply-To mismatch;
- an SPF failure;
- missing authentication;
- malformed emails;
- multiple URLs;
- misleading HTML;
- prompt injection;
- a legitimate email with alarming words;
- a Unicode look-alike domain;
- suspicious attachment filenames.

It also checks these properties:
- missing evidence is never invented;
- heuristic findings are never labelled as confirmed;
- the risk engine gives the same result regardless of finding order;
- malformed input does not crash the parser;
- **no network connection or DNS lookup is attempted** (sockets are patched to fail);
- **email content never appears in the logs** (a canary string is checked).

## Privacy

- Emails are processed in memory. The parsed body is discarded after analysis.
- "Recent investigations" keeps only the reports in the browser session's memory. They can be turned off
  or cleared in Settings.
- Logs contain counts, rule IDs and status codes, never email content.
- No external request happens unless you enable an integration:
  - **VirusTotal** receives individual URLs only, at most 4 per email. It uses the lookup endpoint and
    never submits URLs for scanning, because submitted URLs become visible to other VirusTotal users.
  - **Claude** receives the structured findings and evidence quotes of up to 200 characters each. It never
    receives the email body or the raw headers.

## Security design and limitations

| Threat | Mitigation |
|---|---|
| XSS from email content | HTML is converted to text and never rendered. Untrusted strings are shown with `st.code` (literal text). `unsafe_allow_html` is used only for static CSS and for badges built from internal enum values. |
| Clicking dangerous links | Every displayed URL is defanged and shown as literal text. A manual browser check of a rendered report found no `<a href>` pointing to any extracted domain (this check is not yet automated). |
| SSRF / visiting attacker URLs | The server never fetches user-supplied URLs. If URL scanning is added later, it must block private and link-local IP addresses, re-check the IP after every redirect (DNS rebinding), cap redirects, and run in an isolated egress-restricted worker. |
| Malicious attachments | Only the name, declared type and size are read. Contents are never opened. |
| Oversized or binary input | 5 MB upload limit, 300k-character paste limit, a NUL-byte check, a MIME-part cap and a URL cap. |
| Hidden direction characters | U+202E and similar characters are kept in filenames for detection, shown as `[U+202E]` in the UI, and stripped from other headers with a warning. |
| Prompt injection | The email body is not sent to the model. Quotes are defanged and angle brackets neutralised. The system prompt treats the tagged data as data. No tools are given to the model, and its output is escaped. |
| Secrets | Read from environment variables or Streamlit secrets, never logged or displayed. `.env` and `secrets.toml` are git-ignored. |

Known limitations:
- The registrable-domain calculation uses a small suffix list rather than the full Public Suffix List.
- The brand list is small, so it cannot confirm unknown companies.
- Pasted `Authentication-Results` headers cannot be trusted.
- Detection is English-only.
- The VirusTotal rate limiter is per process.

## Azure-ready design (not implemented yet)

| Future need | Where it plugs in |
|---|---|
| Microsoft Entra ID sign-in | Streamlit's built-in OIDC (`st.login`) in `app.py`; `core/` is unaffected |
| Azure App Service hosting | Run `streamlit run app.py`. Configuration already comes from environment variables. |
| Azure Key Vault | App Service Key Vault references fill the same `VIRUSTOTAL_API_KEY` / `ANTHROPIC_API_KEY` variables |
| Optional report storage (Azure Storage) | A new module that saves the `InvestigationReport` (not the email). It needs explicit user consent and a retention policy. |
| Monitoring | Existing content-free `logging` output can go to Application Insights |
| Outlook add-in / Microsoft Graph | Fetch the MIME message through Graph, then call `parse_eml_bytes()` + `investigate()` |

No Azure dependency or paid resource is created by this project.

## Roadmap

1. Use the Public Suffix List for domain parsing, and add a larger, versioned brand dataset.
2. Add Google Safe Browsing as a second reputation source.
3. Build a labelled evaluation set to measure false positive and false negative rates, then tune severities.
4. Add multilingual rule packs.
5. Add Entra ID sign-in and optional, consented report storage.
6. Build an Outlook add-in through Microsoft Graph.
