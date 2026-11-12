"""
Attachment metadata analysis.

PhishLens never opens, extracts or runs attachments. It only looks at
the filename, the declared content type and the size, and flags:

* executable / script file types (.exe, .js, .vbs, .scr, ...)
* macro-enabled Office files (.docm, .xlsm)
* HTML attachments (often local fake login pages)
* disk images and shortcut files (.iso, .img, .lnk) used to bypass filters
* double extensions ("invoice.pdf.exe")
* the right-to-left override character, which can make "exe.pdf" display
  backwards so a program looks like a document
* a declared type that doesn't match the extension
"""

from __future__ import annotations

from pathlib import PurePath

from models.email_data import ParsedEmail
from models.findings import AnalyzerResult, Category, EvidenceType, Finding, Limitation, Severity

SECTION = "attachments"
EXECUTABLE = {".exe", ".scr", ".com", ".bat", ".cmd", ".pif", ".msi", ".js", ".jse", ".vbs", ".vbe",
              ".wsf", ".ps1", ".hta", ".jar", ".cpl", ".reg", ".dll", ".apk", ".app", ".sh"}
CONTAINERS = {".iso", ".img", ".vhd", ".vhdx", ".lnk", ".one"}
MACRO = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam"}
HTML = {".html", ".htm", ".shtml", ".svg"}
ARCHIVES = {".zip", ".rar", ".7z", ".gz", ".tar", ".cab"}
DOC_LIKE = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".csv"}
_RTLO = "‮"


def analyze_attachments(parsed: ParsedEmail) -> AnalyzerResult:
    out = AnalyzerResult()
    if parsed.source != "eml":
        out.limitations.append(Limitation(
            "Attachments", "Attachments can only be listed when the original .eml file is uploaded."))
    for att in parsed.attachments:
        name = att.filename
        suffixes = [s.lower() for s in PurePath(name.replace(_RTLO, "")).suffixes]
        ext = suffixes[-1] if suffixes else ""
        ev = (f"Filename: {name.replace(_RTLO, '[RTL-override]')}", f"Declared type: {att.content_type}",
              f"Size: {att.size_bytes:,} bytes")

        def add(rule: str, title: str, severity: Severity, explanation: str,
                evidence_type: EvidenceType = EvidenceType.CONFIRMED_TECHNICAL) -> None:
            out.findings.append(Finding(
                rule_id=rule, title=title, category=Category.TECHNICAL, evidence_type=evidence_type,
                severity=severity, explanation=explanation, section=SECTION, evidence=ev,
                root_cause=f"attachment:{name}",
            ))

        if _RTLO in name:
            add("att.rtlo", "Attachment name uses a hidden character to disguise its type", Severity.CRITICAL,
                "The filename contains an invisible 'right-to-left override' character, which makes a "
                "program display as if it were a document. This has no legitimate use in attachments.")
        elif ext in EXECUTABLE:
            add("att.executable", f"Attachment is a program or script ({ext})", Severity.CRITICAL,
                "Opening this file would run code on your computer. Legitimate businesses almost never "
                "email programs. Do not open it.")
        elif len(suffixes) >= 2 and suffixes[-2] in DOC_LIKE and ext in EXECUTABLE | CONTAINERS | HTML | ARCHIVES:
            add("att.double_extension", "Attachment has a misleading double extension", Severity.HIGH,
                "The name looks like a document but the real file type is the last extension. This is "
                "used to trick people into opening programs or archives.")
        elif ext in CONTAINERS:
            add("att.container", f"Attachment is a disk image or shortcut ({ext})", Severity.HIGH,
                "These file types are used to smuggle malware past email filters.")
        elif ext in MACRO:
            add("att.macro", f"Macro-enabled Office file ({ext})", Severity.HIGH,
                "Macro-enabled documents can run code when opened and are a common malware method. "
                "Do not enable macros on documents from unverified senders.")
        elif ext in HTML:
            add("att.html", "HTML file attached", Severity.HIGH,
                "HTML attachments often contain fake login pages that open locally in your browser, "
                "bypassing web filters.", EvidenceType.SUSPICIOUS_INDICATOR)
        elif ext in ARCHIVES:
            add("att.archive", f"Compressed archive attached ({ext})", Severity.LOW,
                "Archives can hide other files from email scanners. Only open if you expected it.",
                EvidenceType.NEEDS_VERIFICATION)

        if ext == ".pdf" and att.content_type not in ("application/pdf", "application/octet-stream"):
            add("att.type_mismatch", "Attachment type does not match its name", Severity.MODERATE,
                "The file is named as a PDF but declared as a different type.",
                EvidenceType.SUSPICIOUS_INDICATOR)

    if parsed.attachments:
        out.limitations.append(Limitation(
            "Attachments",
            "Attachment contents were not opened or scanned for malware; only names and types were checked.",
        ))
    return out
