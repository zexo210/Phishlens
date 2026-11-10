"""Attachment checks based on names, magic bytes and (for HTML/SVG) a small content sample."""

from __future__ import annotations

import re

from .findings import Finding
from .parser import Attachment

EXECUTABLE = {"exe", "scr", "com", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "hta", "jar",
              "msi", "lnk", "dll", "cpl", "reg", "pif"}
MACRO_OFFICE = {"docm", "xlsm", "pptm", "dotm", "xlam", "xlsb"}
ARCHIVES = {"zip", "rar", "7z", "cab", "gz", "tar"}
DISK_IMAGES = {"iso", "img", "vhd", "vhdx"}
HTMLISH = {"html", "htm", "svg", "xhtml", "shtml"}
DOUBLE_EXT = re.compile(r"\.(?:pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|zip)\.(?:exe|scr|js|vbs|bat|cmd|com|html?|lnk|jar|hta|ps1)$", re.I)
SMUGGLING = re.compile(r"type\s*=\s*[\"']?password|atob\(|fromcharcode|unescape\(|eval\(|<form", re.I)


def _ext(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def analyze_attachments(attachments: list) -> tuple:
    findings: list = []
    hashes: list = []
    for a in attachments:
        hashes.append({"filename": a.filename, "sha256": a.sha256, "md5": a.md5, "size": a.size})
        ext = _ext(a.filename)
        tag = f"{a.filename} (sha256 {a.sha256[:12]}...)"

        if DOUBLE_EXT.search(a.filename):
            findings.append(Finding("A06", "attachment", "Double file extension", "high", 30, tag,
                                    ["T1036.007", "T1566.001", "T1204.002"]))
        if ext in EXECUTABLE:
            findings.append(Finding("A01", "attachment", "Executable or script attachment", "high", 30, tag,
                                    ["T1566.001", "T1204.002"]))
        if a.head[:2] == b"MZ" and ext not in {"exe", "dll", "scr", "com", "cpl", "msi"}:
            findings.append(Finding("A07", "attachment", "Windows executable disguised as another file type", "high", 30,
                                    f"{tag}: starts with MZ header", ["T1036.007", "T1204.002"]))
        elif a.head[:4] == b"\x7fELF" and ext not in {"", "elf", "so"}:
            findings.append(Finding("A07", "attachment", "Linux executable disguised as another file type", "high", 30,
                                    f"{tag}: starts with ELF header", ["T1204.002"]))
        if ext in MACRO_OFFICE:
            findings.append(Finding("A02", "attachment", "Macro-enabled Office document", "medium", 20, tag,
                                    ["T1566.001", "T1204.002"]))
        if ext in DISK_IMAGES:
            findings.append(Finding("A03", "attachment", "Disk image attachment (bypasses mark-of-the-web)", "medium", 15, tag,
                                    ["T1566.001"]))
        elif ext in ARCHIVES:
            findings.append(Finding("A04", "attachment", "Archive attachment (contents not inspected)", "low", 8, tag,
                                    ["T1566.001"]))
        if ext == "one":
            findings.append(Finding("A09", "attachment", "OneNote attachment", "medium", 15, tag, ["T1566.001"]))
        if ext in HTMLISH:
            findings.append(Finding("A05", "attachment", "HTML/SVG attachment (credential harvesting or smuggling)", "medium", 15, tag,
                                    ["T1566.001", "T1598"]))
            if SMUGGLING.search(a.text_sample or ""):
                findings.append(Finding("A08", "attachment", "HTML attachment contains a password field, form or obfuscated script", "high", 20,
                                        tag, ["T1598", "T1204.002"]))
    return findings, hashes
