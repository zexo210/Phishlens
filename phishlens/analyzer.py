"""Combine all rule modules into one explainable verdict."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .attachments import analyze_attachments
from .content import analyze_content
from .findings import ATTACK_NAMES, Finding
from .headers import analyze_headers, public_ips
from .parser import ParsedEmail, parse_file
from .textutil import defang, defang_domain
from .urls import analyze_links

BANDS = ((45, "likely phishing"), (20, "suspicious"), (0, "low risk"))


@dataclass
class AnalysisResult:
    source: str
    subject: str
    sender: str
    score: int
    verdict: str
    findings: list
    auth: dict
    tactics: dict
    iocs: dict
    attack: list
    actions: list
    ai: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


def verdict_for(score: int) -> str:
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "low risk"


def _actions(verdict: str, findings: list) -> list:
    ids = {f.id for f in findings}
    acts: list = []
    if verdict == "likely phishing":
        acts += ["Do not click links, open attachments or reply.",
                 "Report the message to your security team / use the mail client's phishing-report button.",
                 "Block the sender and the listed domains at the mail gateway and proxy."]
    elif verdict == "suspicious":
        acts += ["Treat with caution: verify the sender through a separate channel (phone, known address).",
                 "Do not enter credentials or payment details via links in this message."]
    else:
        acts += ["No strong indicators found. Normal caution still applies."]
    if "C-bec" in ids or "H020" in ids:
        acts.append("Confirm any payment or bank-detail change by calling a known number before acting.")
    if "C-sextortion" in ids:
        acts.append("Do not pay. Change reused passwords and enable MFA; this is usually mass-mailed.")
    if any(i.startswith("A") for i in ids):
        acts.append("Never open the attachment on a work machine; submit the hash to a sandbox/reputation service.")
    if any(i in ids for i in ("U05", "U06", "H040")):
        acts.append("If credentials were entered, reset the password and review recent sign-ins.")
    return acts


def analyze(p: ParsedEmail, source: str = "") -> AnalysisResult:
    findings: list = []
    hf, auth = analyze_headers(p)
    uf, url_iocs = analyze_links(p.links)
    cf, tactics = analyze_content(p.subject, p.body)
    af, hashes = analyze_attachments(p.attachments)
    findings = hf + uf + cf + af

    if "password_input" in p.html_flags or ("form" in p.html_flags and "script" in p.html_flags):
        findings.append(Finding("C-form", "content", "Message body contains a form or password field", "high", 15,
                                "Legitimate senders almost never embed login forms in e-mail.", ["T1598"]))

    score = max(0, min(100, sum(f.weight for f in findings)))
    verdict = verdict_for(score)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: (order.get(f.severity, 9), -f.weight))

    attack = sorted({t for f in findings for t in f.attack})
    iocs = {
        "sender": p.from_addr,
        "reply_to": p.reply_to,
        "sender_domain": p.from_domain,
        "domains": url_iocs["domains"],
        "urls": url_iocs["urls"],
        "ips": public_ips(p),
        "attachments": hashes,
    }
    return AnalysisResult(
        source=source, subject=p.subject, sender=f"{p.from_name} <{p.from_addr}>".strip(),
        score=score, verdict=verdict, findings=findings, auth=auth, tactics=tactics, iocs=iocs,
        attack=[{"id": t, "name": ATTACK_NAMES.get(t, t)} for t in attack], actions=_actions(verdict, findings),
    )


def analyze_file(path) -> AnalysisResult:
    return analyze(parse_file(path), source=str(path))


def defanged_iocs(iocs: dict) -> dict:
    """Copy of the IOC dict that is safe to paste into tickets or chat."""
    out = dict(iocs)
    out["domains"] = [defang_domain(d) for d in iocs["domains"]]
    out["urls"] = [defang(u) for u in iocs["urls"]]
    out["ips"] = [i.replace(".", "[.]") for i in iocs["ips"]]
    out["sender"] = iocs["sender"].replace("@", "[@]").replace(".", "[.]")
    out["reply_to"] = iocs["reply_to"].replace("@", "[@]").replace(".", "[.]")
    out["sender_domain"] = defang_domain(iocs["sender_domain"])
    return out
"""Combine all rule modules into one explainable verdict."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .attachments import analyze_attachments
from .content import analyze_content
from .findings import ATTACK_NAMES, Finding
from .headers import analyze_headers, public_ips
from .parser import ParsedEmail, parse_file
from .textutil import defang, defang_domain
from .urls import analyze_links

BANDS = ((45, "likely phishing"), (20, "suspicious"), (0, "low risk"))


@dataclass
class AnalysisResult:
    source: str
    subject: str
    sender: str
    score: int
    verdict: str
    findings: list
    auth: dict
    tactics: dict
    iocs: dict
    attack: list
    actions: list
    ai: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


def verdict_for(score: int) -> str:
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "low risk"


def _actions(verdict: str, findings: list) -> list:
    ids = {f.id for f in findings}
    acts: list = []
    if verdict == "likely phishing":
        acts += ["Do not click links, open attachments or reply.",
                 "Report the message to your security team / use the mail client's phishing-report button.",
                 "Block the sender and the listed domains at the mail gateway and proxy."]
    elif verdict == "suspicious":
        acts += ["Treat with caution: verify the sender through a separate channel (phone, known address).",
                 "Do not enter credentials or payment details via links in this message."]
    else:
        acts += ["No strong indicators found. Normal caution still applies."]
    if "C-bec" in ids or "H020" in ids:
        acts.append("Confirm any payment or bank-detail change by calling a known number before acting.")
    if "C-sextortion" in ids:
        acts.append("Do not pay. Change reused passwords and enable MFA; this is usually mass-mailed.")
    if any(i.startswith("A") for i in ids):
        acts.append("Never open the attachment on a work machine; submit the hash to a sandbox/reputation service.")
    if any(i in ids for i in ("U05", "U06", "H040")):
        acts.append("If credentials were entered, reset the password and review recent sign-ins.")
    return acts


def analyze(p: ParsedEmail, source: str = "") -> AnalysisResult:
    findings: list = []
    hf, auth = analyze_headers(p)
    uf, url_iocs = analyze_links(p.links, p.from_domain)
    cf, tactics = analyze_content(p.subject, p.body)
    af, hashes = analyze_attachments(p.attachments)
    findings = hf + uf + cf + af

    if "password_input" in p.html_flags or ("form" in p.html_flags and "script" in p.html_flags):
        findings.append(Finding("C-form", "content", "Message body contains a form or password field", "high", 15,
                                "Legitimate senders almost never embed login forms in e-mail.", ["T1598"]))

    if url_iocs["aligned"] and any(f.id == "H190" for f in findings) and not any(f.category == "url" for f in findings):
        findings.append(Finding("H191", "header", "All links stay on the sender's own domain (or well-known social networks)",
                                "info", -4, "Consistent with a legitimate bulk sender; not proof of legitimacy."))

    score = max(0, min(100, sum(f.weight for f in findings)))
    verdict = verdict_for(score)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: (order.get(f.severity, 9), -f.weight))

    attack = sorted({t for f in findings for t in f.attack})
    iocs = {
        "sender": p.from_addr,
        "reply_to": p.reply_to,
        "sender_domain": p.from_domain,
        "domains": url_iocs["domains"],
        "urls": url_iocs["urls"],
        "ips": public_ips(p),
        "attachments": hashes,
    }
    return AnalysisResult(
        source=source, subject=p.subject, sender=f"{p.from_name} <{p.from_addr}>".strip(),
        score=score, verdict=verdict, findings=findings, auth=auth, tactics=tactics, iocs=iocs,
        attack=[{"id": t, "name": ATTACK_NAMES.get(t, t)} for t in attack], actions=_actions(verdict, findings),
    )


def analyze_file(path) -> AnalysisResult:
    return analyze(parse_file(path), source=str(path))


def defanged_iocs(iocs: dict) -> dict:
    """Copy of the IOC dict that is safe to paste into tickets or chat."""
    out = dict(iocs)
    out["domains"] = [defang_domain(d) for d in iocs["domains"]]
    out["urls"] = [defang(u) for u in iocs["urls"]]
    out["ips"] = [i.replace(".", "[.]") for i in iocs["ips"]]
    out["sender"] = iocs["sender"].replace("@", "[@]").replace(".", "[.]")
    out["reply_to"] = iocs["reply_to"].replace("@", "[@]").replace(".", "[.]")
    out["sender_domain"] = defang_domain(iocs["sender_domain"])
    return out
