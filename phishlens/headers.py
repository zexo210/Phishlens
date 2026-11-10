"""Header and sender-identity checks."""

from __future__ import annotations

import ipaddress
import re

from .brands import BRANDS, FREEMAIL, check_brand_domain
from .findings import Finding
from .parser import ParsedEmail
from .textutil import normalize, registrable

AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)
RECEIVED_SPF_RE = re.compile(r"^\s*(pass|fail|softfail|neutral|none|temperror|permerror)", re.I)
RANK = {"pass": 0, "neutral": 1, "none": 2, "temperror": 3, "permerror": 3, "softfail": 4, "fail": 5}
AUTH_WEIGHT = {
    "spf": {"fail": 10, "softfail": 6, "none": 4, "temperror": 3, "permerror": 5},
    "dkim": {"fail": 10, "none": 4, "temperror": 3, "permerror": 5},
    "dmarc": {"fail": 15, "none": 4, "temperror": 3, "permerror": 5},
}
EXEC_WORDS = [
    "direktor", "director", "ceo", "cfo", "uprava", "predsjednik", "racunovodstvo", "financije",
    "finance", "human resources", "it support", "helpdesk", "help desk", "administrator",
    "security", "sigurnost", "support", "banka", "bank", "service",
]
DOMAINISH = re.compile(
    r"[\w.+-]+@[\w-]+\.[\w.-]+|(?:https?://)?(?:www\.)?[a-z0-9-]+\.(?:com|net|org|hr|info|biz|eu|io|co|de|uk)\b"
)


def _domain(addr: str) -> str:
    return addr.rpartition("@")[2].lower()


def parse_auth(p: ParsedEmail) -> dict:
    """Return the worst SPF/DKIM/DMARC result seen (multiple signatures are common)."""
    auth: dict = {}
    for line in p.auth_results:
        for m in AUTH_RE.finditer(line):
            k, v = m.group(1).lower(), m.group(2).lower()
            if k not in auth or RANK.get(v, 2) > RANK.get(auth[k], 2):
                auth[k] = v
    if "spf" not in auth:
        for line in p.headers.get("received-spf", []):
            m = RECEIVED_SPF_RE.match(line)
            if m:
                auth["spf"] = m.group(1).lower()
    return auth


def public_ips(p: ParsedEmail) -> list:
    ips: list = []
    for line in p.received:
        for m in re.finditer(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])", line):
            try:
                ip = ipaddress.ip_address(m.group(1))
            except ValueError:
                continue
            if ip.is_global and m.group(1) not in ips:
                ips.append(m.group(1))
    return ips


def analyze_headers(p: ParsedEmail) -> tuple:
    findings: list = []
    auth = parse_auth(p)
    from_dom = p.from_domain

    if not p.auth_results and "spf" not in auth:
        findings.append(Finding("H001", "header", "No authentication results in headers", "low", 3,
                                "SPF/DKIM/DMARC could not be evaluated from this message."))
    else:
        for mech in ("spf", "dkim", "dmarc"):
            result = auth.get(mech)
            weight = AUTH_WEIGHT[mech].get(result or "", 0)
            if weight:
                sev = "high" if result == "fail" else "medium" if result in ("softfail", "permerror") else "low"
                findings.append(Finding(f"H10{'sdm'[('spf', 'dkim', 'dmarc').index(mech)]}", "header",
                                        f"{mech.upper()} = {result}", sev, weight,
                                        f"{mech.upper()} did not pass for this message."))
        if all(auth.get(m) == "pass" for m in ("spf", "dkim", "dmarc")):
            findings.append(Finding("H190", "header", "SPF, DKIM and DMARC all pass", "info", -4,
                                    "Authentication passing does not prove the mail is legitimate "
                                    "(attackers also use properly configured look-alike domains)."))

    if p.reply_to and from_dom and registrable(_domain(p.reply_to)) != registrable(from_dom):
        findings.append(Finding("H020", "header", "Reply-To domain differs from sender domain", "medium", 12,
                                f"From: {p.from_addr}, Reply-To: {p.reply_to}. Replies go to a different "
                                "organisation (typical for business e-mail compromise).", ["T1656"]))
    if p.return_path and from_dom and registrable(_domain(p.return_path)) != registrable(from_dom):
        findings.append(Finding("H021", "header", "Return-Path domain differs from sender domain", "low", 4,
                                f"Return-Path: {p.return_path}. Can be legitimate for mailing services."))

    name_norm = normalize(p.from_name)
    m = DOMAINISH.search(name_norm)
    if m:
        shown = m.group(0)
        shown_dom = shown.rpartition("@")[2] if "@" in shown else re.sub(r"^https?://|^www\.", "", shown)
        if registrable(shown_dom) != registrable(from_dom):
            findings.append(Finding("H030", "header", "Display name contains a different address or domain", "high", 15,
                                    f"Display name '{p.from_name}' vs actual sender {p.from_addr}.", ["T1656"]))

    if from_dom in FREEMAIL:
        tokens = [t for _, (_, ts) in BRANDS.items() for t in ts]
        hit = next((w for w in EXEC_WORDS + tokens if re.search(rf"(?<![a-z0-9]){re.escape(w)}(?![a-z0-9])", name_norm)), None)
        if hit:
            findings.append(Finding("H031", "header", "Corporate/executive display name on a free mail service", "medium", 12,
                                    f"Display name '{p.from_name}' (matches '{hit}') sent from {from_dom}.", ["T1656"]))

    brand = check_brand_domain(from_dom) if from_dom else None
    if brand:
        findings.append(Finding("H040", "header", f"Sender domain imitates {brand[0]}", "high", 25,
                                f"{from_dom}: {brand[1]}.", ["T1656"]))

    if not p.date or not p.message_id:
        findings.append(Finding("H050", "header", "Missing Date or Message-ID header", "low", 3,
                                "Mail generated by scripts or tools often omits these."))

    subj = normalize(p.subject).strip()
    if re.match(r"^(re|fw|fwd|odg|pr)\s*:", subj) and "in-reply-to" not in p.headers and "references" not in p.headers:
        findings.append(Finding("H060", "header", "Fake reply/forward subject", "low", 5,
                                "Subject starts with RE:/FW: but the message is not part of a thread "
                                "(no In-Reply-To or References). Used to add false context."))
    return findings, auth
