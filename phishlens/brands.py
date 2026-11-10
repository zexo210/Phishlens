"""Brand impersonation checks (international + Croatian brands that are commonly phished)."""

from __future__ import annotations

import re
from typing import Optional

from .textutil import levenshtein, registrable

# brand -> (official domains, lowercase name tokens)
BRANDS = {
    "PayPal": (["paypal.com"], ["paypal"]),
    "Microsoft": (["microsoft.com", "office.com", "outlook.com", "live.com", "microsoftonline.com", "office365.com"], ["microsoft", "office365"]),
    "Google": (["google.com", "gmail.com", "googlemail.com"], ["google"]),
    "Apple": (["apple.com", "icloud.com"], ["apple", "icloud"]),
    "Amazon": (["amazon.com", "amazon.de", "amazon.co.uk"], ["amazon"]),
    "DHL": (["dhl.com", "dhl.de"], ["dhl"]),
    "FedEx": (["fedex.com"], ["fedex"]),
    "UPS": (["ups.com"], ["ups"]),
    "Netflix": (["netflix.com"], ["netflix"]),
    "Facebook/Meta": (["facebook.com", "meta.com", "fb.com"], ["facebook"]),
    "LinkedIn": (["linkedin.com"], ["linkedin"]),
    "DocuSign": (["docusign.com", "docusign.net"], ["docusign"]),
    "Zagrebacka banka": (["zaba.hr", "zagrebacka-banka.hr"], ["zaba", "zagrebackabanka"]),
    "PBZ": (["pbz.hr"], ["pbz"]),
    "Erste banka": (["erstebank.hr"], ["erstebank"]),
    "HPB": (["hpb.hr"], ["hpb"]),
    "OTP banka": (["otpbanka.hr"], ["otpbanka"]),
    "Raiffeisenbank": (["rba.hr", "raiffeisenbank.hr"], ["raiffeisen"]),
    "Addiko": (["addiko.hr"], ["addiko"]),
    "FINA": (["fina.hr"], ["fina"]),
    "HZZO": (["hzzo.hr"], ["hzzo"]),
    "Porezna uprava": (["porezna-uprava.gov.hr", "porezna-uprava.hr"], ["porezna"]),
    "Hrvatska posta": (["posta.hr"], ["posta"]),
    "Hrvatski Telekom": (["hrvatskitelekom.hr", "t.ht.hr", "ht.hr"], ["hrvatskitelekom"]),
    "A1 Hrvatska": (["a1.hr"], ["a1hrvatska"]),
    "Telemach": (["telemach.hr"], ["telemach"]),
    "CARNET": (["carnet.hr"], ["carnet"]),
    "e-Gradjani / gov.hr": (["gov.hr"], ["egradjani"]),
}

FREEMAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com",
    "icloud.com", "proton.me", "protonmail.com", "aol.com", "gmx.com", "gmx.net", "mail.com",
    "zoho.com", "yandex.com", "net.hr", "vip.hr", "inbox.com",
}

_DIGITS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})


def _deconfuse(label: str) -> str:
    return label.translate(_DIGITS).replace("rn", "m").replace("vv", "w")


def is_official(host: str) -> bool:
    host = host.lower().strip(".")
    for domains, _ in BRANDS.values():
        for d in domains:
            if host == d or host.endswith("." + d):
                return True
    return False


def check_brand_domain(host: str) -> Optional[tuple]:
    """Return (brand, reason) if `host` imitates a brand without being an official domain."""
    host = host.lower().strip(".")
    if not host or "." not in host or is_official(host):
        return None
    for brand, (domains, tokens) in BRANDS.items():
        for d in domains:
            if re.search(r"(?:^|\.)" + re.escape(d) + r"(?:\.|$)", host):
                return brand, f"official domain '{d}' is used as a sub-domain of a different domain"
    labels = host.split(".")[:-1]  # drop the TLD
    # make sure the registrable label is included even for two-level suffixes
    reg_label = registrable(host).split(".")[0]
    if reg_label not in labels:
        labels.append(reg_label)
    for label in labels:
        for part in re.split(r"[-_]", label):
            if not part:
                continue
            for brand, (_, tokens) in BRANDS.items():
                for token in tokens:
                    if part == token:
                        return brand, f"brand name '{token}' used in a non-official domain"
                    if len(token) >= 6 and token in part:
                        return brand, f"brand name '{token}' embedded in '{part}'"
                    if part != token and _deconfuse(part) == token:
                        return brand, f"look-alike spelling of '{token}' ('{part}')"
                    if len(token) >= 6 and part[0] == token[0] and levenshtein(part, token) == 1:
                        return brand, f"possible typosquat of '{token}' ('{part}')"
    return None
