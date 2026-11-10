"""Link analysis. Static only: URLs are never fetched."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .brands import check_brand_domain
from .findings import Finding
from .parser import Link
from .textutil import defang, registrable

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "cutt.ly",
    "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id",
}
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "gq", "tk", "ml", "cf", "ga", "icu", "cyou", "rest",
    "monster", "sbs", "cfd",
}
SOCIAL = {"twitter.com", "x.com", "facebook.com", "instagram.com", "linkedin.com", "youtube.com",
          "discord.gg", "discord.com", "tiktok.com", "t.me", "github.com"}
TEXT_DOMAIN = re.compile(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]\S*)?", re.I)


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return bool(re.fullmatch(r"\d{8,10}|0x[0-9a-f]+", host))


def analyze_links(links: list, sender_domain: str = "") -> tuple:
    """Return (findings, iocs). Each rule yields at most one finding that lists the URLs it hit.

    `sender_domain` lets us treat long tracking links on the sender's own domain as normal, and keep
    well-known social networks out of the IOC list.
    """
    own = registrable(sender_domain) if sender_domain else ""
    hits: dict = {}
    domains: list = []
    urls: list = []

    def hit(rule: str, link: Link) -> None:
        hits.setdefault(rule, [])
        if link.href not in hits[rule]:
            hits[rule].append(link.href)

    for link in links:
        try:
            parts = urlsplit(link.href)
            host = (parts.hostname or "").lower()
        except ValueError:
            continue
        if not host:
            continue
        reg = registrable(host)
        if reg not in SOCIAL:
            urls.append(link.href)
            if host not in domains:
                domains.append(host)

        if _is_ip_host(host):
            hit("U01", link)
        if "xn--" in host:
            hit("U02", link)
        if "@" in parts.netloc:
            hit("U03", link)
        if host in SHORTENERS:
            hit("U04", link)
        text_match = TEXT_DOMAIN.search(link.text) if link.text else None
        if text_match and registrable(text_match.group(1).removeprefix("www.")) != registrable(host):
            hit("U05", link)
        if check_brand_domain(host):
            hit("U06", link)
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            hit("U07", link)
        if parts.scheme == "http":
            hit("U08", link)
        if host.count(".") >= 4:
            hit("U09", link)
        if len(link.href) > 200 and not (own and reg == own):
            hit("U10", link)

    rules = {
        "U01": ("Link points to an IP address", "high", 20, ["T1566.002"]),
        "U02": ("Link uses punycode (possible homograph domain)", "medium", 15, ["T1566.002"]),
        "U03": ("Link contains credentials/@ before the host", "high", 20, ["T1566.002"]),
        "U04": ("URL shortener hides the real destination", "low", 8, ["T1566.002"]),
        "U05": ("Link text shows a different domain than the real target", "high", 25, ["T1566.002", "T1598.003"]),
        "U06": ("Link domain imitates a known brand", "high", 22, ["T1566.002", "T1598.003"]),
        "U07": ("Link uses a TLD frequently abused for phishing", "low", 6, []),
        "U08": ("Link is not encrypted (http)", "low", 4, []),
        "U09": ("Link has an unusually deep sub-domain chain", "low", 5, []),
        "U10": ("Very long URL", "low", 3, []),
    }
    findings = []
    for rule, (title, sev, weight, attack) in rules.items():
        if rule in hits:
            shown = ", ".join(defang(u) for u in hits[rule][:4])
            more = f" (+{len(hits[rule]) - 4} more)" if len(hits[rule]) > 4 else ""
            findings.append(Finding(rule, "url", title, sev, weight, shown + more, attack))
    aligned = bool(links) and all(
        registrable((urlsplit(l.href).hostname or "").lower()) in SOCIAL
        or (own and registrable((urlsplit(l.href).hostname or "").lower()) == own)
        for l in links if urlsplit(l.href).hostname)
    return findings, {"domains": domains, "urls": urls, "aligned": aligned}
