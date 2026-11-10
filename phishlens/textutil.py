from __future__ import annotations

import re
import unicodedata

# Small stand-in for the Public Suffix List. Good enough for triage; see README limitations.
TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.hr", "co.rs", "com.au", "co.jp", "com.br",
    "co.nz", "co.za", "com.tr", "com.mx",
}


def normalize(text: str) -> str:
    """Lowercase and strip diacritics, so 'Šifra' matches 'sifra' and 'Račun' matches 'racun'."""
    text = text.replace("’", "'").replace("đ", "d").replace("Đ", "D")
    text = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return text.lower()


def registrable(host: str) -> str:
    host = host.lower().strip(".")
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def defang(url: str) -> str:
    """hxxps://example[.]com/path so a report can never be clicked by accident."""
    s = re.sub(r"^http", "hxxp", url, flags=re.I)
    m = re.match(r"^(hxxps?://)([^/?#]*)(.*)$", s, flags=re.I | re.S)
    if m:
        return m.group(1) + m.group(2).replace(".", "[.]") + m.group(3)
    return s.replace(".", "[.]")


def defang_domain(domain: str) -> str:
    return domain.replace(".", "[.]")
