from __future__ import annotations

from dataclasses import dataclass, field

# MITRE ATT&CK techniques referenced by the rules (names as in ATT&CK Enterprise).
ATTACK_NAMES = {
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1598": "Phishing for Information",
    "T1598.003": "Phishing for Information: Spearphishing Link",
    "T1656": "Impersonation",
    "T1036.007": "Masquerading: Double File Extension",
    "T1204.001": "User Execution: Malicious Link",
    "T1204.002": "User Execution: Malicious File",
}


@dataclass
class Finding:
    """One piece of evidence. `weight` is how many points it adds to the risk score."""

    id: str
    category: str  # header | url | content | attachment
    title: str
    severity: str  # info | low | medium | high
    weight: int
    detail: str = ""
    attack: list = field(default_factory=list)
