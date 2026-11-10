"""Social-engineering cue detection in subject and body (Croatian + English).

Matching is diacritic-insensitive. A phrase ending in '*' is a prefix match ('lozink*' -> lozinka, lozinku).
"""

from __future__ import annotations

import re

from .findings import Finding
from .textutil import normalize

# category -> (title, weight for 1 hit, weight for 2+ hits, severity, ATT&CK, phrases)
CATEGORIES = {
    "urgency": ("Urgency / time pressure", 6, 10, "medium", [], [
        "hitno", "hitna", "odmah", "u roku od 24", "u roku od 48", "24 sata", "48 sati",
        "posljednja opomena", "zadnja opomena", "konacna opomena", "blokiran*", "suspendiran*",
        "privremeno ogranicen*", "istjece", "immediately", "urgent", "within 24 hours",
        "within 48 hours", "final notice", "last warning", "will be suspended", "has been suspended",
        "expires today", "act now", "verify now", "as soon as possible", "asap"]),
    "authority": ("Appeal to authority", 4, 6, "low", [], [
        "uprava", "direktor*", "predsjednik", "policij*", "mup", "porezna uprava", "hzzo", "sudski",
        "ovrh*", "ovrsn*", "europol", "interpol*", "odvjetnik*", "ceo", "cfo", "chief executive",
        "bank security", "it support", "helpdesk", "help desk", "security team", "tim za sigurnost",
        "administrator*", "irs", "fbi", "court order"]),
    "fear": ("Fear / threat / extortion", 12, 18, "high", [], [
        "kazn*", "kazneni", "krivicn*", "tuzb*", "pokrenut postupak", "zatvor", "razotkri*",
        "objavit cu", "podijelit cu", "snimio sam", "snimila sam", "webcam", "web kamer*",
        "preko kamere", "intimn*", "vase kontakte", "tvoje kontakte", "legal action", "arrest",
        "expose you", "recorded you", "your webcam", "through your camera", "compromising",
        "share with your contacts", "send to your contacts", "hakirao", "hakirali", "hacked"]),
    "secrecy": ("Secrecy / isolation", 8, 8, "medium", [], [
        "ne govori nikome", "ne govorite nikome", "ne govori nikom", "strogo povjerljivo",
        "povjerljivo", "samo izmedu nas", "ne obavjestavaj", "ne obavjestavajte", "do not tell",
        "keep this confidential", "do not share this", "between us", "do not discuss",
        "don't discuss", "don't tell anyone"]),
    "reward": ("Reward / greed lure", 4, 4, "low", [], [
        "osvojili ste", "cestitamo", "nagrad*", "dobitak", "dobitnik*", "besplatn*", "poklon*",
        "povrat novca", "povrat sredstava", "refund", "you have won", "winner", "gift card", "prize",
        "inheritance", "naslijedstv*", "nasljedstv*", "lottery", "lutrij*"]),
    "credential": ("Credential / payment request", 8, 12, "medium", ["T1598"], [
        "lozink*", "zapork*", "verificirajte", "potvrdite podatke", "potvrdite svoje podatke",
        "potvrdite identitet", "prijavite se", "kod za potvrdu", "jednokratni kod", "otp", "pin",
        "iban", "broj kartice", "cvv", "uplatite", "prebacite", "bitcoin", "btc", "kriptovalut*",
        "gift kartic*", "password", "verify your account", "verify your identity", "sign in",
        "log in", "confirm your identity", "update your payment", "billing information", "ssn",
        "routing number", "security code"]),
    "greeting": ("Generic greeting", 4, 4, "low", [], [
        "postovani korisnice", "postovani klijent*", "dragi korisnice", "dear customer", "dear user",
        "dear client", "dear account holder", "dear sir/madam", "dear sir or madam"]),
}
BEC_PHRASES = [
    "novi iban", "novog iban*", "promjena iban*", "promijenjen* iban*", "promjena racuna",
    "novi racun za uplatu", "nove podatke za uplatu", "change of bank", "change our bank",
    "updated bank details", "new bank account", "bank details have changed", "hitna uplata",
    "hitnu uplatu", "urgent payment", "urgent wire", "wire transfer", "prijenos sredstava",
    "prebacite sredstva"]
CRYPTO_PHRASES = ["bitcoin", "btc", "monero", "kriptovalut*", "ethereum", "usdt", "crypto"]
PRESSURE_CATEGORIES = ("urgency", "authority", "fear", "secrecy", "credential")


def _compile(phrase: str) -> re.Pattern:
    p = normalize(phrase)
    star = p.endswith("*")
    p = p.rstrip("*")
    body = r"\s+".join(re.escape(w) for w in p.split())
    return re.compile(r"(?<![a-z0-9])" + body + ("" if star else r"(?![a-z0-9])"))


_PATTERNS = {k: [(ph, _compile(ph)) for ph in v[5]] for k, v in CATEGORIES.items()}
_BEC = [(ph, _compile(ph)) for ph in BEC_PHRASES]
_CRYPTO = [(ph, _compile(ph)) for ph in CRYPTO_PHRASES]


def _hits(patterns: list, text: str) -> list:
    return [ph for ph, rx in patterns if rx.search(text)]


def analyze_content(subject: str, body: str) -> tuple:
    """Return (findings, tactics) where tactics maps category -> matched phrases."""
    text = " ".join(normalize(subject + "\n" + body).split())
    findings: list = []
    tactics: dict = {}

    for key, (title, w1, w2, sev, attack, _) in CATEGORIES.items():
        found = _hits(_PATTERNS[key], text)
        if not found:
            continue
        tactics[key] = found
        weight = w2 if len(found) >= 2 else w1
        findings.append(Finding(f"C-{key}", "content", title, sev, weight,
                                "Matched: " + ", ".join(found[:6]), attack))

    bec = _hits(_BEC, text)
    if bec:
        tactics["bec_payment"] = bec
        findings.append(Finding("C-bec", "content", "Payment-detail change or urgent transfer request", "high", 15,
                                "Matched: " + ", ".join(bec[:5]) + ". Typical of business e-mail compromise.", ["T1656"]))

    crypto = _hits(_CRYPTO, text)
    if crypto and len(tactics.get("fear", [])) >= 2:
        findings.append(Finding("C-sextortion", "content", "Extortion pattern: threats plus cryptocurrency demand", "high", 25,
                                "Threat language combined with " + ", ".join(crypto[:3]) +
                                ". Do not pay; this pattern is usually mass-mailed.", []))

    pressured = [c for c in PRESSURE_CATEGORIES if c in tactics] + (["bec_payment"] if bec else [])
    if len(pressured) >= 3:
        findings.append(Finding("C-multi", "content", "Several pressure tactics combined", "medium", 10,
                                "Combined: " + ", ".join(pressured) + ".", []))
    return findings, tactics
