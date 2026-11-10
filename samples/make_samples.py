"""Generate five SYNTHETIC .eml files for demos and tests. Nothing here is a real campaign or real person."""

from __future__ import annotations

import sys
from email.message import EmailMessage
from pathlib import Path

AUTH_FAIL = ("mx.example.org; spf=fail smtp.mailfrom=bounce@mailer.invalid; dkim=none; dmarc=fail header.from=%s")
AUTH_PASS = "mx.example.org; spf=pass; dkim=pass header.d=%s; dmarc=pass header.from=%s"


def base(frm: str, to: str, subject: str, date: str, mid: str, auth: str) -> EmailMessage:
    m = EmailMessage()
    m["From"], m["To"], m["Subject"], m["Date"], m["Message-ID"] = frm, to, subject, date, mid
    m["Authentication-Results"] = auth
    m["Received"] = "from mail.sender.invalid ([203.0.113.45]) by mx.example.org; " + date
    return m


def credential_phish() -> EmailMessage:
    m = base("Zagrebačka banka <sigurnost@zaba-secure-login.com>", "ana.kovac@example.org",
             "HITNO: Vaš račun je privremeno blokiran", "Mon, 02 Nov 2026 08:14:00 +0100",
             "<a1@zaba-secure-login.com>", AUTH_FAIL % "zaba-secure-login.com")
    m.set_content("Poštovani korisnice,\n\nZbog sumnjive aktivnosti Vaš račun je privremeno ograničen. "
                  "Morate odmah verificirati podatke i potvrditi lozinku u roku od 24 sata, inače će račun biti blokiran.\n")
    m.add_alternative(
        '<html><body><p>Poštovani korisnice,</p><p>Vaš račun je <b>privremeno ograničen</b>. Odmah potvrdite lozinku '
        'u roku od 24 sata.</p><p><a href="http://zaba-secure-login.com/prijava?id=88213">www.zaba.hr/prijava</a></p>'
        '</body></html>', subtype="html")
    return m


def sextortion() -> EmailMessage:
    m = base("Unknown <x8f2k@mailbox.invalid>", "marko.horvat@example.org", "Tvoja lozinka i snimka",
             "Tue, 03 Nov 2026 03:02:00 +0100", "<b2@mailbox.invalid>", AUTH_FAIL % "mailbox.invalid")
    m.set_content("Znam tvoju lozinku. Hakirao sam tvoj uređaj i snimio sam te preko kamere dok si gledao intimne "
                  "sadržaje. Podijelit ću snimku na tvoje kontakte ako ne uplatiš 800 EUR u bitcoin u roku od 48 sati. "
                  "Ne govori nikome o ovome. Bitcoin adresa: bc1qexampleexampleexampleexample0000\n")
    return m


def bec_ceo() -> EmailMessage:
    m = base("Ivan Perić - Direktor <ivan.peric.direktor@gmail.com>", "financije@example.org",
             "RE: Hitna uplata dobavljaču", "Wed, 04 Nov 2026 09:40:00 +0100", "<c3@gmail.com>",
             "mx.example.org; spf=pass; dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com")
    m["Reply-To"] = "ivan.peric@example-holdings.invalid"
    m.set_content("Bok, trebam hitnu uplatu dobavljaču danas. Dobavljač je promijenio račun, pošalji na novi IBAN "
                  "HR0000000000000000000. Strogo povjerljivo, ne govori nikome dok ne završimo. Potvrdi odmah.\n")
    return m


def malware_attachment() -> EmailMessage:
    m = base("HR Odjel <hr@firma-dokumenti.xyz>", "ana.kovac@example.org", "Plaća za listopad - pogledajte prilog",
             "Wed, 04 Nov 2026 11:05:00 +0100", "<d4@firma-dokumenti.xyz>", AUTH_FAIL % "firma-dokumenti.xyz")
    m.set_content("Poštovani korisnice, u privitku se nalazi obračun. Otvorite odmah i prijavite se lozinkom.\n")
    m.add_attachment(b"MZ\x90\x00" + b"\x00" * 60, maintype="application", subtype="octet-stream",
                     filename="obracun_listopad.pdf.exe")
    m.add_attachment(b"<html><form><input type='password' name='p'></form><script>eval(atob('AAAA'))</script></html>",
                     maintype="text", subtype="html", filename="prijava.html")
    return m


def benign_newsletter() -> EmailMessage:
    m = base("Example Weekly <news@newsletter.example.org>", "ana.kovac@example.org", "Tjedni pregled: novosti iz IT-a",
             "Fri, 06 Nov 2026 07:00:00 +0100", "<e5@newsletter.example.org>",
             AUTH_PASS % ("newsletter.example.org", "newsletter.example.org"))
    m["In-Reply-To"] = "<prev@newsletter.example.org>"
    m.set_content("Pozdrav Ana, ovo su ovotjedne novosti. Pročitaj članak: https://newsletter.example.org/tjedan-45\n")
    m.add_alternative('<html><body><p>Pozdrav Ana,</p><p><a href="https://newsletter.example.org/tjedan-45">'
                      'newsletter.example.org/tjedan-45</a></p></body></html>', subtype="html")
    return m


SAMPLES = {
    "01_credential_phish_hr.eml": credential_phish,
    "02_sextortion_hr.eml": sextortion,
    "03_bec_ceo_fraud.eml": bec_ceo,
    "04_malicious_attachment.eml": malware_attachment,
    "05_benign_newsletter.eml": benign_newsletter,
}


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, fn in SAMPLES.items():
        (out / name).write_bytes(fn().as_bytes())
        print("wrote", out / name)


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent)
