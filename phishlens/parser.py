"""Parse an .eml file into a flat structure the analyzers can work on (stdlib only)."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from email import message_from_bytes, policy
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path

URL_RE = re.compile(r"""https?://[^\s<>"'`\])}]+""", re.I)
TRAILING = ".,;:!?)"
TEXT_LIKE_EXT = (".html", ".htm", ".svg", ".js", ".hta", ".vbs", ".txt", ".xml")


@dataclass
class Link:
    href: str
    text: str = ""


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    md5: str
    head: bytes = b""
    text_sample: str = ""


@dataclass
class ParsedEmail:
    headers: dict
    subject: str
    from_name: str
    from_addr: str
    reply_to: str
    return_path: str
    to: str
    date: str
    message_id: str
    received: list
    auth_results: list
    text_body: str
    html_text: str
    links: list
    attachments: list
    html_flags: set = field(default_factory=set)
    raw_size: int = 0

    @property
    def body(self) -> str:
        return (self.text_body + "\n" + self.html_text).strip()

    @property
    def from_domain(self) -> str:
        return self.from_addr.rpartition("@")[2].lower()


class _HTMLScan(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list = []
        self.links: list = []
        self.flags: set = set()
        self._href = None
        self._anchor: list = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag in ("script", "style"):
            self._skip += 1
            if tag == "script":
                self.flags.add("script")
        elif tag == "a" and a.get("href"):
            self._href = a["href"].strip()
            self._anchor = []
        elif tag == "form":
            self.flags.add("form")
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.flags.add("password_input")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._href is not None:
            self.links.append(Link(self._href, " ".join("".join(self._anchor).split())))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._anchor.append(data)


def _decode(part, payload: bytes) -> str:
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _make_attachment(name: str, ctype: str, payload: bytes) -> Attachment:
    sample = ""
    if ctype in ("text/html", "text/plain", "image/svg+xml") or name.lower().endswith(TEXT_LIKE_EXT):
        sample = payload[:20000].decode("utf-8", errors="replace")
    return Attachment(
        filename=name,
        content_type=ctype,
        size=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        md5=hashlib.md5(payload).hexdigest(),  # noqa: S324 (IOC lookups only, not security)
        head=payload[:8],
        text_sample=sample,
    )


def parse_eml(data: bytes) -> ParsedEmail:
    msg = message_from_bytes(data, policy=policy.default)

    headers: dict = {}
    for key, value in msg.items():
        headers.setdefault(key.lower(), []).append(str(value))

    def hdr(name: str) -> str:
        vals = headers.get(name.lower())
        return vals[0] if vals else ""

    from_name, from_addr = parseaddr(hdr("from"))
    text_parts: list = []
    html_parts: list = []
    attachments: list = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        fname = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if fname or part.get_content_disposition() == "attachment":
            attachments.append(_make_attachment(fname or "(unnamed)", ctype, payload))
        elif ctype == "text/plain":
            text_parts.append(_decode(part, payload))
        elif ctype == "text/html":
            html_parts.append(_decode(part, payload))

    scan = _HTMLScan()
    for html in html_parts:
        scan.feed(html)
    scan.close()
    html_text = " ".join(" ".join(scan.text).split())
    text_body = "\n".join(text_parts).strip()

    links: dict = {}
    for link in scan.links:
        if re.match(r"https?://", link.href, re.I):
            links.setdefault(link.href, link)
    for source in (text_body, html_text):
        for m in URL_RE.finditer(source):
            url = m.group(0).rstrip(TRAILING)
            links.setdefault(url, Link(url, ""))

    return ParsedEmail(
        headers=headers,
        subject=hdr("subject"),
        from_name=from_name,
        from_addr=from_addr.lower(),
        reply_to=parseaddr(hdr("reply-to"))[1].lower(),
        return_path=parseaddr(hdr("return-path"))[1].lower(),
        to=hdr("to"),
        date=hdr("date"),
        message_id=hdr("message-id"),
        received=headers.get("received", []),
        auth_results=headers.get("authentication-results", []),
        text_body=text_body,
        html_text=html_text,
        links=list(links.values()),
        attachments=attachments,
        html_flags=scan.flags,
        raw_size=len(data),
    )


def parse_file(path) -> ParsedEmail:
    return parse_eml(Path(path).read_bytes())
