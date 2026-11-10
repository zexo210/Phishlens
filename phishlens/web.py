"""Local web UI: paste or drop an .eml and get the report. Binds to 127.0.0.1 only; nothing is sent anywhere."""

from __future__ import annotations

import argparse
import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .analyzer import analyze
from .parser import parse_eml
from .report import to_html

MAX_BYTES = 5 * 1024 * 1024
SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"

PAGE = """<!doctype html><html lang="hr"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>phishlens</title>
<style>
:root{--bg:#fff;--fg:#1c1b1f;--mut:#666;--card:#f5f5f7;--line:#ddd;--acc:#1a56db}
@media(prefers-color-scheme:dark){:root{--bg:#121212;--fg:#eee;--mut:#aaa;--card:#1e1e1e;--line:#333;--acc:#7aa7ff}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:960px;margin:0 auto;padding:24px 16px}
h1{margin:0 0 4px}p.s{color:var(--mut);margin:0 0 16px}
textarea{width:100%;min-height:180px;box-sizing:border-box;background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:10px;font:13px ui-monospace,monospace}
.row{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0}
button{background:var(--acc);color:#fff;border:0;border-radius:8px;padding:8px 14px;font:inherit;cursor:pointer}
button.g{background:var(--card);color:var(--fg);border:1px solid var(--line)}
#drop{border:2px dashed var(--line);border-radius:8px;padding:14px;text-align:center;color:var(--mut)}
#drop.on{border-color:var(--acc)}
iframe{width:100%;height:760px;border:1px solid var(--line);border-radius:8px;margin-top:16px;background:#fff;display:none}
#err{color:#b3261e}
</style>
<main>
<h1>phishlens</h1>
<p class="s">Zalijepi izvorni tekst maila (&bdquo;Show original&ldquo;) ili povuci .eml datoteku. Sve se obrađuje lokalno na ovom računalu.</p>
<div id="drop">Povuci .eml ovdje ili <label style="text-decoration:underline;cursor:pointer">odaberi datoteku<input id="f" type="file" accept=".eml,message/rfc822" hidden></label></div>
<div class="row"><textarea id="t" placeholder="From: ...&#10;Subject: ...&#10;&#10;tijelo poruke"></textarea></div>
<div class="row"><button id="go">Analiziraj</button><span id="err"></span></div>
<div class="row" id="samples"><span style="color:var(--mut)">Primjeri:</span></div>
<iframe id="out" sandbox title="report"></iframe>
</main>
<script>
const $=id=>document.getElementById(id), out=$('out'), err=$('err');
async function run(body){
  err.textContent='';
  try{
    const r=await fetch('/analyze',{method:'POST',body});
    if(!r.ok){err.textContent=await r.text();return}
    out.srcdoc=await r.text();out.style.display='block';out.scrollIntoView({behavior:'smooth'});
  }catch(e){err.textContent='Greška: '+e}
}
$('go').onclick=()=>{const v=$('t').value;if(!v.trim()){err.textContent='Zalijepi mail ili odaberi datoteku.';return}run(new TextEncoder().encode(v))};
async function file(f){if(f)run(await f.arrayBuffer())}
$('f').onchange=e=>file(e.target.files[0]);
const d=$('drop');
d.ondragover=e=>{e.preventDefault();d.classList.add('on')};d.ondragleave=()=>d.classList.remove('on');
d.ondrop=e=>{e.preventDefault();d.classList.remove('on');file(e.dataTransfer.files[0])};
fetch('/samples').then(r=>r.json()).then(list=>{list.forEach(n=>{
  const b=document.createElement('button');b.className='g';b.textContent=n.replace(/\\.eml$/,'');
  b.onclick=async()=>{const r=await fetch('/sample/'+encodeURIComponent(n));$('t').value=await r.text();run(new TextEncoder().encode($('t').value))};
  $('samples').appendChild(b)})});
</script></html>"""


def sample_names() -> list:
    return sorted(p.name for p in SAMPLES_DIR.glob("*.eml")) if SAMPLES_DIR.is_dir() else []


class Handler(BaseHTTPRequestHandler):
    server_version = "phishlens"

    def _send(self, code: int, body: bytes, ctype: str = "text/html; charset=utf-8") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(200, PAGE.encode())
        elif path == "/samples":
            self._send(200, json.dumps(sample_names()).encode(), "application/json")
        elif path.startswith("/sample/"):
            from urllib.parse import unquote
            name = unquote(path[len("/sample/"):])
            if name in sample_names():  # allow-list: no path traversal possible
                self._send(200, (SAMPLES_DIR / name).read_bytes(), "text/plain; charset=utf-8")
            else:
                self._send(404, b"not found", "text/plain")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/analyze":
            return self._send(404, b"not found", "text/plain")
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._send(400, b"bad length", "text/plain")
        if n <= 0 or n > MAX_BYTES:
            return self._send(413, b"empty or larger than 5 MB", "text/plain; charset=utf-8")
        data = self.rfile.read(n)
        try:
            result = analyze(parse_eml(data), source="web")
            self._send(200, to_html(result).encode())
        except Exception as exc:  # parser must never take the server down
            self._send(500, f"analysis failed: {type(exc).__name__}".encode(), "text/plain")

    def log_message(self, *args) -> None:  # keep the terminal quiet (and free of mail content)
        pass


def make_server(port: int = 8765) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="phishlens.web", description="Local web UI for phishlens.")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args(argv)
    srv = make_server(args.port)
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    print(f"phishlens UI: {url}  (Ctrl+C to stop)")
    if not args.no_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
