"""Render an AnalysisResult as Markdown, JSON or a standalone HTML page. IOCs are always defanged."""

from __future__ import annotations

import html
import json

from .analyzer import AnalysisResult, defanged_iocs

COLORS = {"likely phishing": "#b3261e", "suspicious": "#b26a00", "low risk": "#1b6e3c"}


def _ai_lines(ai: dict) -> list:
    if not ai:
        return []
    lines = ["", "## AI second opinion (advisory, does not change the score)", ""]
    if ai.get("error"):
        return lines + [f"_AI step failed: {ai['error']}_"]
    lines.append(f"- Assessment: **{ai.get('assessment', '?')}** (confidence {ai.get('confidence', '?')})")
    lines.append(f"- Summary: {ai.get('summary', '')}")
    for t in ai.get("tactics", []):
        lines.append(f"- Tactic: {t}")
    for e in ai.get("evidence", []):
        lines.append(f"- Evidence: {e}")
    if ai.get("disagreement"):
        lines.append(f"- Differs from heuristics: {ai['disagreement']}")
    return lines


def to_markdown(r: AnalysisResult) -> str:
    iocs = defanged_iocs(r.iocs)
    L = [f"# Phishing analysis: {r.subject or '(no subject)'}", "",
         f"- Source: `{r.source}`", f"- Sender: {iocs['sender']} ({r.sender.split('<')[0].strip() or 'no display name'})",
         f"- **Risk score: {r.score}/100, verdict: {r.verdict}**",
         f"- Authentication: " + (", ".join(f"{k.upper()}={v}" for k, v in r.auth.items()) or "not available"), "",
         "## Findings", ""]
    if r.findings:
        L += ["| Sev | Pts | Finding | Detail |", "|---|---|---|---|"]
        for f in r.findings:
            L.append(f"| {f.severity} | {f.weight:+d} | {f.title} | {f.detail.replace('|', '/')} |")
    else:
        L.append("No indicators found.")
    if r.tactics:
        L += ["", "## Social-engineering tactics", ""]
        for k, v in r.tactics.items():
            L.append(f"- **{k}**: {', '.join(v[:6])}")
    if r.attack:
        L += ["", "## MITRE ATT&CK", ""] + [f"- {a['id']} {a['name']}" for a in r.attack]
    L += ["", "## Indicators of compromise (defanged)", ""]
    for key in ("sender", "reply_to", "sender_domain"):
        if iocs[key]:
            L.append(f"- {key}: `{iocs[key]}`")
    for key in ("domains", "urls", "ips"):
        for v in iocs[key]:
            L.append(f"- {key[:-1]}: `{v}`")
    for a in iocs["attachments"]:
        L.append(f"- attachment: `{a['filename']}` sha256 `{a['sha256']}`")
    L += ["", "## Recommended actions", ""] + [f"- {a}" for a in r.actions]
    L += _ai_lines(r.ai)
    L += ["", "_Heuristic triage aid. It can be wrong in both directions; a human decides._", ""]
    return "\n".join(L)


def to_json(r: AnalysisResult) -> str:
    d = r.to_dict()
    d["iocs"] = defanged_iocs(r.iocs)
    return json.dumps(d, indent=2, ensure_ascii=False)


def to_html(r: AnalysisResult) -> str:
    e = html.escape
    color = COLORS.get(r.verdict, "#444")
    rows = "".join(
        f"<tr><td>{e(f.severity)}</td><td>{f.weight:+d}</td><td>{e(f.title)}</td><td>{e(f.detail)}</td></tr>"
        for f in r.findings)
    iocs = defanged_iocs(r.iocs)
    ioc_items = "".join(f"<li><code>{e(str(v))}</code></li>" for k in ("sender", "reply_to", "domains", "urls", "ips")
                        for v in (iocs[k] if isinstance(iocs[k], list) else [iocs[k]]) if v)
    acts = "".join(f"<li>{e(a)}</li>" for a in r.actions)
    att = "".join(f"<li>{e(a['id'])} {e(a['name'])}</li>" for a in r.attack)
    ai = "<br>".join(e(l) for l in _ai_lines(r.ai) if l)
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>phishlens report</title>
<style>body{{font:15px/1.5 system-ui,sans-serif;max-width:860px;margin:2rem auto;padding:0 16px;color:#1c1b1f;background:#fff}}
.score{{display:inline-block;padding:.4rem 1rem;border-radius:8px;color:#fff;background:{color};font-weight:600}}
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #ddd;padding:6px;text-align:left;vertical-align:top}}
code{{background:#f1f1f1;padding:1px 4px;border-radius:4px;word-break:break-all}}
@media(prefers-color-scheme:dark){{body{{background:#121212;color:#eee}}code{{background:#2a2a2a}}td,th{{border-color:#333}}}}</style>
<h1>{e(r.subject or '(no subject)')}</h1>
<p>Sender: {e(iocs['sender'])}</p>
<p><span class="score">{r.score}/100 &middot; {e(r.verdict)}</span></p>
<h2>Findings</h2><table><tr><th>Sev</th><th>Pts</th><th>Finding</th><th>Detail</th></tr>{rows}</table>
<h2>MITRE ATT&amp;CK</h2><ul>{att}</ul>
<h2>IOCs (defanged)</h2><ul>{ioc_items}</ul>
<h2>Recommended actions</h2><ul>{acts}</ul>
<p>{ai}</p>
<p><small>Heuristic triage aid; a human makes the final call.</small></p></html>"""


RENDERERS = {"md": to_markdown, "json": to_json, "html": to_html}
