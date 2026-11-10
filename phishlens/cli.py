"""Command line interface: phishlens mail.eml [--format md|json|html] [--ai] [--redact]"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .analyzer import analyze
from .parser import parse_eml
from .report import RENDERERS

EXIT = {"low risk": 0, "suspicious": 1, "likely phishing": 2}
LEVEL = {"low": 0, "suspicious": 1, "phishing": 2}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="phishlens", description="Explainable phishing e-mail triage (.eml).")
    ap.add_argument("files", nargs="+", help=".eml files, or '-' for stdin")
    ap.add_argument("-f", "--format", choices=sorted(RENDERERS), default="md")
    ap.add_argument("-o", "--out", help="write report here (a directory when several files are given)")
    ap.add_argument("--ai", action="store_true", help="add an optional AI second opinion (sends content to the API)")
    ap.add_argument("--model", default=None, help="model for --ai (default: $PHISHLENS_MODEL or built-in)")
    ap.add_argument("--redact", action="store_true", help="mask e-mails, IPs and numbers before the AI call")
    ap.add_argument("--fail-on", choices=sorted(LEVEL), default=None,
                    help="exit non-zero if any verdict reaches this level (low|suspicious|phishing)")
    ap.add_argument("--version", action="version", version=f"phishlens {__version__}")
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    render = RENDERERS[args.format]
    worst = 0
    outputs: list = []
    for name in args.files:
        try:
            data = sys.stdin.buffer.read() if name == "-" else Path(name).read_bytes()
        except OSError as exc:
            print(f"phishlens: cannot read {name}: {exc}", file=sys.stderr)
            return 3
        parsed = parse_eml(data)
        result = analyze(parsed, source="stdin" if name == "-" else name)
        if args.ai:
            from .llm import DEFAULT_MODEL, analyze_with_llm
            result.ai = analyze_with_llm(parsed, result, model=args.model or DEFAULT_MODEL, do_redact=args.redact)
        worst = max(worst, EXIT[result.verdict])
        outputs.append((name, render(result)))

    if args.out:
        out = Path(args.out)
        if len(outputs) > 1:
            out.mkdir(parents=True, exist_ok=True)
            for name, text in outputs:
                (out / (Path(name).stem + "." + args.format)).write_text(text, encoding="utf-8")
        else:
            out.write_text(outputs[0][1], encoding="utf-8")
    else:
        print("\n\n".join(t for _, t in outputs))

    if args.fail_on is not None:
        need = LEVEL[args.fail_on]
        return worst if worst >= need else 0
    return 0
