"""Measure phishlens on a labelled corpus.

Layout:  corpus/phish/*.eml   and   corpus/ham/*.eml
Run:     python -m phishlens.evaluate corpus/ [--threshold 45]
"""

from __future__ import annotations

import argparse
from pathlib import Path

from .analyzer import analyze
from .parser import parse_eml


def score_dir(folder: Path) -> list:
    rows = []
    for f in sorted(folder.glob("*.eml")):
        try:
            r = analyze(parse_eml(f.read_bytes()), source=str(f))
            rows.append((f.name, r.score, [x.title for x in r.findings[:3]]))
        except Exception as exc:
            rows.append((f.name, -1, [f"error: {type(exc).__name__}"]))
    return rows


def metrics(phish: list, ham: list, threshold: int) -> dict:
    tp = sum(1 for _, s, _ in phish if s >= threshold)
    fn = len(phish) - tp
    fp = sum(1 for _, s, _ in ham if s >= threshold)
    tn = len(ham) - fp
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"threshold": threshold, "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "precision": round(prec, 3), "recall": round(rec, 3), "f1": round(f1, 3)}


def report(phish: list, ham: list, thresholds=(20, 45)) -> str:
    L = [f"Corpus: {len(phish)} phish, {len(ham)} ham", ""]
    L.append("threshold  TP  FN  FP  TN  precision  recall   F1")
    for t in thresholds:
        m = metrics(phish, ham, t)
        L.append(f"{t:>9}  {m['tp']:>2}  {m['fn']:>2}  {m['fp']:>2}  {m['tn']:>2}  {m['precision']:>9}  {m['recall']:>6}  {m['f1']}")
    t = thresholds[-1]
    fns = [r for r in phish if r[1] < t]
    fps = [r for r in ham if r[1] >= t]
    if fns:
        L += ["", f"Missed phish (score < {t}):"] + [f"  {n}  score={s}" for n, s, _ in fns[:15]]
    if fps:
        L += ["", f"False alarms (score >= {t}):"] + [f"  {n}  score={s}  because: {'; '.join(w)}" for n, s, w in fps[:15]]
    return "\n".join(L)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="phishlens.evaluate")
    ap.add_argument("corpus", type=Path, help="folder with phish/ and ham/ subfolders of .eml files")
    ap.add_argument("--threshold", type=int, default=45)
    args = ap.parse_args(argv)
    phish, ham = score_dir(args.corpus / "phish"), score_dir(args.corpus / "ham")
    if not phish or not ham:
        print("Need .eml files in both phish/ and ham/ subfolders.")
        return 2
    print(report(phish, ham, thresholds=tuple(sorted({20, args.threshold}))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
