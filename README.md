# phishlens

Explainable phishing e-mail triage for `.eml` files. Pure Python standard library for the core; an optional AI second opinion is opt-in.

Built as a portfolio project by a communications/informatics background aiming at SOC / CTI roles. It focuses on what an analyst actually does when a suspicious mail lands: check headers, inspect links and attachments, name the social-engineering tactics, extract IOCs, map to MITRE ATT&CK, and decide.

## Features

- **Headers**: SPF/DKIM/DMARC from `Authentication-Results`, Reply-To / Return-Path mismatch, display-name spoofing, executive name on a free mail service, fake `RE:`/`FW:` subjects.
- **Brand impersonation**: look-alike, typosquat and homoglyph domains for international and Croatian brands (banks, FINA, HZZO, Porezna, Pošta, HT, A1, Telemach, CARNET, gov.hr).
- **Links** (never fetched): IP hosts, punycode, `@` tricks, shorteners, anchor text vs real target, odd TLDs, plain HTTP.
- **Social engineering** (Croatian and English, diacritic-insensitive): urgency, authority, fear/extortion, secrecy, reward, credential/payment requests, BEC payment-change language, sextortion pattern.
- **Attachments**: double extensions, executables, macro Office files, archives/disk images, HTML/SVG with password forms or obfuscated script, magic-byte mismatch (`MZ`/`ELF` hidden as other types), SHA-256/MD5.
- **Output**: Markdown, JSON or standalone HTML; every finding shows its points and evidence; IOCs are defanged; ATT&CK techniques listed.
- **Optional AI opinion** (`--ai`): advisory only, never changes the score.

## Usage

```bash
python -m phishlens samples/01_credential_phish_hr.eml
python -m phishlens samples/*.eml --format html --out reports/
python -m phishlens mail.eml --format json --fail-on suspicious   # CI / pipelines
cat mail.eml | python -m phishlens -
```

Web UI (local only, 127.0.0.1): `python -m phishlens.web` opens a page where you paste a raw mail or drop an `.eml`.

Measure it on labelled data: put `.eml` files in `corpus/phish/` and `corpus/ham/`, then `python -m phishlens.evaluate corpus/` prints TP/FN/FP/TN, precision, recall, F1 and lists missed phish and false alarms.

Exit codes: `0` ok, `1` suspicious, `2` likely phishing (with `--fail-on`), `3` unreadable file.

Score = sum of finding weights clamped to 0-100. Bands: below 20 low risk, 20-44 suspicious, 45 and above likely phishing. Weights live next to each rule, so tuning is a one-line change.

## Optional AI second opinion

```bash
pip install anthropic
export ANTHROPIC_API_KEY=...
python -m phishlens mail.eml --ai --redact
```

Design choices: the e-mail is untrusted data inside `<email>` tags, the closing tag is escaped so it cannot break out, the reply must be JSON and is validated, API errors never break the offline analysis, and the AI verdict is shown next to the heuristic score rather than replacing it.

**Responsible use:** `--ai` sends message content to an external API. Use `--redact`, and never run it on confidential, personal-data-heavy or classified mail. Without `--ai` nothing leaves your machine.

## Tests

```bash
pip install pytest
python -m pytest
```

The AI layer is tested with a fake client (no network). Samples in `samples/` are synthetic: invented domains, no real people or campaigns. Regenerate with `python samples/make_samples.py samples`.

## Limitations (honest)

- Heuristics and keyword lists: they miss novel lures and can flag legitimate urgent mail. A human decides.
- No live reputation lookups, no URL detonation, no archive/Office macro inspection, no image/QR analysis.
- Registrable-domain logic uses a small suffix list, not the full Public Suffix List.
- Language lexicon covers Croatian and English only.
- Passing SPF/DKIM/DMARC lowers the score slightly but does not prove legitimacy.
- Not validated on a large labelled corpus; the sample scores are demonstrations, not benchmarks.

## Ideas for next steps

PSL-based domain parsing, VirusTotal/URLhaus enrichment (opt-in), QR-code and image text extraction, Sigma/YARA rule export, evaluation on a public phishing corpus.

## Layout

```
phishlens/  parser, headers, urls, content, attachments, analyzer, report, llm, cli, web, evaluate
samples/    synthetic .eml generator and outputs
tests/      pytest suite
```
