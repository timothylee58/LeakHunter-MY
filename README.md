# LeakHunter MY 🔍

> Find Malaysian PII leaking into your application logs — deterministic regex + Luhn, fully offline, PDPA 2010 tagged.

## Quick start

```bash
pip install -e ".[dev]"

# generate sample leaky logs
python -m sample_app.payments

# scan and report
leakhunter scan logs/

# fix: write masked copies of every leaky log
leakhunter scan logs/ --fix

# scan + write JSON report
leakhunter scan logs/ --report reports/leaks.json

# CI gate — exit 1 if HIGH severity found
leakhunter scan logs/ --fail-on-high
```

## What it detects

| PII Type      | Method                              | PDPA Principle |
|---------------|-------------------------------------|----------------|
| MyKad IC      | Regex + date validation + PB code   | S9 — Security  |
| Payment card  | 13–19 digits, prefix + Luhn         | S9 — Security  |
| Bank account  | 10–16 digits near banking keywords  | S9 — Security  |
| MY mobile     | `(+60\|0)1X` + 7–8 digits           | S7 — Notice    |
| Email         | RFC-5321 simplified regex           | S7 — Notice    |

## Severity scoring

```
score  = sensitivity × exposure_multiplier
HIGH   ≥ 3.0   (IC/card/bank at any level; IC/card/bank at ERROR = 4.5)
MEDIUM ≥ 2.0   (phone at ERROR)
LOW    < 2.0   (email at INFO)
```

## Architecture

```
leakhunter/
  detectors.py   — regex patterns, Luhn, IC validation
  severity.py    — scoring + PDPA tags
  scanner.py     — file / directory scan, Finding dataclass
  tracer.py      — JSON log → app source file:line
  masking.py     — in-place redaction to *.masked copies
  report.py      — Rich console table + JSON report
  cli.py         — Typer CLI (scan, demo)

sample_app/
  models.py        — fake Customer + PaymentRecord
  logging_setup.py — JSON-line logger with pathname + lineno
  payments.py      — intentionally leaky processor (demo target)

tests/
  conftest.py      — canary fixture (unique fake PII)
  test_detectors.py
  test_payments.py — canary integration: leak → detect
  test_masking.py  — mask → re-scan → zero findings
```

## Running tests

```bash
pytest -v
pytest --tb=short tests/test_masking.py   # masking only
```

> **All PII values in this repository are entirely synthetic.** No real persons, real cards, or real accounts are used anywhere.
