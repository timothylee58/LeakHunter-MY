"""Shared fixtures for LeakHunter tests."""
from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from sample_app.models import Customer, PaymentRecord


# ---------------------------------------------------------------------------
# Canary customer — unique fake values that must never appear in clean logs
# ---------------------------------------------------------------------------
CANARY_IC      = "901123-08-7654"    # fake IC — 1990-11-23, PB=08 (Perak)
CANARY_EMAIL   = "canary.pii@leakhunter-fake.my"
CANARY_PHONE   = "+60178887777"      # fake MY mobile
CANARY_CARD    = "4532015112830366"  # Visa Luhn-valid, fake test number
CANARY_ACCOUNT = "1122334455"        # fake 10-digit bank account


@pytest.fixture()
def canary_customer() -> Customer:
    """Return the canary Customer with unique fake PII."""
    return Customer(
        name="Canary Demo",
        ic_number=CANARY_IC,
        email=CANARY_EMAIL,
        phone=CANARY_PHONE,
    )


@pytest.fixture()
def canary_payment(canary_customer: Customer) -> PaymentRecord:
    """Return a PaymentRecord with all canary PII values."""
    return PaymentRecord(
        customer=canary_customer,
        card_number=CANARY_CARD,
        bank_account=CANARY_ACCOUNT,
        amount_myr=99.00,
    )


@pytest.fixture()
def log_dir(tmp_path: Path) -> Path:
    """Return a fresh temporary log directory."""
    d = tmp_path / "logs"
    d.mkdir()
    return d


@pytest.fixture()
def clean_log(log_dir: Path) -> Path:
    """A log file with NO PII — should produce zero findings."""
    p = log_dir / "clean.jsonl"
    records = [
        {"level": "INFO",    "message": "Server started on port 8080",    "pathname": "app.py",    "lineno": 10},
        {"level": "DEBUG",   "message": "Cache miss for key=user_prefs",   "pathname": "cache.py",  "lineno": 22},
        {"level": "WARNING", "message": "High memory usage detected",      "pathname": "monitor.py","lineno": 5},
    ]
    p.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return p


@pytest.fixture()
def leaky_log(log_dir: Path) -> Path:
    """A log file that contains all canary PII values."""
    p = log_dir / "leaky.jsonl"
    records = [
        {"level": "INFO",  "message": f"Customer ic={CANARY_IC} email={CANARY_EMAIL}",
         "pathname": "payments.py", "lineno": 33},
        {"level": "INFO",  "message": f"Phone {CANARY_PHONE} registered",
         "pathname": "customers.py", "lineno": 18},
        {"level": "ERROR", "message": f"Payment failed card={CANARY_CARD} account=akaun {CANARY_ACCOUNT}",
         "pathname": "payments.py", "lineno": 48},
    ]
    p.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return p
