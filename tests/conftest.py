"""Shared pytest fixtures for LeakHunter tests."""
from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from sample_app.logging_setup import LOG_PATH, get_logger
from sample_app.models import Customer

# ---------------------------------------------------------------------------
# Canary constants — unique fake values used to prove leaks by string search
# ---------------------------------------------------------------------------
CANARY_IC      = "900101-14-5678"
CANARY_CARD    = "4111 1111 1111 1111"
CANARY_ACCOUNT = "5140 1234 7890"
CANARY_PHONE   = "+6012-345 6789"
CANARY_EMAIL   = "canary.tan@leakhunter.test"


# ---------------------------------------------------------------------------
# Session-scoped fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def truncate_app_log() -> None:
    """Truncate logs/app.jsonl at the start of each pytest session."""
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOG_PATH.write_text("", encoding="utf-8")


@pytest.fixture(scope="session")
def CANARY() -> Customer:  # noqa: N802  — named CANARY to match spec
    """The canary Customer with unique fake PII values."""
    return Customer(
        name="CANARY Tan Ah Kow",
        ic_number=CANARY_IC,
        card_number=CANARY_CARD,
        bank_account=CANARY_ACCOUNT,
        mobile=CANARY_PHONE,
        email=CANARY_EMAIL,
    )


@pytest.fixture(scope="session")
def app_logger() -> logging.Logger:
    """Return the payments logger at DEBUG level for the whole session."""
    logger = get_logger("payments")
    logger.setLevel(logging.DEBUG)
    return logger


# ---------------------------------------------------------------------------
# Function-scoped fixtures (used by test_masking.py / test_detectors.py)
# ---------------------------------------------------------------------------

@pytest.fixture()
def log_dir(tmp_path: Path) -> Path:
    """Return a fresh temporary log directory."""
    d = tmp_path / "logs"
    d.mkdir()
    return d


@pytest.fixture()
def clean_log(log_dir: Path) -> Path:
    """A .jsonl file with NO PII — should produce zero findings."""
    p = log_dir / "clean.jsonl"
    records = [
        {"ts": "2024-01-01T00:00:00+00:00", "level": "INFO",    "logger": "app",
         "message": "Server started on port 8080",  "pathname": "app.py",    "lineno": 10, "exc_text": None},
        {"ts": "2024-01-01T00:00:01+00:00", "level": "DEBUG",   "logger": "app",
         "message": "Cache miss for key=user_prefs", "pathname": "cache.py",  "lineno": 22, "exc_text": None},
        {"ts": "2024-01-01T00:00:02+00:00", "level": "WARNING", "logger": "app",
         "message": "High memory usage detected",    "pathname": "monitor.py","lineno": 5,  "exc_text": None},
    ]
    p.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return p


@pytest.fixture()
def leaky_log(log_dir: Path) -> Path:
    """A .jsonl file that contains every canary PII value."""
    p = log_dir / "leaky.jsonl"
    records = [
        {"ts": "2024-01-01T00:00:00+00:00", "level": "INFO",  "logger": "payments",
         "message": f"Customer ic={CANARY_IC} email={CANARY_EMAIL}",
         "pathname": "payments.py", "lineno": 33, "exc_text": None},
        {"ts": "2024-01-01T00:00:01+00:00", "level": "INFO",  "logger": "payments",
         "message": f"Phone {CANARY_PHONE} registered",
         "pathname": "customers.py", "lineno": 18, "exc_text": None},
        {"ts": "2024-01-01T00:00:02+00:00", "level": "ERROR", "logger": "payments",
         "message": f"Payment failed card={CANARY_CARD} account=akaun {CANARY_ACCOUNT}",
         "pathname": "payments.py", "lineno": 48, "exc_text": None},
    ]
    p.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return p
