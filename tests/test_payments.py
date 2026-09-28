"""Canary-based integration tests for the sample payments app."""
from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

import sample_app.payments as payments_module
from sample_app.logging_setup import configure
from sample_app.models import Customer, PaymentRecord
from sample_app.payments import process_payment
from leakhunter.scanner import scan_dir, scan_file
from tests.conftest import (
    CANARY_ACCOUNT,
    CANARY_CARD,
    CANARY_EMAIL,
    CANARY_IC,
    CANARY_PHONE,
)


@pytest.fixture()
def canary_log(tmp_path: Path, canary_customer: Customer) -> tuple[Path, Path]:
    """Run process_payment with canary data, redirected to a tmp log dir."""
    log_dir = tmp_path / "logs"
    # Reconfigure the logger that payments.py actually uses ("sample_app")
    app_logger = configure(log_dir, name="sample_app")
    # Point the module-level logger to this reconfigured instance
    payments_module.logger = app_logger

    record = PaymentRecord(
        customer=canary_customer,
        card_number=CANARY_CARD,
        bank_account=CANARY_ACCOUNT,
        amount_myr=50.00,
    )
    process_payment(record)

    # Close handlers to flush OS buffers to disk
    for h in list(app_logger.handlers):
        h.flush()
        h.close()
    app_logger.handlers.clear()

    log_file = log_dir / "sample_app.jsonl"
    return log_dir, log_file


class TestCanaryLeaks:
    def test_canary_ic_leaks_into_log(self, canary_log: tuple[Path, Path]) -> None:
        _, log_file = canary_log
        content = log_file.read_text()
        assert CANARY_IC in content, "Canary IC should appear in log (intentional leak)"

    def test_canary_email_leaks_into_log(self, canary_log: tuple[Path, Path]) -> None:
        _, log_file = canary_log
        assert CANARY_EMAIL in log_file.read_text()

    def test_canary_phone_leaks_into_log(self, canary_log: tuple[Path, Path]) -> None:
        _, log_file = canary_log
        assert CANARY_PHONE in log_file.read_text()

    def test_scanner_detects_canary_leaks(self, canary_log: tuple[Path, Path]) -> None:
        log_dir, _ = canary_log
        findings = scan_dir(log_dir)
        assert len(findings) > 0, "Scanner must detect at least one canary PII value"

    def test_scanner_finds_mykad(self, canary_log: tuple[Path, Path]) -> None:
        log_dir, _ = canary_log
        findings = scan_dir(log_dir)
        types = {f.match.pii_type for f in findings}
        assert "MYKAD" in types

    def test_source_ref_traced(self, canary_log: tuple[Path, Path]) -> None:
        """Each finding from a JSON log must have a traceable source reference."""
        log_dir, _ = canary_log
        findings = scan_dir(log_dir)
        # At least some findings should have a source ref (JSON lines have pathname+lineno)
        with_ref = [f for f in findings if f.source_ref is not None]
        assert len(with_ref) > 0, "Source refs must be traced from JSON log lines"

    def test_severity_high_for_ic(self, canary_log: tuple[Path, Path]) -> None:
        log_dir, _ = canary_log
        findings = scan_dir(log_dir)
        ic_findings = [f for f in findings if f.match.pii_type == "MYKAD"]
        assert all(f.severity == "HIGH" for f in ic_findings)
