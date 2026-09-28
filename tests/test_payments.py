"""Integration tests: exercise PaymentService with CANARY data.

After the root-cause fixes, no raw PII should appear in logs/app.jsonl.
Tests assert both correct service behaviour AND that logs are clean.
"""
from __future__ import annotations

import json
import logging
import pytest

from sample_app.logging_setup import LOG_PATH
from sample_app.models import Customer
from sample_app.payments import PaymentError, PaymentService
from leakhunter.masking import mask
from tests.conftest import (
    CANARY_ACCOUNT,
    CANARY_CARD,
    CANARY_EMAIL,
    CANARY_IC,
    CANARY_PHONE,
)


@pytest.fixture(scope="module")
def svc() -> PaymentService:
    return PaymentService()


# ---------------------------------------------------------------------------
# Functional tests — assert the service works correctly
# ---------------------------------------------------------------------------

class TestVerifyIc:
    """FIX 1 — masked IC logged, not raw value."""

    def test_returns_true_for_valid_ic(self, svc: PaymentService, CANARY: Customer) -> None:
        assert svc.verify_ic(CANARY) is True

    def test_raw_ic_not_in_log(self, svc: PaymentService, CANARY: Customer) -> None:
        svc.verify_ic(CANARY)
        content = LOG_PATH.read_text(encoding="utf-8")
        assert CANARY_IC not in content, "FIX 1: raw IC must NOT appear in logs"

    def test_masked_ic_in_log(self, svc: PaymentService, CANARY: Customer) -> None:
        svc.verify_ic(CANARY)
        content = LOG_PATH.read_text(encoding="utf-8")
        assert mask("MYKAD", CANARY_IC) in content, "Masked IC must appear in log"


class TestPrepareCharge:
    """FIX 2 — Customer.__repr__ omits PII fields."""

    def test_returns_payload_dict(self, svc: PaymentService, CANARY: Customer) -> None:
        payload = svc.prepare_charge(CANARY, 100.0)
        assert payload["card"] == CANARY.card_number
        assert payload["amount"] == 100.0

    def test_repr_is_safe(self, CANARY: Customer) -> None:
        r = repr(CANARY)
        assert CANARY_IC    not in r, "IC must not appear in __repr__"
        assert CANARY_CARD  not in r, "card must not appear in __repr__"
        assert CANARY_EMAIL not in r, "email must not appear in __repr__"

    def test_raw_pii_not_in_log_after_prepare_charge(
        self, svc: PaymentService, CANARY: Customer
    ) -> None:
        svc.prepare_charge(CANARY, 50.0)
        content = LOG_PATH.read_text(encoding="utf-8")
        assert CANARY_IC    not in content, "IC must not appear in logs"
        assert CANARY_CARD  not in content, "card must not appear in logs"
        assert CANARY_EMAIL not in content, "email must not appear in logs"


class TestCharge:
    """FIX 3 — PaymentError carries ref_id only; card never reaches log."""

    def test_returns_true_for_positive_amount(self, svc: PaymentService, CANARY: Customer) -> None:
        assert svc.charge(CANARY, 250.0) is True

    def test_raises_payment_error_for_non_positive(self, svc: PaymentService, CANARY: Customer) -> None:
        with pytest.raises(PaymentError, match="Declined"):
            svc.charge(CANARY, 0)

    def test_card_not_in_payment_error_message(self, svc: PaymentService, CANARY: Customer) -> None:
        try:
            svc.charge(CANARY, 0)
        except PaymentError as exc:
            assert CANARY_CARD not in str(exc), "Card must not appear in PaymentError message"

    def test_raw_card_not_in_log_on_decline(self, svc: PaymentService, CANARY: Customer) -> None:
        svc.process(CANARY, -1.0)
        content = LOG_PATH.read_text(encoding="utf-8")
        assert CANARY_CARD not in content, "FIX 3: card must NOT appear in logs after decline"


class TestNotifyCallback:
    """FIX 4 — masked URL logged; real URL never reaches log."""

    def test_callback_is_sent(self, svc: PaymentService, CANARY: Customer) -> None:
        svc.notify_callback(CANARY)  # must not raise

    def test_raw_card_not_in_log_after_callback(self, svc: PaymentService, CANARY: Customer) -> None:
        svc.notify_callback(CANARY)
        content = LOG_PATH.read_text(encoding="utf-8")
        assert CANARY_CARD not in content, "FIX 4: raw card must NOT appear in callback log"
        assert CANARY_IC   not in content, "FIX 4: raw IC must NOT appear in callback log"

    def test_masked_values_in_log_after_callback(self, svc: PaymentService, CANARY: Customer) -> None:
        svc.notify_callback(CANARY)
        content = LOG_PATH.read_text(encoding="utf-8")
        assert mask("PAYMENT_CARD", CANARY_CARD) in content
        assert mask("MYKAD", CANARY_IC) in content


class TestProcessFull:
    """End-to-end: after fixes, no raw PII appears anywhere in logs."""

    def test_success_path_returns_true(self, svc: PaymentService, CANARY: Customer) -> None:
        assert svc.process(CANARY, 99.00) is True

    def test_failure_path_returns_false(self, svc: PaymentService, CANARY: Customer) -> None:
        assert svc.process(CANARY, -1.0) is False

    def test_no_raw_pii_in_log_after_full_run(
        self, svc: PaymentService, CANARY: Customer
    ) -> None:
        svc.process(CANARY, 99.00)
        svc.process(CANARY, -1.0)
        content = LOG_PATH.read_text(encoding="utf-8")
        for value, label in [
            (CANARY_IC,      "IC"),
            (CANARY_CARD,    "card"),
            (CANARY_EMAIL,   "email"),
            (CANARY_PHONE,   "phone"),
            (CANARY_ACCOUNT, "account"),
        ]:
            assert value not in content, f"Raw {label} must NOT appear in logs/app.jsonl"

    def test_log_lines_are_valid_json(self, svc: PaymentService, CANARY: Customer) -> None:
        svc.process(CANARY, 99.00)
        lines = [ln for ln in LOG_PATH.read_text(encoding="utf-8").splitlines() if ln.strip()]
        for line in lines:
            record = json.loads(line)  # raises if invalid
            assert "ts" in record
            assert "level" in record
            assert "message" in record
