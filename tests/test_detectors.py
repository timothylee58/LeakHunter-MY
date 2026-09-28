"""Tests for individual PII detectors."""
from __future__ import annotations

import pytest

from leakhunter.detectors import (
    detect_bank_account,
    detect_card,
    detect_email,
    detect_mykad,
    detect_phone,
    run_all,
)


# ---------------------------------------------------------------------------
# MyKad IC
# ---------------------------------------------------------------------------
class TestMyKad:
    def test_valid_ic_detected(self) -> None:
        text = "Customer IC: 901123-08-7654"
        matches = detect_mykad(text)
        assert len(matches) == 1
        assert matches[0].pii_type == "MYKAD"
        assert matches[0].value == "901123-08-7654"

    def test_invalid_birthplace_rejected(self) -> None:
        # PB=00 is never issued
        assert detect_mykad("IC: 901123-00-1234") == []

    def test_never_issued_pb_17_rejected(self) -> None:
        assert detect_mykad("IC: 901123-17-1234") == []

    def test_invalid_month_rejected(self) -> None:
        assert detect_mykad("IC: 901300-08-1234") == []

    def test_invalid_day_rejected(self) -> None:
        assert detect_mykad("IC: 901132-08-1234") == []

    def test_multiple_ics_in_text(self) -> None:
        text = "a=850312-14-5678 b=901123-08-7654"
        assert len(detect_mykad(text)) == 2

    def test_no_false_positive_on_plain_digits(self) -> None:
        assert detect_mykad("Order ref: 123456789012") == []


# ---------------------------------------------------------------------------
# Payment card
# ---------------------------------------------------------------------------
class TestPaymentCard:
    def test_visa_luhn_valid(self) -> None:
        matches = detect_card("card: 4111111111111111")
        assert len(matches) == 1
        assert matches[0].pii_type == "PAYMENT_CARD"

    def test_visa_luhn_invalid_rejected(self) -> None:
        assert detect_card("card: 4111111111111112") == []

    def test_mastercard_detected(self) -> None:
        # Luhn-valid Mastercard test number
        assert len(detect_card("5500005555555559")) == 1

    def test_amex_detected(self) -> None:
        assert len(detect_card("378282246310005")) == 1

    def test_spaces_stripped(self) -> None:
        assert len(detect_card("4111 1111 1111 1111")) == 1


# ---------------------------------------------------------------------------
# Bank account
# ---------------------------------------------------------------------------
class TestBankAccount:
    def test_detected_after_keyword(self) -> None:
        text = "account: 1122334455"
        matches = detect_bank_account(text)
        assert len(matches) == 1
        assert matches[0].value == "1122334455"

    def test_detected_with_malay_keyword(self) -> None:
        text = "akaun 1122334455"
        assert len(detect_bank_account(text)) == 1

    def test_not_detected_without_context(self) -> None:
        # 10-digit number with no banking keyword nearby
        assert detect_bank_account("ref: 1234567890") == []

    def test_too_short_rejected(self) -> None:
        assert detect_bank_account("account: 123456789") == []  # only 9 digits


# ---------------------------------------------------------------------------
# Malaysian phone
# ---------------------------------------------------------------------------
class TestPhone:
    def test_plus60_detected(self) -> None:
        matches = detect_phone("+60123456789")
        assert len(matches) == 1
        assert matches[0].pii_type == "MY_PHONE"

    def test_local_format_detected(self) -> None:
        assert len(detect_phone("0178887777")) == 1

    def test_non_my_number_rejected(self) -> None:
        # +44 UK number — should not match
        assert detect_phone("+441234567890") == []


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------
class TestEmail:
    def test_basic_email(self) -> None:
        matches = detect_email("contact: siti.demo@example.my")
        assert len(matches) == 1
        assert matches[0].pii_type == "EMAIL"

    def test_no_false_positive(self) -> None:
        assert detect_email("no email here just text") == []


# ---------------------------------------------------------------------------
# run_all aggregation
# ---------------------------------------------------------------------------
class TestRunAll:
    def test_all_types_found(self) -> None:
        text = (
            "ic=901123-08-7654 "
            "email=canary@example.my "
            "phone=+60178887777 "
            "card=4111111111111111 "
            "account account=1122334455"
        )
        matches = run_all(text)
        types = {m.pii_type for m in matches}
        assert "MYKAD"        in types
        assert "EMAIL"        in types
        assert "MY_PHONE"     in types
        assert "PAYMENT_CARD" in types
        assert "BANK_ACCOUNT" in types

    def test_results_sorted_by_position(self) -> None:
        text = "email=a@b.com ic=901123-08-7654"
        matches = run_all(text)
        positions = [m.span[0] for m in matches]
        assert positions == sorted(positions)
