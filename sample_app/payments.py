"""Intentionally leaky payment processor — used to demonstrate LeakHunter."""
from __future__ import annotations

from pathlib import Path

from sample_app.logging_setup import configure
from sample_app.models import Customer, PaymentRecord

logger = configure(Path("logs"))

# ---------------------------------------------------------------------------
# FAKE data — no real persons, no real cards, no real accounts
# ---------------------------------------------------------------------------
_FAKE_CUSTOMER = Customer(
    name="Siti Binti Demo",
    ic_number="850312-14-5678",   # fake IC — date 1985-03-12, PB=14 (Pahang)
    email="siti.demo@example.my",
    phone="+60123456789",         # fake MY mobile
)

_FAKE_PAYMENT = PaymentRecord(
    customer=_FAKE_CUSTOMER,
    card_number="4111111111111111",  # Visa test card (Luhn-valid, fake)
    bank_account="1234567890",       # fake — 10 digits, near keyword below
    amount_myr=250.00,
)


def process_payment(record: PaymentRecord) -> bool:
    """Simulate payment processing with exactly 4 planted PII leaks."""
    # LEAK 1 — IC number in info log
    logger.info("Processing payment customer_ic=%s", record.customer.ic_number)

    # LEAK 2 — email + phone together in debug log
    logger.debug(
        "Customer contact email=%s phone=%s",
        record.customer.email,
        record.customer.phone,
    )

    try:
        if record.amount_myr <= 0:
            raise ValueError("Amount must be positive")

        # LEAK 3 — card number on success path
        logger.info(
            "Payment approved card=%s amount=%.2f MYR",
            record.card_number,
            record.amount_myr,
        )
        return True
    except ValueError as exc:
        # LEAK 4 — bank account on error path
        logger.error(
            "Payment failed account=%s error=%s",
            record.bank_account,
            exc,
        )
        return False


def run_demo() -> None:
    """Run two transactions: one approved, one rejected (triggers LEAK 4)."""
    process_payment(_FAKE_PAYMENT)

    bad = PaymentRecord(
        customer=_FAKE_CUSTOMER,
        card_number=_FAKE_PAYMENT.card_number,
        bank_account=_FAKE_PAYMENT.bank_account,
        amount_myr=-1.0,
    )
    process_payment(bad)


if __name__ == "__main__":
    run_demo()
