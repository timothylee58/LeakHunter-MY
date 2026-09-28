"""Intentionally leaky payment service — FIXED version with root-cause fixes."""
from __future__ import annotations

import uuid

from sample_app.logging_setup import get_logger
from sample_app.models import Customer
from leakhunter.masking import mask, mask_pii

log = get_logger("payments")


class PaymentError(Exception):
    """Raised when a payment is declined; carries only a reference id."""


class PaymentService:
    """Processes payments — all four original leaks are fixed at source."""

    def __init__(self, base_callback_url: str = "https://pay.example.my/cb") -> None:
        self._base = base_callback_url

    def verify_ic(self, customer: Customer) -> bool:
        """Validate the customer's IC number (stub).

        FIX 1 — log the masked IC value, not the raw ic_number.
        """
        masked_ic = mask("MYKAD", customer.ic_number)
        log.info("Verifying IC %s", masked_ic)
        return bool(customer.ic_number)

    def prepare_charge(self, customer: Customer, amount_myr: float) -> dict:
        """Build a charge payload (stub).

        FIX 2 — Customer.__repr__ now returns only the name, so
        log.debug(f"Processing {customer}") is safe.
        """
        log.debug("Processing %s", customer)   # safe: repr omits PII fields
        return {"card": customer.card_number, "amount": amount_myr}

    def charge(self, customer: Customer, amount_myr: float) -> bool:
        """Execute the charge; raise PaymentError on invalid amount.

        FIX 3 — PaymentError carries a ref_id only, never the payload.
        The caller catches PaymentError and logs the ref_id.
        """
        self.prepare_charge(customer, amount_myr)
        if amount_myr <= 0:
            ref_id = uuid.uuid4().hex[:8]
            raise PaymentError(f"Declined ref={ref_id}")
        return True

    def notify_callback(self, customer: Customer) -> None:
        """Fire the post-payment webhook.

        FIX 4 — build the real URL (used for the HTTP call, not logged),
        and a separate masked URL for logging.
        """
        real_url = f"{self._base}?card={customer.card_number}&ic={customer.ic_number}"
        masked_card = mask("PAYMENT_CARD", customer.card_number)
        masked_ic   = mask("MYKAD", customer.ic_number)
        log_url = f"{self._base}?card={masked_card}&ic={masked_ic}"
        log.info("Callback sent: %s", log_url)
        # real_url would be passed to the HTTP client here (not shown)
        _ = real_url

    def process(self, customer: Customer, amount_myr: float) -> bool:
        """Full payment flow: verify, charge, notify.  Returns True on success."""
        self.verify_ic(customer)
        try:
            ok = self.charge(customer, amount_myr)
        except PaymentError as exc:
            log.exception("payment failed: %s", exc)   # exc carries only ref_id
            return False
        if ok:
            self.notify_callback(customer)
        return ok
