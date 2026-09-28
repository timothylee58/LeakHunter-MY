"""Fake customer / payment models — all data is synthetic."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Customer:
    name: str
    ic_number: str       # Malaysian IC (fake)
    email: str
    phone: str


@dataclass
class PaymentRecord:
    customer: Customer
    card_number: str     # Fake payment card
    bank_account: str    # Fake bank account number
    amount_myr: float
