"""Fake customer model — all data is synthetic."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Customer:
    """Malaysian customer with a safe __repr__ that never exposes PII."""
    name: str
    ic_number: str = field(repr=False)       # Malaysian IC (fake)
    card_number: str = field(repr=False)     # Payment card (fake)
    bank_account: str = field(repr=False)    # Bank account (fake)
    mobile: str = field(repr=False)          # MY mobile (fake)
    email: str = field(repr=False)

    def __repr__(self) -> str:  # noqa: D105
        return f"Customer(name={self.name!r})"
