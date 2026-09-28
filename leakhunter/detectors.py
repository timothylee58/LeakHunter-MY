"""PII detectors for Malaysian personal data types."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

PiiType = Literal["MYKAD", "PAYMENT_CARD", "BANK_ACCOUNT", "MY_PHONE", "EMAIL"]

# ---------------------------------------------------------------------------
# Valid MyKad birthplace codes (Pusat Pentadbiran Warganegara codes).
# Codes 00, 17-20 are never issued.
# ---------------------------------------------------------------------------
_VALID_PB: set[str] = {
    f"{n:02d}" for n in
    list(range(1, 17)) +       # 01-16  states
    list(range(21, 60)) +      # 21-59  states / FT
    list(range(60, 67)) +      # 60-66  birth outside Malaysia
    list(range(71, 75)) +      # 71-74  special cases
    list(range(82, 100))       # 82-99  older codes
}

_DAYS_IN_MONTH = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]


@dataclass(slots=True)
class Match:
    """A single PII match within a text string."""
    pii_type: PiiType
    value: str
    span: tuple[int, int]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _luhn(digits: str) -> bool:
    """Return True if *digits* passes the Luhn check."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _valid_ic_date(yy: str, mm: str, dd: str) -> bool:
    """Return True if yy/mm/dd form a plausible birth date."""
    m, d = int(mm), int(dd)
    if not (1 <= m <= 12 and 1 <= d <= 31):
        return False
    return d <= _DAYS_IN_MONTH[m]


# ---------------------------------------------------------------------------
# MyKad IC  — YYMMDD-PB-####
# ---------------------------------------------------------------------------
_IC_RE = re.compile(r"\b(\d{2})(0[1-9]|1[0-2])(\d{2})-(\d{2})-(\d{4})\b")


def detect_mykad(text: str) -> list[Match]:
    """Detect Malaysian IC numbers, validating date and birthplace code."""
    results: list[Match] = []
    for m in _IC_RE.finditer(text):
        yy, mm, dd, pb, seq = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
        if pb not in _VALID_PB:
            continue
        if not _valid_ic_date(yy, mm, dd):
            continue
        results.append(Match("MYKAD", m.group(0), m.span()))
    return results


# ---------------------------------------------------------------------------
# Payment card  — 13-19 digits, Luhn, major-network prefix
# ---------------------------------------------------------------------------
_CARD_PREFIXES = re.compile(
    r"^(?:4\d{12,18}"                      # Visa
    r"|5[1-5]\d{14}"                        # Mastercard classic
    r"|2(?:2[2-9]\d|[3-6]\d{2}|7[01]\d|720)\d{12}"  # Mastercard 2-series
    r"|3[47]\d{13}"                         # Amex
    r"|6(?:011|5\d{2})\d{12,15}"           # Discover
    r")$"
)
_CARD_RE = re.compile(r"\b(\d[\d -]{11,21}\d)\b")


def detect_card(text: str) -> list[Match]:
    """Detect payment card numbers using prefix + Luhn validation."""
    results: list[Match] = []
    for m in _CARD_RE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"[ -]", "", raw)
        if not (13 <= len(digits) <= 19):
            continue
        if not _CARD_PREFIXES.match(digits):
            continue
        if not _luhn(digits):
            continue
        results.append(Match("PAYMENT_CARD", raw, m.span()))
    return results


# ---------------------------------------------------------------------------
# Bank account  — 10-16 digits near context keywords
# ---------------------------------------------------------------------------
_BANK_CONTEXT_RE = re.compile(
    r"(?:acct|account|akaun|bank|no\.?\s*acc|no\.?\s*akaun)"
    r".{0,30}?(\b\d{10,16}\b)"
    r"|(\b\d{10,16}\b).{0,30}?(?:acct|account|akaun|bank)",
    re.IGNORECASE | re.DOTALL,
)


def detect_bank_account(text: str) -> list[Match]:
    """Detect bank account numbers appearing near relevant context words."""
    results: list[Match] = []
    seen: set[tuple[int, int]] = set()
    for m in _BANK_CONTEXT_RE.finditer(text):
        grp = m.group(1) or m.group(2)
        # find actual span of the digit group within the full match
        start = text.index(grp, m.start())
        span = (start, start + len(grp))
        if span in seen:
            continue
        seen.add(span)
        results.append(Match("BANK_ACCOUNT", grp, span))
    return results


# ---------------------------------------------------------------------------
# Malaysian mobile  — (+60|0)1X followed by 7-8 digits (separators allowed)
# ---------------------------------------------------------------------------
# Allow optional spaces/hyphens between digit groups after the prefix.
_PHONE_RE = re.compile(
    r"(?<!\d)"
    r"(\+?60|0)"          # country prefix
    r"(1[0-9])"           # 01X
    r"[-\s]?"             # optional separator
    r"(\d{3,4})"          # first digit group
    r"[-\s]?"             # optional separator
    r"(\d{4})"            # last 4 digits
    r"(?!\d)"
)


def detect_phone(text: str) -> list[Match]:
    """Detect Malaysian mobile numbers (bare and formatted with separators)."""
    results: list[Match] = []
    for m in _PHONE_RE.finditer(text):
        # Validate total digit count is 9–10 (after stripping separators)
        raw = m.group(0)
        digits = re.sub(r"[^\d]", "", raw)
        # Remove country prefix digits to count subscriber digits
        prefix = m.group(1).lstrip("+")  # "60" or "0"
        subscriber_digits = digits[len(prefix):]
        if 9 <= len(subscriber_digits) <= 10:
            results.append(Match("MY_PHONE", raw, m.span()))
    return results


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)


def detect_email(text: str) -> list[Match]:
    """Detect e-mail addresses."""
    return [Match("EMAIL", m.group(0), m.span()) for m in _EMAIL_RE.finditer(text)]


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

def run_all(text: str) -> list[Match]:
    """Run every detector and return all matches, sorted by position."""
    matches: list[Match] = []
    for fn in (detect_mykad, detect_card, detect_bank_account, detect_phone, detect_email):
        matches.extend(fn(text))
    matches.sort(key=lambda x: x.span[0])
    return matches
