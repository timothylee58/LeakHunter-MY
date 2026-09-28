"""Severity scoring for PII findings."""
from __future__ import annotations

from typing import Literal

from leakhunter.detectors import PiiType

SeverityLabel = Literal["HIGH", "MEDIUM", "LOW"]

# Sensitivity weights per PII type
_SENSITIVITY: dict[PiiType, float] = {
    "MYKAD": 3.0,
    "PAYMENT_CARD": 3.0,
    "BANK_ACCOUNT": 3.0,
    "MY_PHONE": 2.0,
    "EMAIL": 1.0,
}

# Exposure multipliers per log level
_EXPOSURE: dict[str, float] = {
    "ERROR": 1.5,
    "CRITICAL": 1.5,
    "EXCEPTION": 1.5,
    "WARNING": 1.2,
    "INFO": 1.0,
    "DEBUG": 1.0,
    "UNKNOWN": 1.0,
}

# PDPA 2010 Security Principle tag per PII type
PDPA_TAG: dict[PiiType, str] = {
    "MYKAD":        "PDPA-S9: Biometric/identity data — must not be disclosed without consent",
    "PAYMENT_CARD": "PDPA-S9: Financial data — PCI-DSS and PDPA protection required",
    "BANK_ACCOUNT": "PDPA-S9: Financial data — restricted processing under PDPA",
    "MY_PHONE":     "PDPA-S7: Contact data — collection must be notified",
    "EMAIL":        "PDPA-S7: Contact data — collection must be notified",
}


def score(pii_type: PiiType, log_level: str) -> float:
    """Return a numeric severity score for a PII type at a given log level."""
    sens = _SENSITIVITY.get(pii_type, 1.0)
    exp = _EXPOSURE.get(log_level.upper(), 1.0)
    return round(sens * exp, 2)


def classify(raw_score: float) -> SeverityLabel:
    """Map a numeric score to HIGH / MEDIUM / LOW."""
    if raw_score >= 3.0:
        return "HIGH"
    if raw_score >= 2.0:
        return "MEDIUM"
    return "LOW"
