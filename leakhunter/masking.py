"""PII masking — format-preserving token masks, inline text redaction, logging filter."""
from __future__ import annotations

import logging
import re
from pathlib import Path

from leakhunter.detectors import PiiType, run_all

# ---------------------------------------------------------------------------
# Format-preserving masks
# ---------------------------------------------------------------------------

def mask(pii_type: PiiType, value: str) -> str:
    """Return a format-preserving masked token for *value*.

    Examples
    --------
    MYKAD        "900101-14-5678"      -> "******-**-5678"
    PAYMENT_CARD "4111 1111 1111 1111" -> "**** **** **** 1111"
    BANK_ACCOUNT "1234567890"          -> "******7890"
    MY_PHONE     "+6012-345 6789"      -> "+60**-*** 6789"
    EMAIL        "user@example.my"     -> "u***@example.my"
    """
    if pii_type == "MYKAD":
        # Keep last 4 digits of sequence; mask date + birthplace
        parts = value.split("-")
        if len(parts) == 3:
            return f"******-**-{parts[2]}"
        return "******-**-****"

    if pii_type == "PAYMENT_CARD":
        digits = re.sub(r"[ -]", "", value)
        last4 = digits[-4:]
        # Rebuild with original spacing pattern, masking all but last group
        groups = re.findall(r"[\d]+|[ -]", value)
        result: list[str] = []
        digit_count = 0
        total_to_mask = len(digits) - 4
        for g in groups:
            if re.match(r"\d+", g):
                masked_chars: list[str] = []
                for ch in g:
                    if digit_count < total_to_mask:
                        masked_chars.append("*")
                    else:
                        masked_chars.append(ch)
                    digit_count += 1
                result.append("".join(masked_chars))
            else:
                result.append(g)
        return "".join(result)

    if pii_type == "BANK_ACCOUNT":
        digits = re.sub(r"[ -]", "", value)
        keep = min(4, len(digits))
        return "*" * (len(digits) - keep) + digits[-keep:]

    if pii_type == "MY_PHONE":
        # Keep country prefix (+60 / 60 / 0) and last 4 digits
        digits_only = re.sub(r"[^\d+]", "", value)
        last4 = digits_only[-4:]
        # Identify prefix
        if value.startswith("+60"):
            prefix = "+60"
        elif value.startswith("60"):
            prefix = "60"
        else:
            prefix = "0"
        return f"{prefix}****{last4}"

    if pii_type == "EMAIL":
        at = value.find("@")
        if at > 0:
            local = value[:at]
            domain = value[at:]          # includes the @
            return local[0] + "***" + domain
        return "***@***"

    return "[REDACTED]"


# ---------------------------------------------------------------------------
# Replacement tokens for bulk text redaction (mask_pii)
# ---------------------------------------------------------------------------

_BULK_TOKEN: dict[PiiType, str] = {
    "MYKAD":        "[IC-REDACTED]",
    "PAYMENT_CARD": "[CARD-REDACTED]",
    "BANK_ACCOUNT": "[ACCT-REDACTED]",
    "MY_PHONE":     "[PHONE-REDACTED]",
    "EMAIL":        "[EMAIL-REDACTED]",
}


def mask_pii(text: str) -> str:
    """Detect and redact all PII in *text* in a single pass.

    Does not require pre-computed findings — runs detectors inline.
    Suitable for use inside logging filters and formatters.
    """
    matches = run_all(text)
    if not matches:
        return text
    chars = list(text)
    for m in sorted(matches, key=lambda x: x.span[0], reverse=True):
        token = _BULK_TOKEN.get(m.pii_type, "[REDACTED]")
        chars[m.span[0]:m.span[1]] = list(token)
    return "".join(chars)


# ---------------------------------------------------------------------------
# Logging integration
# ---------------------------------------------------------------------------

class SafeFormatter(logging.Formatter):
    """Drop-in Formatter that redacts PII from the final formatted string."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        return mask_pii(super().format(record))


class RedactingFilter(logging.Filter):
    """Logging Filter that scrubs PII from message *and* exc_text in-place.

    Attach to any handler or logger.  Rewrites ``record.msg``, clears
    ``record.args``, and sanitises ``record.exc_text``.
    """

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        try:
            rendered = record.getMessage()
        except Exception:
            rendered = str(record.msg)
        record.msg = mask_pii(rendered)
        record.args = None
        if record.exc_text:
            record.exc_text = mask_pii(record.exc_text)
        return True


# Keep the old name as an alias so existing imports don't break.
RedactFilter = RedactingFilter


# ---------------------------------------------------------------------------
# File-level masking helpers (used by older scanner-based tests)
# ---------------------------------------------------------------------------

def _mask_value(pii_type: PiiType) -> str:
    """Return the bulk redaction token for a PII type."""
    return _BULK_TOKEN.get(pii_type, "[REDACTED]")


def mask_findings(text: str, findings: list) -> str:  # type: ignore[type-arg]
    """Return *text* with every pre-computed Finding span replaced.

    Accepts the legacy Finding dataclass from scanner.py.
    """
    sorted_findings = sorted(findings, key=lambda f: f.match.span[0], reverse=True)
    chars = list(text)
    for f in sorted_findings:
        start, end = f.match.span
        token = _BULK_TOKEN.get(f.match.pii_type, "[REDACTED]")
        chars[start:end] = list(token)
    return "".join(chars)


def mask_file(path: Path, findings: list) -> Path:  # type: ignore[type-arg]
    """Write a masked copy of *path* to *path*.masked and return that path.

    Original file is never modified.
    """
    file_findings = [f for f in findings if f.log_path.resolve() == path.resolve()]
    original = path.read_text(encoding="utf-8", errors="replace")

    lines = original.splitlines(keepends=True)
    by_line: dict[int, list] = {}
    for f in file_findings:
        by_line.setdefault(f.log_line_no, []).append(f)

    masked_lines: list[str] = []
    for lineno, line in enumerate(lines, start=1):
        line_findings = by_line.get(lineno, [])
        if line_findings:
            line_no_newline = line.rstrip("\n\r")
            masked = mask_findings(line_no_newline, line_findings)
            ending = line[len(line_no_newline):]
            masked_lines.append(masked + ending)
        else:
            masked_lines.append(line)

    out_path = path.with_suffix(path.suffix + ".masked")
    out_path.write_text("".join(masked_lines), encoding="utf-8")
    return out_path


# Legacy alias — the OLD two-argument form mask(text, findings) still works
# via this name so existing test code imports it directly.
# NOTE: do not shadow the top-level mask(pii_type, value) function.
def mask_text_with_findings(text: str, findings: list) -> str:
    """Alias for mask_findings — used internally."""
    return mask_findings(text, findings)
