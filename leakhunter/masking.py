"""Mask PII values in log text, writing safe copies to *.masked files."""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from leakhunter.detectors import PiiType, run_all
from leakhunter.scanner import Finding

# Replacement templates per PII type
_MASK: dict[PiiType, str] = {
    "MYKAD":        "[IC-REDACTED]",
    "PAYMENT_CARD": "[CARD-REDACTED]",
    "BANK_ACCOUNT": "[ACCT-REDACTED]",
    "MY_PHONE":     "[PHONE-REDACTED]",
    "EMAIL":        "[EMAIL-REDACTED]",
}


def mask_pii(text: str) -> str:
    """Detect and redact all PII in *text* in a single pass.

    Unlike :func:`mask`, this function does not require pre-computed findings —
    it runs the detectors inline.  Suitable for use in logging filters and
    formatters.
    """
    matches = run_all(text)
    if not matches:
        return text
    # Replace right-to-left so earlier span offsets stay valid
    chars = list(text)
    for m in sorted(matches, key=lambda x: x.span[0], reverse=True):
        token = _MASK.get(m.pii_type, "[REDACTED]")
        chars[m.span[0]:m.span[1]] = list(token)
    return "".join(chars)


class SafeFormatter(logging.Formatter):
    """A drop-in logging Formatter that redacts PII before writing each record."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        formatted = super().format(record)
        return mask_pii(formatted)


class RedactFilter(logging.Filter):
    """A logging Filter that scrubs PII from the rendered log message in-place.

    Attach to any handler or logger; it rewrites ``record.msg`` and clears
    ``record.args`` so the already-formatted message is stored safely.
    """

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        # Render args into msg first, then redact the merged string
        try:
            rendered = record.getMessage()
        except Exception:
            rendered = str(record.msg)
        record.msg = mask_pii(rendered)
        record.args = None
        return True


def mask(text: str, findings: list[Finding]) -> str:
    """Return *text* with every pre-computed PII span replaced by its mask token.

    Spans are replaced right-to-left so earlier offsets stay valid.
    """
    sorted_findings = sorted(findings, key=lambda f: f.match.span[0], reverse=True)
    chars = list(text)
    for f in sorted_findings:
        start, end = f.match.span
        token = _MASK.get(f.match.pii_type, "[REDACTED]")
        chars[start:end] = list(token)
    return "".join(chars)


def mask_file(path: Path, findings: list[Finding]) -> Path:
    """Write a masked copy of *path* to *path*.masked and return that path.

    Original file is never modified.
    """
    file_findings = [f for f in findings if f.log_path.resolve() == path.resolve()]
    original = path.read_text(encoding="utf-8", errors="replace")

    lines = original.splitlines(keepends=True)
    by_line: dict[int, list[Finding]] = {}
    for f in file_findings:
        by_line.setdefault(f.log_line_no, []).append(f)

    masked_lines: list[str] = []
    for lineno, line in enumerate(lines, start=1):
        line_findings = by_line.get(lineno, [])
        if line_findings:
            line_no_newline = line.rstrip("\n\r")
            masked = mask(line_no_newline, line_findings)
            ending = line[len(line_no_newline):]
            masked_lines.append(masked + ending)
        else:
            masked_lines.append(line)

    out_path = path.with_suffix(path.suffix + ".masked")
    out_path.write_text("".join(masked_lines), encoding="utf-8")
    return out_path
