"""JSON-line logging setup for the sample app."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

LOG_PATH = Path("logs") / "app.jsonl"

_HANDLER_NAME = "app_jsonl"  # sentinel to avoid duplicate handlers


class _JsonFormatter(logging.Formatter):
    """Emit one JSON line per record with the canonical key set."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        exc_text: str | None = None
        if record.exc_info:
            exc_text = self.formatException(record.exc_info)
        return json.dumps(
            {
                "ts":       datetime.now(timezone.utc).isoformat(),
                "level":    record.levelname,
                "logger":   record.name,
                "pathname": record.pathname,
                "lineno":   record.lineno,
                "message":  record.getMessage(),
                "exc_text": exc_text,
            },
            ensure_ascii=False,
        )


def get_logger(name: str) -> logging.Logger:
    """Return a DEBUG-level logger that appends JSON lines to logs/app.jsonl.

    Creates logs/ if missing.  The file is *not* truncated here — truncation
    at the start of each pytest session is handled by the session fixture in
    conftest.py.

    Attaches a RedactingFilter as defence-in-depth so any PII that slips
    through the application-level masking is scrubbed before it reaches disk.
    """
    from leakhunter.masking import RedactingFilter  # local import avoids circular dep

    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Avoid adding duplicate handlers when the module is re-imported
    if not any(getattr(h, "_lh_name", None) == _HANDLER_NAME for h in logger.handlers):
        fh = logging.FileHandler(LOG_PATH, encoding="utf-8", mode="a")
        fh.setFormatter(_JsonFormatter())
        fh.addFilter(RedactingFilter())
        fh._lh_name = _HANDLER_NAME  # type: ignore[attr-defined]
        logger.addHandler(fh)

    logger.propagate = False
    return logger
