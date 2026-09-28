"""JSON-line logging setup for the sample app."""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path


class _JsonFormatter(logging.Formatter):
    """Emit each log record as a single JSON line with source location."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level":     record.levelname,
            "message":   record.getMessage(),
            "pathname":  record.pathname,
            "lineno":    record.lineno,
            "logger":    record.name,
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure(log_dir: Path = Path("logs"), name: str = "sample_app") -> logging.Logger:
    """Return a logger that writes JSON lines to *log_dir*/<name>.jsonl."""
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{name}.jsonl"

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(_JsonFormatter())
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.WARNING)
    sh.setFormatter(_JsonFormatter())
    logger.addHandler(sh)

    return logger
