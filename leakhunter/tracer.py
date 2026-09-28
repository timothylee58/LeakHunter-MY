"""Trace a log line back to its application source file and line number."""
from __future__ import annotations

import json
import linecache
from dataclasses import dataclass, field


@dataclass(slots=True)
class SourceRef:
    """Application source location embedded in a structured log record."""
    pathname: str
    lineno: int
    snippet: str = field(default="")   # the actual source line, if readable

    def __str__(self) -> str:
        return f"{self.pathname}:{self.lineno}"


def _read_snippet(pathname: str, lineno: int) -> str:
    """Return the source line at *pathname*:*lineno*, stripped, or empty string."""
    try:
        line = linecache.getline(pathname, lineno)
        return line.strip()
    except Exception:
        return ""


def trace_line(raw_line: str) -> SourceRef | None:
    """Parse a JSON log line and extract pathname + lineno + code snippet."""
    try:
        obj = json.loads(raw_line)
    except (json.JSONDecodeError, ValueError):
        return None

    # Support common structlog / python-json-logger field names
    pathname = obj.get("pathname") or obj.get("filename") or obj.get("module")
    lineno = obj.get("lineno") or obj.get("line") or obj.get("line_number")

    if pathname and lineno is not None:
        try:
            ln = int(lineno)
            snippet = _read_snippet(str(pathname), ln)
            return SourceRef(str(pathname), ln, snippet)
        except (TypeError, ValueError):
            return None
    return None
