"""Scan log files and source trees for PII findings."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from leakhunter.detectors import Match, run_all
from leakhunter.severity import PDPA_TAG, SeverityLabel, classify, score
from leakhunter.tracer import SourceRef, trace_line


@dataclass(slots=True)
class Finding:
    """One PII occurrence discovered in a log or source file."""
    match: Match
    log_level: str
    severity_score: float
    severity: SeverityLabel
    pdpa_tag: str
    raw_line: str
    log_path: Path
    log_line_no: int               # 1-based line number in the file
    source_ref: SourceRef | None   # traced back to app source, if available


# ---------------------------------------------------------------------------
# Log-level extraction
# ---------------------------------------------------------------------------

def _extract_log_level(line: str, obj: dict | None = None) -> str:
    """Best-effort extraction of log level from a raw log line."""
    if obj is not None:
        for key in ("level", "levelname", "severity", "log_level"):
            if key in obj:
                return str(obj[key]).upper()
    for token in ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"):
        if token in line.upper():
            return token
    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Single-file streaming scanner
# ---------------------------------------------------------------------------

def _iter_findings(path: Path) -> Iterator[Finding]:
    """Yield findings from *path* one line at a time (no full-file load)."""
    try:
        fh = path.open(encoding="utf-8", errors="replace")
    except OSError:
        return
    with fh:
        for lineno, raw in enumerate(fh, start=1):
            raw = raw.rstrip("\n\r")
            if not raw:
                continue

            # Try to parse as JSON once per line for log-level + source tracing
            obj: dict | None = None
            try:
                obj = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                pass

            # Scan message + exc_text fields (where the PII actually lives)
            if obj is not None:
                scan_text = (obj.get("message") or "") + " " + (obj.get("exc_text") or "")
            else:
                scan_text = raw

            matches = run_all(scan_text)
            if not matches:
                continue

            log_level = _extract_log_level(raw, obj)
            source = trace_line(raw)

            for m in matches:
                s = score(m.pii_type, log_level)
                yield Finding(
                    match=m,
                    log_level=log_level,
                    severity_score=s,
                    severity=classify(s),
                    pdpa_tag=PDPA_TAG.get(m.pii_type, "PDPA-S9"),
                    raw_line=raw,
                    log_path=path,
                    log_line_no=lineno,
                    source_ref=source,
                )


def scan_file(path: Path) -> list[Finding]:
    """Scan a single log file and return all PII findings."""
    return list(_iter_findings(path))


# ---------------------------------------------------------------------------
# Directory scanner — parallel across files
# ---------------------------------------------------------------------------

def scan_dir(
    root: Path,
    pattern: str = "**/*.jsonl",
    *,
    max_workers: int = 4,
) -> list[Finding]:
    """Scan all log files under *root* matching *pattern* in parallel.

    Each file is processed in its own thread so large directories don't block
    on I/O.  Results are returned in deterministic file-name order.
    """
    log_files = sorted(root.glob(pattern))
    if not log_files:
        return []

    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(scan_file, f): f for f in log_files}
        # Collect in submission order to keep output deterministic
        for f in log_files:
            future = next(fut for fut, path in futures.items() if path == f)
            findings.extend(future.result())
    return findings


# ---------------------------------------------------------------------------
# Source-code scanner
# ---------------------------------------------------------------------------

def scan_source(root: Path, pattern: str = "**/*.py") -> list[Finding]:
    """Scan Python source files under *root* for hard-coded PII values.

    Returns findings whose ``log_path`` is the source file and whose
    ``source_ref`` points at the offending line within that same file.
    """
    findings: list[Finding] = []
    for src_file in sorted(root.glob(pattern)):
        try:
            fh = src_file.open(encoding="utf-8", errors="replace")
        except OSError:
            continue
        with fh:
            for lineno, raw in enumerate(fh, start=1):
                raw = raw.rstrip("\n\r")
                matches = run_all(raw)
                if not matches:
                    continue
                source = SourceRef(str(src_file), lineno, raw.strip())
                for m in matches:
                    s = score(m.pii_type, "INFO")
                    findings.append(Finding(
                        match=m,
                        log_level="SOURCE",
                        severity_score=s,
                        severity=classify(s),
                        pdpa_tag=PDPA_TAG.get(m.pii_type, "PDPA-S9"),
                        raw_line=raw,
                        log_path=src_file,
                        log_line_no=lineno,
                        source_ref=source,
                    ))
    return findings
