"""Scan log files for PII findings."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from leakhunter.detectors import Match, run_all
from leakhunter.severity import PDPA_TAG, SeverityLabel, classify, score
from leakhunter.tracer import SourceRef, trace_line


@dataclass(slots=True)
class Finding:
    """One PII occurrence discovered in a log file."""
    match: Match
    log_level: str
    severity_score: float
    severity: SeverityLabel
    pdpa_tag: str
    raw_line: str
    log_path: Path
    log_line_no: int               # 1-based line number in the log file
    source_ref: SourceRef | None   # traced back to app source, if available


def _extract_log_level(line: str) -> str:
    """Best-effort extraction of log level from a raw log line."""
    # Try JSON first
    try:
        obj = json.loads(line)
        for key in ("level", "levelname", "severity", "log_level"):
            if key in obj:
                return str(obj[key]).upper()
    except (json.JSONDecodeError, ValueError):
        pass
    # Fall back to plain-text heuristics
    for token in ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"):
        if token in line.upper():
            return token
    return "UNKNOWN"


def scan_file(path: Path) -> list[Finding]:
    """Scan a single log file and return all PII findings."""
    findings: list[Finding] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return findings

    for lineno, raw in enumerate(lines, start=1):
        matches = run_all(raw)
        if not matches:
            continue
        log_level = _extract_log_level(raw)
        source = trace_line(raw)
        for m in matches:
            s = score(m.pii_type, log_level)
            findings.append(Finding(
                match=m,
                log_level=log_level,
                severity_score=s,
                severity=classify(s),
                pdpa_tag=PDPA_TAG.get(m.pii_type, "PDPA-S9"),
                raw_line=raw,
                log_path=path,
                log_line_no=lineno,
                source_ref=source,
            ))
    return findings


def scan_dir(root: Path, pattern: str = "**/*.jsonl") -> list[Finding]:
    """Recursively scan all log files under *root* matching *pattern*."""
    findings: list[Finding] = []
    for log_file in sorted(root.glob(pattern)):
        findings.extend(scan_file(log_file))
    return findings


def scan_source(root: Path, pattern: str = "**/*.py") -> list[Finding]:
    """Scan Python source files under *root* for hard-coded PII values.

    Returns findings whose ``log_path`` is the source file and whose
    ``source_ref`` points at the offending line within that same file.
    """
    findings: list[Finding] = []
    for src_file in sorted(root.glob(pattern)):
        try:
            lines = src_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for lineno, raw in enumerate(lines, start=1):
            matches = run_all(raw)
            if not matches:
                continue
            from leakhunter.tracer import SourceRef
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
