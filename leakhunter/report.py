"""Console, JSON, and Markdown reporting for PII findings."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box

from leakhunter.scanner import Finding
from leakhunter.masking import mask as mask_value

console = Console()

_SEVERITY_COLOUR = {
    "HIGH":   "bold red",
    "MEDIUM": "yellow",
    "LOW":    "cyan",
}

_PDPA_NOTE = (
    "**PDPA 2010 — Security Principle (Section 9)**\n"
    "Data processors must take practical steps to protect personal data from "
    "any loss, misuse, modification, unauthorised or accidental access or "
    "disclosure, alteration or destruction.  Each finding above represents a "
    "potential breach of this obligation."
)


def render_console(findings: list[Finding]) -> None:
    """Print a Rich summary table to stdout."""
    if not findings:
        console.print("[bold green]No PII leaks found.[/bold green]")
        return

    table = Table(
        title=f"LeakHunter MY — {len(findings)} finding(s)",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("Severity",   style="bold", width=8)
    table.add_column("Type",       width=14)
    table.add_column("Masked",     width=24)
    table.add_column("File",       width=28)
    table.add_column("Line",       width=6,  justify="right")
    table.add_column("Source Ref", width=32)
    table.add_column("PDPA",       width=16)

    for f in sorted(findings, key=lambda x: (-x.severity_score, str(x.log_path))):
        colour = _SEVERITY_COLOUR.get(f.severity, "white")
        source = str(f.source_ref) if f.source_ref else "unknown"
        masked = mask_value(f.match.pii_type, f.match.value)
        table.add_row(
            f"[{colour}]{f.severity}[/{colour}]",
            f.match.pii_type,
            f"[dim]{masked}[/dim]",
            f.log_path.name,
            str(f.log_line_no),
            source,
            "[dim]PDPA 2010[/dim]",
        )

    console.print(table)

    high = sum(1 for f in findings if f.severity == "HIGH")
    med  = sum(1 for f in findings if f.severity == "MEDIUM")
    low  = sum(1 for f in findings if f.severity == "LOW")
    console.print(
        f"\n  HIGH [bold red]{high}[/bold red]  "
        f"MEDIUM [yellow]{med}[/yellow]  "
        f"LOW [cyan]{low}[/cyan]\n"
    )


def render_json(findings: list[Finding], out: Path) -> None:
    """Write a machine-readable JSON report to *out*."""
    out.parent.mkdir(parents=True, exist_ok=True)
    records = [_finding_to_dict(f) for f in findings]
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "findings": records,
    }
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"[dim]JSON report written -> {out}[/dim]")


def write_receipt(
    findings: list[Finding],
    path: Path,
    title: str = "LeakHunter MY — PII Receipt",
) -> None:
    """Write a Markdown receipt to *path*.

    The receipt contains:
    - Timestamp and finding totals by severity
    - A table of findings showing **masked values only** (never raw PII)
    - Source snippets grouped by severity
    - A PDPA 2010 Security Principle note
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    high   = [f for f in findings if f.severity == "HIGH"]
    medium = [f for f in findings if f.severity == "MEDIUM"]
    low    = [f for f in findings if f.severity == "LOW"]

    lines: list[str] = [
        f"# {title}",
        "",
        f"_Generated: {now}_",
        "",
        f"**Total findings:** {len(findings)} "
        f"(HIGH {len(high)} · MEDIUM {len(medium)} · LOW {len(low)})",
        "",
    ]

    if not findings:
        lines += ["_No PII found. Logs are clean._", ""]
    else:
        for label, group in (("[HIGH]", high), ("[MEDIUM]", medium), ("[LOW]", low)):
            if not group:
                continue
            lines += [f"## {label}", ""]
            lines += [
                "| Type | Masked value | File | Line | Source | PDPA |",
                "|------|--------------|------|------|--------|------|",
            ]
            for f in group:
                source = str(f.source_ref) if f.source_ref else "—"
                masked = mask_value(f.match.pii_type, f.match.value).replace("|", "\\|")
                lines.append(
                    f"| {f.match.pii_type} | `{masked}` | {f.log_path.name} "
                    f"| {f.log_line_no} | `{source}` | PDPA 2010 S9 |"
                )
            lines.append("")

            # Source snippets
            seen: set[str] = set()
            snippet_lines: list[str] = []
            for f in group:
                if f.source_ref and f.source_ref.snippet:
                    key = str(f.source_ref)
                    if key not in seen:
                        seen.add(key)
                        snippet_lines += [
                            f"**`{f.source_ref}`**",
                            "```python",
                            f.source_ref.snippet,
                            "```",
                            "",
                        ]
            if snippet_lines:
                lines += ["### Source snippets", ""] + snippet_lines

    lines += [
        "---",
        "",
        _PDPA_NOTE,
        "",
    ]

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    console.print(f"[dim]Receipt -> {path}[/dim]")


# Alias so existing code using render_markdown continues to work
def render_markdown(
    findings: list[Finding],
    out: Path,
    title: str = "LeakHunter MY — PII Receipt",
) -> None:
    """Alias for write_receipt — kept for backwards compatibility."""
    write_receipt(findings, out, title)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _finding_to_dict(f: Finding) -> dict:
    masked = mask_value(f.match.pii_type, f.match.value)
    return {
        "severity":       f.severity,
        "severity_score": f.severity_score,
        "pii_type":       f.match.pii_type,
        "masked_value":   masked,
        "log_file":       str(f.log_path),
        "log_line":       f.log_line_no,
        "log_level":      f.log_level,
        "source_ref":     str(f.source_ref) if f.source_ref else None,
        "snippet":        f.source_ref.snippet if f.source_ref else None,
        "pdpa_tag":       f.pdpa_tag,
    }
