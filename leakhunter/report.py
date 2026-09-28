"""Console, JSON, and Markdown reporting for PII findings."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box

from leakhunter.scanner import Finding

console = Console()

_SEVERITY_COLOUR = {
    "HIGH":   "bold red",
    "MEDIUM": "yellow",
    "LOW":    "cyan",
}


def render_console(findings: list[Finding]) -> None:
    """Print a Rich summary table to stdout."""
    if not findings:
        console.print("[bold green]✓ No PII leaks found.[/bold green]")
        return

    table = Table(
        title=f"LeakHunter MY — {len(findings)} finding(s)",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("Severity",   style="bold", width=8)
    table.add_column("Type",       width=14)
    table.add_column("Value",      width=24)
    table.add_column("Log File",   width=28)
    table.add_column("Log Line",   width=8,  justify="right")
    table.add_column("Source Ref", width=30)
    table.add_column("PDPA Tag",   width=50)

    for f in sorted(findings, key=lambda x: (-x.severity_score, str(x.log_path))):
        colour = _SEVERITY_COLOUR.get(f.severity, "white")
        source = str(f.source_ref) if f.source_ref else "unknown"
        table.add_row(
            f"[{colour}]{f.severity}[/{colour}]",
            f.match.pii_type,
            f"[dim]{f.match.value[:22]}[/dim]",
            f.log_path.name,
            str(f.log_line_no),
            source,
            f"[dim]{f.pdpa_tag}[/dim]",
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
    console.print(f"[dim]JSON report written → {out}[/dim]")


def render_markdown(findings: list[Finding], out: Path, title: str = "LeakHunter MY — PII Receipt") -> None:
    """Write a Markdown receipt to *out* (e.g. reports/receipt_before.md).

    The receipt lists every finding grouped by severity with source snippet.
    Suitable as a before/after diff artefact for demo purposes.
    """
    out.parent.mkdir(parents=True, exist_ok=True)

    high   = [f for f in findings if f.severity == "HIGH"]
    medium = [f for f in findings if f.severity == "MEDIUM"]
    low    = [f for f in findings if f.severity == "LOW"]

    lines: list[str] = [
        f"# {title}",
        "",
        f"_Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_",
        "",
        f"**Total findings:** {len(findings)} "
        f"(HIGH {len(high)} · MEDIUM {len(medium)} · LOW {len(low)})",
        "",
    ]

    for label, group in (("🔴 HIGH", high), ("🟡 MEDIUM", medium), ("🔵 LOW", low)):
        if not group:
            continue
        lines += [f"## {label}", ""]
        lines += ["| Type | Value | Log File | Line | Source | PDPA |",
                  "|------|-------|----------|------|--------|------|"]
        for f in group:
            source = str(f.source_ref) if f.source_ref else "—"
            snippet = f.source_ref.snippet if f.source_ref and f.source_ref.snippet else ""
            val = f.match.value.replace("|", "\\|")
            lines.append(
                f"| {f.match.pii_type} | `{val}` | {f.log_path.name} "
                f"| {f.log_line_no} | `{source}` | {f.pdpa_tag} |"
            )
        lines.append("")
        # Source snippets sub-section
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

    if not findings:
        lines += ["_No PII found. Logs are clean._", ""]

    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    console.print(f"[dim]Markdown receipt → {out}[/dim]")


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _finding_to_dict(f: Finding) -> dict:
    return {
        "severity":       f.severity,
        "severity_score": f.severity_score,
        "pii_type":       f.match.pii_type,
        "value":          f.match.value,
        "log_file":       str(f.log_path),
        "log_line":       f.log_line_no,
        "log_level":      f.log_level,
        "source_ref":     str(f.source_ref) if f.source_ref else None,
        "snippet":        f.source_ref.snippet if f.source_ref else None,
        "pdpa_tag":       f.pdpa_tag,
    }
