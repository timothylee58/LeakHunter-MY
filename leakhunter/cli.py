"""LeakHunter MY — CLI entry point."""
from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from leakhunter.masking import mask_file
from leakhunter.report import render_console, render_json, write_receipt
from leakhunter.scanner import scan_dir, scan_file, scan_source

app = typer.Typer(
    name="leakhunter",
    help="Find Malaysian PII leaking into application logs.",
    add_completion=False,
)
console = Console()

_FAIL_LEVELS = {"high", "medium", "low"}


@app.command()
def scan(
    path: Path = typer.Argument(
        ...,
        help="Directory or file to scan (source code or log files).",
    ),
    logs: Optional[Path] = typer.Option(
        None, "--logs",
        help="Also scan this log directory (*.jsonl) in addition to PATH.",
    ),
    receipt: Optional[Path] = typer.Option(
        None, "--receipt",
        help="Write a Markdown receipt to this path (e.g. reports/receipt_before.md).",
    ),
    report: Optional[Path] = typer.Option(
        None, "--report", "-r",
        help="Write a JSON report to this path.",
    ),
    fail_on: Optional[str] = typer.Option(
        None, "--fail-on",
        help="Exit 1 if any finding >= this severity: high|medium|low.",
    ),
    # Legacy options kept for backwards compatibility
    fix: bool = typer.Option(False, "--fix", hidden=True),
    receipt_before: Optional[Path] = typer.Option(None, "--receipt-before", hidden=True),
    receipt_after: Optional[Path] = typer.Option(None, "--receipt-after", hidden=True),
    pattern: str = typer.Option("**/*.jsonl", "--pattern", hidden=True),
    fail_on_high: bool = typer.Option(False, "--fail-on-high", hidden=True),
) -> None:
    """Scan source code and/or log files for Malaysian PII leaks."""
    findings: list = []

    # Source scan when PATH is a directory of .py files
    if path.is_dir():
        findings.extend(scan_source(path))
    elif path.is_file():
        findings.extend(scan_file(path))
    else:
        console.print(f"[bold red]Path not found:[/bold red] {path}")
        raise typer.Exit(1)

    # Optional separate log directory scan
    if logs:
        if logs.is_dir():
            findings.extend(scan_dir(logs, pattern))
        elif logs.is_file():
            findings.extend(scan_file(logs))

    # Legacy log-dir scan (path used to default to "logs")
    if not path.is_dir() and not logs:
        pass  # already handled above

    render_console(findings)

    if report:
        render_json(findings, report)

    if receipt or receipt_before:
        write_receipt(findings, receipt or receipt_before,  # type: ignore[arg-type]
                      title="LeakHunter MY — Scan Receipt")

    if fix and findings:
        affected = {f.log_path for f in findings}
        for p in sorted(affected):
            out = mask_file(p, findings)
            console.print(f"[green]Masked ->[/green] {out}")
        if receipt_after:
            after: list = []
            for p in sorted(affected):
                masked = p.with_suffix(p.suffix + ".masked")
                if masked.exists():
                    after.extend(scan_file(masked))
            write_receipt(after, receipt_after, title="LeakHunter MY — After Fix")
    elif receipt_after:
        write_receipt(findings, receipt_after,
                      title="LeakHunter MY — After Fix (no --fix)")

    # Unified --fail-on + legacy --fail-on-high
    threshold = (fail_on or "").lower()
    if fail_on_high:
        threshold = "high"
    if threshold in _FAIL_LEVELS:
        levels_to_fail = {"high"}
        if threshold in ("medium", "low"):
            levels_to_fail.add("medium")
        if threshold == "low":
            levels_to_fail.add("low")
        if any(f.severity.lower() in levels_to_fail for f in findings):
            raise typer.Exit(1)


@app.command()
def source(
    src_dir: Path = typer.Argument(
        Path("."),
        help="Directory to scan for hard-coded PII in Python source files.",
    ),
    report: Optional[Path] = typer.Option(
        None, "--report", "-r",
        help="Write a JSON report to this path.",
    ),
    receipt: Optional[Path] = typer.Option(
        None, "--receipt",
        help="Write a Markdown receipt to this path.",
    ),
    fail_on_high: bool = typer.Option(
        False, "--fail-on-high",
        help="Exit 1 if any HIGH severity finding exists.",
    ),
) -> None:
    """Scan Python source files for hard-coded PII values."""
    findings = scan_source(src_dir)
    render_console(findings)
    if report:
        render_json(findings, report)
    if receipt:
        write_receipt(findings, receipt, title="LeakHunter MY — Source Scan")
    if fail_on_high and any(f.severity == "HIGH" for f in findings):
        raise typer.Exit(1)


@app.command()
def demo() -> None:
    """Run a quick self-contained demo scan against the bundled sample logs."""
    sample_logs = Path(__file__).parent.parent / "logs"
    if not sample_logs.exists():
        console.print(
            "[yellow]No logs/ directory found. "
            "Run the sample app first:[/yellow]\n"
            "  python -m sample_app.payments"
        )
        raise typer.Exit(1)

    console.print("[bold]LeakHunter MY — demo scan[/bold]\n")
    findings = scan_dir(sample_logs)
    render_console(findings)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
