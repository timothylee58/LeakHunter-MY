"""LeakHunter MY — CLI entry point."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from leakhunter.masking import mask_file
from leakhunter.report import render_console, render_json, render_markdown
from leakhunter.scanner import scan_dir, scan_file, scan_source

app = typer.Typer(
    name="leakhunter",
    help="Find Malaysian PII leaking into application logs.",
    add_completion=False,
)
console = Console()


@app.command()
def scan(
    log_dir: Path = typer.Argument(
        Path("logs"),
        help="Directory (or single file) to scan.",
    ),
    fix: bool = typer.Option(
        False,
        "--fix",
        help="Write .masked copies of every log file that contains PII.",
    ),
    report: Optional[Path] = typer.Option(
        None, "--report", "-r",
        help="Write a JSON report to this path.",
    ),
    receipt_before: Optional[Path] = typer.Option(
        None, "--receipt-before",
        help="Write a Markdown receipt of findings BEFORE masking.",
    ),
    receipt_after: Optional[Path] = typer.Option(
        None, "--receipt-after",
        help="Write a Markdown receipt AFTER masking (should be empty).",
    ),
    pattern: str = typer.Option(
        "**/*.jsonl",
        "--pattern",
        help="Glob pattern for log files when log_dir is a directory.",
    ),
    fail_on_high: bool = typer.Option(
        False, "--fail-on-high",
        help="Exit 1 if any HIGH severity finding exists (CI gate).",
    ),
) -> None:
    """Scan log files for Malaysian PII and report findings."""
    if log_dir.is_file():
        findings = scan_file(log_dir)
    elif log_dir.is_dir():
        findings = scan_dir(log_dir, pattern)
    else:
        console.print(f"[bold red]Path not found:[/bold red] {log_dir}")
        raise typer.Exit(1)

    render_console(findings)

    if report:
        render_json(findings, report)

    if receipt_before:
        render_markdown(findings, receipt_before, title="LeakHunter MY — Before Fix")

    if fix and findings:
        affected = {f.log_path for f in findings}
        for path in sorted(affected):
            out = mask_file(path, findings)
            console.print(f"[green]Masked →[/green] {out}")

        if receipt_after:
            # Re-scan masked copies to produce the "after" receipt
            after_findings: list = []
            for path in sorted(affected):
                masked = path.with_suffix(path.suffix + ".masked")
                if masked.exists():
                    after_findings.extend(scan_file(masked))
            render_markdown(
                after_findings, receipt_after,
                title="LeakHunter MY — After Fix",
            )
    elif receipt_after:
        # --fix not requested: write receipt_after against the same findings
        render_markdown(
            findings, receipt_after,
            title="LeakHunter MY — After Fix (no --fix applied)",
        )

    if fail_on_high and any(f.severity == "HIGH" for f in findings):
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
        render_markdown(findings, receipt, title="LeakHunter MY — Source Scan")
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
