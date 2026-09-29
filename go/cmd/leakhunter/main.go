// LeakHunter MY — Go CLI entry point.
//
// Usage:
//
//	leakhunter scan <path> [--logs <dir>] [--fail-on high|medium|low]
//	                       [--receipt <path>] [--format sarif|json] [--output <path>]
//	leakhunter source <dir>
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/leakhunter-my/leakhunter/internal/report"
	"github.com/leakhunter-my/leakhunter/internal/scanner"
	"github.com/leakhunter-my/leakhunter/internal/severity"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "scan":
		cmdScan(os.Args[2:])
	case "source":
		cmdSource(os.Args[2:])
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `LeakHunter MY — find Malaysian PII leaking into application logs.

Commands:
  scan   <path>  Scan log directory (*.jsonl) or a single log file.
  source <dir>   Scan Python source files for hard-coded PII.

scan flags:
  --logs    <dir>          Additional log directory to scan.
  --fail-on high|medium|low  Exit 1 if any finding >= severity.
  --receipt <path>         Write a Markdown receipt.
  --format  sarif|json     Output format for --output.
  --output  <path>         Write structured report (JSON or SARIF).
  --workers <n>            Worker goroutines (default 4).`)
}

// ---------------------------------------------------------------------------
// scan subcommand
// ---------------------------------------------------------------------------

func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	logs := fs.String("logs", "", "additional log directory")
	failOn := fs.String("fail-on", "", "fail on severity: high|medium|low")
	receipt := fs.String("receipt", "", "write markdown receipt to path")
	format := fs.String("format", "json", "output format: json|sarif")
	output := fs.String("output", "", "write structured report to path")
	workers := fs.Int("workers", scanner.DefaultWorkers, "parallel workers")

	// Go's flag package stops at the first non-flag arg.  We support both
	// "scan <path> --flag" and "scan --flag <path>" by re-parsing the
	// remainder after extracting the positional argument.
	var scanPath string
	remaining := args
	for i, a := range args {
		if !strings.HasPrefix(a, "-") {
			scanPath = a
			remaining = append(append([]string{}, args[:i]...), args[i+1:]...)
			break
		}
	}
	if scanPath == "" {
		fmt.Fprintln(os.Stderr, "scan requires a path argument")
		os.Exit(1)
	}
	_ = fs.Parse(remaining)

	var findings []scanner.Finding

	info, err := os.Stat(scanPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "path not found: %s\n", scanPath)
		os.Exit(1)
	}
	if info.IsDir() {
		fs2, err := scanner.ScanDir(scanPath, "**/*.jsonl", *workers)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
			os.Exit(1)
		}
		findings = append(findings, fs2...)
	} else {
		fs2, err := scanner.ScanFile(scanPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
			os.Exit(1)
		}
		findings = append(findings, fs2...)
	}

	if *logs != "" {
		fs2, err := scanner.ScanDir(*logs, "**/*.jsonl", *workers)
		if err != nil {
			fmt.Fprintf(os.Stderr, "logs scan error: %v\n", err)
		} else {
			findings = append(findings, fs2...)
		}
	}

	report.RenderConsole(findings, os.Stdout)

	if *receipt != "" {
		if err := report.WriteMarkdown(findings, *receipt,
			"LeakHunter MY — Scan Receipt"); err != nil {
			fmt.Fprintf(os.Stderr, "receipt error: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Receipt -> %s\n", *receipt)
		}
	}

	if *output != "" {
		var writeErr error
		if strings.ToLower(*format) == "sarif" {
			writeErr = report.WriteSARIF(findings, *output)
			fmt.Fprintf(os.Stderr, "SARIF report -> %s\n", *output)
		} else {
			writeErr = report.WriteJSON(findings, *output)
			fmt.Fprintf(os.Stderr, "JSON report -> %s\n", *output)
		}
		if writeErr != nil {
			fmt.Fprintf(os.Stderr, "output error: %v\n", writeErr)
		}
	}

	applyFailOn(*failOn, findings)
}

// ---------------------------------------------------------------------------
// source subcommand
// ---------------------------------------------------------------------------

func cmdSource(args []string) {
	fs := flag.NewFlagSet("source", flag.ExitOnError)
	failOnHigh := fs.Bool("fail-on-high", false, "exit 1 if any HIGH finding")
	receipt := fs.String("receipt", "", "write markdown receipt to path")
	_ = fs.Parse(args)

	srcDir := "."
	if fs.NArg() > 0 {
		srcDir = fs.Arg(0)
	}

	findings, err := scanner.ScanSource(srcDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "source scan error: %v\n", err)
		os.Exit(1)
	}

	report.RenderConsole(findings, os.Stdout)

	if *receipt != "" {
		if err := report.WriteMarkdown(findings, *receipt,
			"LeakHunter MY — Source Scan"); err != nil {
			fmt.Fprintf(os.Stderr, "receipt error: %v\n", err)
		}
	}

	if *failOnHigh {
		for _, f := range findings {
			if f.Severity == severity.High {
				os.Exit(1)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

func applyFailOn(threshold string, findings []scanner.Finding) {
	t := strings.ToLower(threshold)
	if t == "" {
		return
	}
	levels := map[string]bool{"high": true}
	if t == "medium" || t == "low" {
		levels["medium"] = true
	}
	if t == "low" {
		levels["low"] = true
	}
	for _, f := range findings {
		if levels[strings.ToLower(string(f.Severity))] {
			os.Exit(1)
		}
	}
}
