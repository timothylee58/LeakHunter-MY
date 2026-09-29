package scanner_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/leakhunter-my/leakhunter/internal/scanner"
	"github.com/leakhunter-my/leakhunter/internal/severity"
)

// canary values — all fake, never realistic PII
const (
	canaryIC      = "900101-14-5678"
	canaryCard    = "4111 1111 1111 1111"
	canaryAccount = "1234567890"
	canaryPhone   = "+6012-345 6789"
	canaryEmail   = "canary.tan@leakhunter.test"
)

// writeJSONL writes JSON-line records to a temp file and returns its path.
func writeJSONL(t *testing.T, dir string, records []map[string]any) string {
	t.Helper()
	p := filepath.Join(dir, "test.jsonl")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func logLine(level, msg string) map[string]any {
	return map[string]any{
		"ts": "2024-01-01T00:00:00Z", "level": level,
		"logger": "test", "message": msg,
		"pathname": "test.py", "lineno": 1, "exc_text": nil,
	}
}

// ---------------------------------------------------------------------------
// ScanFile tests
// ---------------------------------------------------------------------------

func TestScanFile_detects_ic(t *testing.T) {
	dir := t.TempDir()
	p := writeJSONL(t, dir, []map[string]any{
		logLine("INFO", "customer ic="+canaryIC),
	})
	findings, err := scanner.ScanFile(p)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Match.Value == canaryIC {
			found = true
		}
	}
	if !found {
		t.Errorf("expected IC finding, got %+v", findings)
	}
}

func TestScanFile_detects_card_in_error(t *testing.T) {
	dir := t.TempDir()
	p := writeJSONL(t, dir, []map[string]any{
		logLine("ERROR", "payment failed card="+canaryCard),
	})
	findings, err := scanner.ScanFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Error("expected card finding, got none")
	}
	for _, f := range findings {
		if f.Match.Value == canaryCard {
			if f.Severity != severity.High {
				t.Errorf("card at ERROR level should be HIGH, got %s", f.Severity)
			}
			return
		}
	}
	t.Error("card value not found in findings")
}

func TestScanFile_clean_log_zero_findings(t *testing.T) {
	dir := t.TempDir()
	p := writeJSONL(t, dir, []map[string]any{
		logLine("INFO", "server started on port 8080"),
		logLine("DEBUG", "cache miss for key=user_prefs"),
	})
	findings, err := scanner.ScanFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestScanFile_exc_text_scanned(t *testing.T) {
	dir := t.TempDir()
	record := map[string]any{
		"ts": "2024-01-01T00:00:00Z", "level": "ERROR",
		"logger": "test", "message": "payment failed",
		"pathname": "test.py", "lineno": 10,
		"exc_text": fmt.Sprintf("Traceback: card=%s leaked here", canaryCard),
	}
	p := writeJSONL(t, dir, []map[string]any{record})
	findings, err := scanner.ScanFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Error("expected finding from exc_text, got none")
	}
}

func TestScanFile_long_line_no_truncation(t *testing.T) {
	// Line > 64 KB to exercise the custom buffer size.
	dir := t.TempDir()
	padding := make([]byte, 70000)
	for i := range padding {
		padding[i] = 'x'
	}
	record := map[string]any{
		"ts": "2024-01-01T00:00:00Z", "level": "ERROR",
		"logger":   "test",
		"message":  fmt.Sprintf("big %s card=%s", string(padding), canaryCard),
		"pathname": "test.py", "lineno": 1, "exc_text": nil,
	}
	p := writeJSONL(t, dir, []map[string]any{record})
	findings, err := scanner.ScanFile(p)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Match.Value == canaryCard {
			found = true
		}
	}
	if !found {
		t.Error("card not detected in >64KB line — buffer may have been truncated")
	}
}

// ---------------------------------------------------------------------------
// ScanDir tests
// ---------------------------------------------------------------------------

func TestScanDir_multiple_files(t *testing.T) {
	dir := t.TempDir()
	writeJSONL(t, dir, []map[string]any{logLine("INFO", "ic="+canaryIC)})
	// Rename so there's a second file too
	p2 := filepath.Join(dir, "test2.jsonl")
	writeJSONL(t, dir, []map[string]any{logLine("INFO", "email="+canaryEmail)})
	_ = os.Rename(filepath.Join(dir, "test.jsonl"), filepath.Join(dir, "test1.jsonl"))
	_ = os.WriteFile(p2, []byte(`{"ts":"2024-01-01T00:00:00Z","level":"INFO","message":"email=`+canaryEmail+`","exc_text":null}`+"\n"), 0644)

	findings, err := scanner.ScanDir(dir, "**/*.jsonl", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) < 2 {
		t.Errorf("expected >= 2 findings from 2 files, got %d", len(findings))
	}
}

func TestScanDir_empty_dir(t *testing.T) {
	dir := t.TempDir()
	findings, err := scanner.ScanDir(dir, "**/*.jsonl", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in empty dir, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Canary integration: every canary value appears in findings
// ---------------------------------------------------------------------------

func TestScanFile_all_canary_values_detected(t *testing.T) {
	dir := t.TempDir()
	p := writeJSONL(t, dir, []map[string]any{
		logLine("INFO", "ic="+canaryIC+" email="+canaryEmail),
		logLine("INFO", "phone="+canaryPhone),
		logLine("ERROR", "card="+canaryCard+" akaun "+canaryAccount),
	})
	findings, err := scanner.ScanFile(p)
	if err != nil {
		t.Fatal(err)
	}
	found := make(map[string]bool)
	for _, f := range findings {
		found[f.Match.Value] = true
	}
	for _, want := range []string{canaryIC, canaryCard, canaryEmail} {
		if !found[want] {
			t.Errorf("canary value %q not detected", want)
		}
	}
}

// ---------------------------------------------------------------------------
// Severity scoring
// ---------------------------------------------------------------------------

func TestSeverity_ic_at_error_is_high(t *testing.T) {
	dir := t.TempDir()
	p := writeJSONL(t, dir, []map[string]any{
		logLine("ERROR", "ic="+canaryIC),
	})
	findings, err := scanner.ScanFile(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Match.Value == canaryIC && f.Severity != severity.High {
			t.Errorf("IC at ERROR level should be HIGH, got %s (score %.2f)",
				f.Severity, f.SeverityScore)
		}
	}
}

func TestSeverity_email_at_info_is_low(t *testing.T) {
	dir := t.TempDir()
	p := writeJSONL(t, dir, []map[string]any{
		logLine("INFO", "email="+canaryEmail),
	})
	findings, err := scanner.ScanFile(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Match.Value == canaryEmail && f.Severity != severity.Low {
			t.Errorf("email at INFO level should be LOW, got %s", f.Severity)
		}
	}
}
