// Package report renders PII findings as console text, JSON, Markdown, and SARIF.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/leakhunter-my/leakhunter/internal/detector"
	"github.com/leakhunter-my/leakhunter/internal/masking"
	"github.com/leakhunter-my/leakhunter/internal/scanner"
	"github.com/leakhunter-my/leakhunter/internal/severity"
)

const pdpaNote = "PDPA 2010 — Security Principle (Section 9): Data processors must take " +
	"practical steps to protect personal data from any loss, misuse, modification, " +
	"unauthorised or accidental access or disclosure, alteration or destruction."

// RenderConsole prints a plain-text summary to w.
func RenderConsole(findings []scanner.Finding, w io.Writer) {
	if len(findings) == 0 {
		fmt.Fprintln(w, "No PII leaks found.")
		return
	}

	sorted := make([]scanner.Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].SeverityScore != sorted[j].SeverityScore {
			return sorted[i].SeverityScore > sorted[j].SeverityScore
		}
		return sorted[i].LogPath < sorted[j].LogPath
	})

	fmt.Fprintf(w, "LeakHunter MY -- %d finding(s)\n", len(findings))
	fmt.Fprintln(w, strings.Repeat("-", 80))
	fmt.Fprintf(w, "%-8s %-14s %-26s %-28s %5s\n",
		"Severity", "Type", "Masked", "File", "Line")
	fmt.Fprintln(w, strings.Repeat("-", 80))
	for _, f := range sorted {
		masked := masking.Mask(f.Match.PiiType, f.Match.Value)
		file := f.LogPath
		if len(file) > 28 {
			file = "..." + file[len(file)-25:]
		}
		fmt.Fprintf(w, "%-8s %-14s %-26s %-28s %5d\n",
			f.Severity, f.Match.PiiType, masked, file, f.LogLineNo)
	}
	fmt.Fprintln(w, strings.Repeat("-", 80))

	var high, med, low int
	for _, f := range findings {
		switch f.Severity {
		case severity.High:
			high++
		case severity.Medium:
			med++
		case severity.Low:
			low++
		}
	}
	fmt.Fprintf(w, "  HIGH %d  MEDIUM %d  LOW %d\n\n", high, med, low)
}

// WriteMarkdown writes a Markdown receipt to path.
func WriteMarkdown(findings []scanner.Finding, path, title string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	now := time.Now().UTC().Format("2006-01-02 15:04 UTC")
	var high, med, low []scanner.Finding
	for _, f := range findings {
		switch f.Severity {
		case severity.High:
			high = append(high, f)
		case severity.Medium:
			med = append(med, f)
		case severity.Low:
			low = append(low, f)
		}
	}

	fmt.Fprintf(f, "# %s\n\n", title)
	fmt.Fprintf(f, "_Generated: %s_\n\n", now)
	fmt.Fprintf(f, "**Total findings:** %d (HIGH %d * MEDIUM %d * LOW %d)\n\n",
		len(findings), len(high), len(med), len(low))

	if len(findings) == 0 {
		fmt.Fprintln(f, "_No PII found. Logs are clean._")
	} else {
		for _, pair := range []struct {
			label string
			group []scanner.Finding
		}{{"HIGH", high}, {"MEDIUM", med}, {"LOW", low}} {
			if len(pair.group) == 0 {
				continue
			}
			fmt.Fprintf(f, "## [%s]\n\n", pair.label)
			fmt.Fprintln(f, "| Type | Masked value | File | Line | Source | PDPA |")
			fmt.Fprintln(f, "|------|--------------|------|------|--------|------|")
			for _, finding := range pair.group {
				source := "unknown"
				if finding.SourceRef != nil {
					source = finding.SourceRef.String()
				}
				masked := strings.ReplaceAll(
					masking.Mask(finding.Match.PiiType, finding.Match.Value), "|", "\\|")
				fmt.Fprintf(f, "| %s | `%s` | %s | %d | `%s` | PDPA 2010 S9 |\n",
					finding.Match.PiiType, masked,
					finding.LogPath, finding.LogLineNo, source)
			}
			fmt.Fprintln(f)
		}
	}
	fmt.Fprintf(f, "---\n\n%s\n", pdpaNote)
	return nil
}

// WriteJSON writes a machine-readable JSON report to path.
func WriteJSON(findings []scanner.Finding, path string) error {
	type record struct {
		Severity      string `json:"severity"`
		SeverityScore float64 `json:"severity_score"`
		PiiType       string `json:"pii_type"`
		MaskedValue   string `json:"masked_value"`
		LogFile       string `json:"log_file"`
		LogLine       int    `json:"log_line"`
		LogLevel      string `json:"log_level"`
		SourceRef     string `json:"source_ref,omitempty"`
		PDPATag       string `json:"pdpa_tag"`
	}
	records := make([]record, len(findings))
	for i, f := range findings {
		sr := ""
		if f.SourceRef != nil {
			sr = f.SourceRef.String()
		}
		records[i] = record{
			Severity:      string(f.Severity),
			SeverityScore: f.SeverityScore,
			PiiType:       string(f.Match.PiiType),
			MaskedValue:   masking.Mask(f.Match.PiiType, f.Match.Value),
			LogFile:       f.LogPath,
			LogLine:       f.LogLineNo,
			LogLevel:      f.LogLevel,
			SourceRef:     sr,
			PDPATag:       f.PDPATag,
		}
	}
	payload := map[string]any{
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
		"total_findings": len(findings),
		"findings":       records,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// ---------------------------------------------------------------------------
// SARIF v2.1.0
// ---------------------------------------------------------------------------

var sarifRules = []map[string]any{
	sarifRule("LH001", "MyKadIcLeak", "Malaysian IC number in log output",
		"A Malaysian Identity Card (MyKad) number was detected. PDPA 2010 Section 9."),
	sarifRule("LH002", "PaymentCardLeak", "Payment card number in log output",
		"A payment card number (Luhn-valid) was detected. PCI-DSS + PDPA 2010 Section 9."),
	sarifRule("LH003", "BankAccountLeak", "Bank account number in log output",
		"A bank account number was detected near a banking keyword. PDPA 2010 Section 9."),
	sarifRule("LH004", "MobileNumberLeak", "Malaysian mobile number in log output",
		"A Malaysian mobile number (+60 / 01X prefix) was detected. PDPA 2010 Section 7."),
	sarifRule("LH005", "EmailAddressLeak", "Email address in log output",
		"An email address was detected. PDPA 2010 Section 7."),
}

var sarifRuleID = map[detector.PiiType]string{
	detector.PiiMyKad:       "LH001",
	detector.PiiPaymentCard: "LH002",
	detector.PiiBankAccount: "LH003",
	detector.PiiPhone:       "LH004",
	detector.PiiEmail:       "LH005",
}

var sarifLevel = map[severity.Label]string{
	severity.High:   "error",
	severity.Medium: "warning",
	severity.Low:    "note",
}

func sarifRule(id, name, short, full string) map[string]any {
	return map[string]any{
		"id":               id,
		"name":             name,
		"shortDescription": map[string]any{"text": short},
		"fullDescription":  map[string]any{"text": full},
		"helpUri":          "https://github.com/leakhunter-my/leakhunter",
		"properties":       map[string]any{"tags": []string{"security", "pii", "pdpa"}},
	}
}

// WriteSARIF writes a SARIF v2.1.0 report to path.
func WriteSARIF(findings []scanner.Finding, path string) error {
	results := make([]map[string]any, len(findings))
	for i, f := range findings {
		masked := masking.Mask(f.Match.PiiType, f.Match.Value)
		ruleID := sarifRuleID[f.Match.PiiType]
		if ruleID == "" {
			ruleID = "LH001"
		}
		level := sarifLevel[f.Severity]
		if level == "" {
			level = "warning"
		}
		uri := f.LogPath
		lineNo := f.LogLineNo
		if f.SourceRef != nil {
			uri = f.SourceRef.Pathname
			lineNo = f.SourceRef.Lineno
		}
		results[i] = map[string]any{
			"ruleId": ruleID,
			"level":  level,
			"message": map[string]any{
				"text": fmt.Sprintf("%s detected (%s). Severity: %s. %s.",
					f.Match.PiiType, masked, f.Severity, f.PDPATag),
			},
			"locations": []map[string]any{
				{
					"physicalLocation": map[string]any{
						"artifactLocation": map[string]any{
							"uri":       uri,
							"uriBaseId": "%SRCROOT%",
						},
						"region": map[string]any{"startLine": lineNo},
					},
				},
			},
		}
	}

	payload := map[string]any{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{
			{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":           "leakhunter-my",
						"version":        "0.1.0",
						"informationUri": "https://github.com/leakhunter-my/leakhunter",
						"rules":          sarifRules,
					},
				},
				"results": results,
				"invocations": []map[string]any{
					{
						"executionSuccessful": true,
						"endTimeUtc":          time.Now().UTC().Format(time.RFC3339),
					},
				},
			},
		},
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
