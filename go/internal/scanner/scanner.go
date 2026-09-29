// Package scanner streams log files and source files for PII findings.
//
// bufio.Scanner default max line size is 64 KB; long exception stack traces
// will silently truncate unless the buffer is enlarged.  We set 1 MiB.
//
// Parallelism: a fixed-size goroutine worker pool processes one file per job.
// Results are gathered from a channel and sorted by (filepath, line number)
// for deterministic output.
package scanner

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/leakhunter-my/leakhunter/internal/detector"
	"github.com/leakhunter-my/leakhunter/internal/severity"
	"github.com/leakhunter-my/leakhunter/internal/tracer"
)

const (
	// scanBufSize is the per-line buffer size for bufio.Scanner.
	// 64 KB default is too small for exception traces; 1 MiB covers real-world logs.
	scanBufSize = 1 << 20 // 1 MiB
	// DefaultWorkers is the default goroutine pool size for parallel directory scans.
	DefaultWorkers = 4
)

// Finding represents one PII occurrence discovered in a log or source file.
type Finding struct {
	Match         detector.Match
	LogLevel      string
	SeverityScore float64
	Severity      severity.Label
	PDPATag       string
	RawLine       string
	LogPath       string
	LogLineNo     int // 1-based
	SourceRef     *tracer.SourceRef
}

// ---------------------------------------------------------------------------
// Log-level extraction
// ---------------------------------------------------------------------------

func extractLogLevel(rawLine string, obj map[string]any) string {
	if obj != nil {
		for _, key := range []string{"level", "levelname", "severity", "log_level"} {
			if v, ok := obj[key]; ok {
				if s, ok := v.(string); ok {
					return strings.ToUpper(s)
				}
			}
		}
	}
	upper := strings.ToUpper(rawLine)
	for _, tok := range []string{"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"} {
		if strings.Contains(upper, tok) {
			return tok
		}
	}
	return "UNKNOWN"
}

// ---------------------------------------------------------------------------
// Single-file streaming scanner
// ---------------------------------------------------------------------------

// ScanFile scans a single log file and returns all PII findings.
func ScanFile(path string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, scanBufSize), scanBufSize)

	var findings []Finding
	lineno := 0

	for sc.Scan() {
		lineno++
		raw := sc.Text()
		if raw == "" {
			continue
		}

		// Attempt JSON parse for log-level extraction and source tracing.
		var obj map[string]any
		if err := json.Unmarshal([]byte(raw), &obj); err == nil {
			// Scan message + exc_text fields; PII lives in log message, not JSON keys.
			msg, _ := obj["message"].(string)
			exc, _ := obj["exc_text"].(string)
			scanText := msg + " " + exc
			matches := detector.RunAll(scanText)
			if len(matches) == 0 {
				continue
			}
			level := extractLogLevel(raw, obj)
			src := tracer.TraceLine(raw)
			for _, m := range matches {
				s := severity.Score(m.PiiType, level)
				findings = append(findings, Finding{
					Match:         m,
					LogLevel:      level,
					SeverityScore: s,
					Severity:      severity.Classify(s),
					PDPATag:       severity.PDPATag[m.PiiType],
					RawLine:       raw,
					LogPath:       path,
					LogLineNo:     lineno,
					SourceRef:     src,
				})
			}
		} else {
			// Plain text log line.
			matches := detector.RunAll(raw)
			if len(matches) == 0 {
				continue
			}
			level := extractLogLevel(raw, nil)
			for _, m := range matches {
				s := severity.Score(m.PiiType, level)
				findings = append(findings, Finding{
					Match:         m,
					LogLevel:      level,
					SeverityScore: s,
					Severity:      severity.Classify(s),
					PDPATag:       severity.PDPATag[m.PiiType],
					RawLine:       raw,
					LogPath:       path,
					LogLineNo:     lineno,
				})
			}
		}
	}
	return findings, sc.Err()
}

// ---------------------------------------------------------------------------
// Directory scanner — parallel worker pool
// ---------------------------------------------------------------------------

// ScanDir scans all files matching glob pattern under root using a worker pool.
// Results are returned in deterministic (file, line) order.
func ScanDir(root, pattern string, workers int) ([]Finding, error) {
	if workers <= 0 {
		workers = DefaultWorkers
	}
	paths, err := filepath.Glob(filepath.Join(root, pattern))
	if err != nil {
		return nil, err
	}
	// Glob doesn't recurse; use Walk for ** semantics.
	if len(paths) == 0 || strings.Contains(pattern, "**") {
		paths, err = walkGlob(root, pattern)
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, nil
	}

	type result struct {
		path     string
		findings []Finding
		err      error
	}

	jobs := make(chan string, len(paths))
	results := make(chan result, len(paths))

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				fs, err := ScanFile(p)
				results <- result{p, fs, err}
			}
		}()
	}
	for _, p := range paths {
		jobs <- p
	}
	close(jobs)
	wg.Wait()
	close(results)

	// Collect in original sorted-path order for determinism.
	byPath := make(map[string][]Finding)
	for r := range results {
		if r.err == nil {
			byPath[r.path] = r.findings
		}
	}
	var all []Finding
	for _, p := range paths {
		all = append(all, byPath[p]...)
	}
	return all, nil
}

// walkGlob walks root and returns files whose relative path matches the suffix pattern.
func walkGlob(root, pattern string) ([]string, error) {
	// Strip leading **/ for simple suffix matching.
	suffix := strings.TrimPrefix(pattern, "**/")
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if !d.IsDir() {
			matched, _ := filepath.Match(suffix, filepath.Base(path))
			if matched {
				out = append(out, path)
			}
		}
		return nil
	})
	return out, err
}

// ---------------------------------------------------------------------------
// Source-code scanner — regex heuristics on log call sites
// ---------------------------------------------------------------------------

// logCallRE detects Python log calls that reference PII-suggestive fields.
// RE2-safe: no lookbehind needed.
// Pattern: log.(info|debug|error|exception)(f"... {ic|card|account ...}
var logCallRE = regexp.MustCompile(`(?i)log\s*\.\s*(?:info|debug|error|warning|exception|critical)\s*\([^)]*\{[^}]*(?:ic|card|account|mobile|phone|email)[^}]*\}`)

// ScanSource scans Python source files for hard-coded PII and risky log calls.
func ScanSource(root string) ([]Finding, error) {
	var findings []Finding
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(path, ".py") {
			return nil
		}
		fs, err := scanSourceFile(path)
		if err != nil {
			return nil // skip unreadable files
		}
		findings = append(findings, fs...)
		return nil
	})
	return findings, err
}

func scanSourceFile(path string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, scanBufSize), scanBufSize)

	var findings []Finding
	lineno := 0

	for sc.Scan() {
		lineno++
		raw := sc.Text()
		matches := detector.RunAll(raw)
		if len(matches) == 0 && !logCallRE.MatchString(raw) {
			continue
		}
		src := &tracer.SourceRef{Pathname: path, Lineno: lineno, Snippet: strings.TrimSpace(raw)}
		for _, m := range matches {
			s := severity.Score(m.PiiType, "INFO")
			findings = append(findings, Finding{
				Match:         m,
				LogLevel:      "SOURCE",
				SeverityScore: s,
				Severity:      severity.Classify(s),
				PDPATag:       severity.PDPATag[m.PiiType],
				RawLine:       raw,
				LogPath:       path,
				LogLineNo:     lineno,
				SourceRef:     src,
			})
		}
	}
	return findings, sc.Err()
}

func mustCompile(s string) interface{ MatchString(string) bool } {
	return mustCompiledRE{r: regexp.MustCompile(s)}
}

type mustCompiledRE struct {
	r interface{ MatchString(string) bool }
}

func (m mustCompiledRE) MatchString(s string) bool { return m.r.MatchString(s) }
