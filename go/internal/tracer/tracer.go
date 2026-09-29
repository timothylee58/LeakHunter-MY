// Package tracer resolves a JSON log line back to its application source location.
package tracer

import (
	"bufio"
	"encoding/json"
	"os"
	"strconv"
	"strings"
)

// SourceRef is an application source location embedded in a structured log record.
type SourceRef struct {
	Pathname string
	Lineno   int
	Snippet  string // the actual source line, trimmed; empty if unreadable
}

func (s SourceRef) String() string {
	return s.Pathname + ":" + strconv.Itoa(s.Lineno)
}

// TraceLine parses a JSON log line and returns the embedded source location, or nil.
func TraceLine(rawLine string) *SourceRef {
	var obj map[string]any
	if err := json.Unmarshal([]byte(rawLine), &obj); err != nil {
		return nil
	}

	pathname := stringField(obj, "pathname", "filename", "module")
	lineno := intField(obj, "lineno", "line", "line_number")
	if pathname == "" || lineno <= 0 {
		return nil
	}

	snippet := readSnippet(pathname, lineno)
	return &SourceRef{pathname, lineno, snippet}
}

// readSnippet reads a single line from a file by number (1-based).
// Returns empty string if the file cannot be read or the line is out of range.
func readSnippet(pathname string, lineno int) string {
	f, err := os.Open(pathname)
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		if n == lineno {
			return strings.TrimSpace(sc.Text())
		}
	}
	return ""
}

func stringField(obj map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := obj[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func intField(obj map[string]any, keys ...string) int {
	for _, k := range keys {
		if v, ok := obj[k]; ok {
			switch n := v.(type) {
			case float64:
				return int(n)
			case int:
				return n
			}
		}
	}
	return 0
}
