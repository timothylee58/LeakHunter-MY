// Package masking provides format-preserving PII masks and file-level redaction.
package masking

import (
	"regexp"
	"strings"

	"github.com/leakhunter-my/leakhunter/internal/detector"
)

var spaceDash = regexp.MustCompile(`[ -]`)

// Mask returns a format-preserving masked token for value.
// The last 4 significant characters are preserved; everything else is starred.
func Mask(piiType detector.PiiType, value string) string {
	switch piiType {
	case detector.PiiMyKad:
		// YYMMDD-PB-#### -> ******-**-####
		parts := strings.Split(value, "-")
		if len(parts) == 3 {
			return "******-**-" + parts[2]
		}
		return "******-**-****"

	case detector.PiiPaymentCard:
		digits := spaceDash.ReplaceAllString(value, "")
		if len(digits) < 4 {
			return strings.Repeat("*", len(value))
		}
		last4 := digits[len(digits)-4:]
		totalMask := len(digits) - 4
		// Rebuild preserving original separators
		var b strings.Builder
		masked := 0
		for _, ch := range value {
			if ch == ' ' || ch == '-' {
				b.WriteRune(ch)
			} else {
				if masked < totalMask {
					b.WriteByte('*')
				} else {
					b.WriteRune(ch)
				}
				masked++
			}
		}
		_ = last4
		return b.String()

	case detector.PiiBankAccount:
		digits := spaceDash.ReplaceAllString(value, "")
		keep := 4
		if len(digits) < keep {
			keep = len(digits)
		}
		return strings.Repeat("*", len(digits)-keep) + digits[len(digits)-keep:]

	case detector.PiiPhone:
		// Keep country prefix and last 4 digits
		stripped := regexp.MustCompile(`[^\d+]`).ReplaceAllString(value, "")
		last4 := stripped
		if len(stripped) >= 4 {
			last4 = stripped[len(stripped)-4:]
		}
		prefix := "+60"
		if strings.HasPrefix(value, "+60") {
			prefix = "+60"
		} else if strings.HasPrefix(value, "60") {
			prefix = "60"
		} else {
			prefix = "0"
		}
		return prefix + "****" + last4

	case detector.PiiEmail:
		at := strings.IndexByte(value, '@')
		if at > 0 {
			return string(value[0]) + "***" + value[at:]
		}
		return "***@***"
	}
	return "[REDACTED]"
}

// bulkToken is the replacement used when bulk-redacting text.
var bulkToken = map[detector.PiiType]string{
	detector.PiiMyKad:       "[IC-REDACTED]",
	detector.PiiPaymentCard: "[CARD-REDACTED]",
	detector.PiiBankAccount: "[ACCT-REDACTED]",
	detector.PiiPhone:       "[PHONE-REDACTED]",
	detector.PiiEmail:       "[EMAIL-REDACTED]",
}

// MaskPII redacts all PII found in text with bulk tokens.
func MaskPII(text string) string {
	matches := detector.RunAll(text)
	if len(matches) == 0 {
		return text
	}
	// Replace longest values first to prevent partial-overlap issues.
	result := text
	// Sort by length descending.
	sorted := make([]detector.Match, len(matches))
	copy(sorted, matches)
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if len(sorted[j].Value) > len(sorted[i].Value) {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	for _, m := range sorted {
		tok := bulkToken[m.PiiType]
		if tok == "" {
			tok = "[REDACTED]"
		}
		result = strings.ReplaceAll(result, m.Value, tok)
	}
	return result
}

// MaskLine redacts PII from a single raw log line (JSON or plain text).
func MaskLine(line string) string {
	return MaskPII(line)
}
