// Package detector implements RE2-safe regex detectors for Malaysian PII.
//
// Bank-account detection uses the "find keyword indices then distance check"
// pattern because RE2 (used by Go's regexp package) does not support
// lookbehind assertions.  This gives guaranteed linear-time scanning with
// no risk of ReDoS.
package detector

import (
	"regexp"
	"strings"
)

// PiiType identifies the kind of personal data found.
type PiiType string

const (
	PiiMyKad       PiiType = "MYKAD"
	PiiPaymentCard PiiType = "PAYMENT_CARD"
	PiiBankAccount PiiType = "BANK_ACCOUNT"
	PiiPhone       PiiType = "MY_PHONE"
	PiiEmail       PiiType = "EMAIL"
)

// Match records one detected PII occurrence.
type Match struct {
	PiiType PiiType
	Value   string
	Start   int // byte offset in the scanned text
	End     int
}

// ---------------------------------------------------------------------------
// Valid MyKad birthplace codes.  Codes 00 and 17-20 are never issued.
// ---------------------------------------------------------------------------

var validPB = func() map[string]bool {
	m := make(map[string]bool)
	ranges := [][2]int{{1, 16}, {21, 59}, {60, 66}, {71, 74}, {82, 99}}
	for _, r := range ranges {
		for n := r[0]; n <= r[1]; n++ {
			m[paddedTwo(n)] = true
		}
	}
	return m
}()

func paddedTwo(n int) string {
	if n < 10 {
		return "0" + string(rune('0'+n))
	}
	s := ""
	s += string(rune('0' + n/10))
	s += string(rune('0' + n%10))
	return s
}

var daysInMonth = [13]int{0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}

func validICDate(mm, dd int) bool {
	return mm >= 1 && mm <= 12 && dd >= 1 && dd <= daysInMonth[mm]
}

// ---------------------------------------------------------------------------
// MyKad IC  — YYMMDD-PB-####
// RE2 note: \b works in Go regexp (it matches word boundaries).
// ---------------------------------------------------------------------------

var icRE = regexp.MustCompile(`\b(\d{2})(0[1-9]|1[0-2])(\d{2})-(\d{2})-(\d{4})\b`)

// DetectMyKad returns MyKad IC matches, validating date and birthplace code.
func DetectMyKad(text string) []Match {
	var out []Match
	for _, loc := range icRE.FindAllStringSubmatchIndex(text, -1) {
		// loc[0]:loc[1] = full match; subgroups at loc[2n]:loc[2n+1]
		full := text[loc[0]:loc[1]]
		mm := atoi(text[loc[4]:loc[5]])
		dd := atoi(text[loc[6]:loc[7]])
		pb := text[loc[8]:loc[9]]
		if !validPB[pb] || !validICDate(mm, dd) {
			continue
		}
		out = append(out, Match{PiiMyKad, full, loc[0], loc[1]})
	}
	return out
}

// ---------------------------------------------------------------------------
// Payment card — 13-19 digits, Luhn check, major-network prefix
// ---------------------------------------------------------------------------

var cardRE = regexp.MustCompile(`\b(\d[\d -]{11,21}\d)\b`)

// card prefix patterns (applied after stripping spaces/hyphens)
var cardPrefixRE = regexp.MustCompile(
	`^(?:4\d{12,18}` +
		`|5[1-5]\d{14}` +
		`|2(?:2[2-9]\d|[3-6]\d{2}|7[01]\d|720)\d{12}` +
		`|3[47]\d{13}` +
		`|6(?:011|5\d{2})\d{12,15})$`,
)

var spaceDash = regexp.MustCompile(`[ -]`)

func luhn(digits string) bool {
	total := 0
	for i, ch := range reverse(digits) {
		n := int(ch - '0')
		if i%2 == 1 {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		total += n
	}
	return total%10 == 0
}

func reverse(s string) string {
	r := []byte(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// DetectCard returns payment card matches (Luhn-validated, prefix-checked).
func DetectCard(text string) []Match {
	var out []Match
	for _, loc := range cardRE.FindAllStringIndex(text, -1) {
		raw := text[loc[0]:loc[1]]
		digits := spaceDash.ReplaceAllString(raw, "")
		if len(digits) < 13 || len(digits) > 19 {
			continue
		}
		if !cardPrefixRE.MatchString(digits) {
			continue
		}
		if !luhn(digits) {
			continue
		}
		out = append(out, Match{PiiPaymentCard, raw, loc[0], loc[1]})
	}
	return out
}

// ---------------------------------------------------------------------------
// Bank account — 10-16 digits within 30 bytes of a banking keyword.
//
// RE2 has no lookbehind, so we find keyword positions and digit-run positions
// separately, then check whether any pair is within 30 bytes of each other.
// This is O(k*d) where k=keyword matches and d=digit matches — fast in
// practice because both sets are small on a single log line.
// ---------------------------------------------------------------------------

var bankKeywordRE = regexp.MustCompile(`(?i)acct|account|akaun|bank|no\.?\s*acc|no\.?\s*akaun`)
var bankDigitRE = regexp.MustCompile(`\b\d{10,16}\b`)

const bankContextWindow = 30

// DetectBankAccount returns bank account numbers near banking keywords.
func DetectBankAccount(text string) []Match {
	kwLocs := bankKeywordRE.FindAllStringIndex(text, -1)
	if len(kwLocs) == 0 {
		return nil
	}
	digLocs := bankDigitRE.FindAllStringIndex(text, -1)
	if len(digLocs) == 0 {
		return nil
	}

	seen := make(map[[2]int]bool)
	var out []Match

	for _, dl := range digLocs {
		for _, kl := range kwLocs {
			// distance between the end of one and start of the other
			var dist int
			if dl[0] > kl[1] {
				dist = dl[0] - kl[1]
			} else if kl[0] > dl[1] {
				dist = kl[0] - dl[1]
			} else {
				dist = 0 // overlapping
			}
			if dist <= bankContextWindow {
				key := [2]int{dl[0], dl[1]}
				if !seen[key] {
					seen[key] = true
					out = append(out, Match{PiiBankAccount, text[dl[0]:dl[1]], dl[0], dl[1]})
				}
				break
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Malaysian mobile — (+60|0)1X + 7-8 digits (separators allowed)
// RE2 note: \b and (?:...) are fine; no lookbehind needed here because
// we use \D or start-of-string anchoring via character class.
// ---------------------------------------------------------------------------

var phoneRE = regexp.MustCompile(`(?:^|[^\d])(\+?60|0)(1[0-9])[-\s]?(\d{3,4})[-\s]?(\d{4})(?:[^\d]|$)`)

// DetectPhone returns Malaysian mobile number matches.
func DetectPhone(text string) []Match {
	var out []Match
	for _, loc := range phoneRE.FindAllStringSubmatchIndex(text, -1) {
		// group 0 = full match (may include leading non-digit), groups 1-4 = parts
		prefix := text[loc[2]:loc[3]]      // +60 or 60 or 0
		mid1 := text[loc[4]:loc[5]]        // 1X
		mid2 := text[loc[6]:loc[7]]        // 3-4 digits
		last := text[loc[8]:loc[9]]        // 4 digits
		rawPhone := prefix + mid1 + mid2 + last

		// Validate subscriber digit count (after stripping country prefix)
		strippedPrefix := strings.TrimPrefix(prefix, "+")
		allDigits := spaceDash.ReplaceAllString(rawPhone, "")
		sub := allDigits[len(strippedPrefix):]
		if len(sub) < 9 || len(sub) > 10 {
			continue
		}

		// The actual phone token is the concatenation of the 4 groups
		// Recompute span: find the exact start/end within the full match
		fullStart := loc[0]
		fullMatch := text[loc[0]:loc[1]]
		tokenStart := strings.Index(fullMatch, prefix)
		if tokenStart < 0 {
			tokenStart = 0
		}
		phoneStart := fullStart + tokenStart
		phoneEnd := phoneStart + len(rawPhone)
		// Reconstruct value with original separators from source text
		value := text[loc[2]:loc[9]]
		phoneEnd = loc[9]
		out = append(out, Match{PiiPhone, value, loc[2], phoneEnd})
	}
	return out
}

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------

var emailRE = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)

// DetectEmail returns email address matches.
func DetectEmail(text string) []Match {
	var out []Match
	for _, loc := range emailRE.FindAllStringIndex(text, -1) {
		out = append(out, Match{PiiEmail, text[loc[0]:loc[1]], loc[0], loc[1]})
	}
	return out
}

// ---------------------------------------------------------------------------
// Allowlist — suppress known-safe test fixtures
// ---------------------------------------------------------------------------

var allowlist = make(map[string]bool)

// AddToAllowlist registers values that must never be reported (e.g. test canaries).
func AddToAllowlist(values ...string) {
	for _, v := range values {
		allowlist[v] = true
	}
}

// ClearAllowlist removes all allowlist entries (for test teardown).
func ClearAllowlist() {
	allowlist = make(map[string]bool)
}

// ---------------------------------------------------------------------------
// Aggregate
// ---------------------------------------------------------------------------

// RunAll runs every detector on text and returns deduplicated matches.
func RunAll(text string) []Match {
	var all []Match
	seen := make(map[[2]int]bool)

	add := func(ms []Match) {
		for _, m := range ms {
			if allowlist[m.Value] {
				continue
			}
			key := [2]int{m.Start, m.End}
			if seen[key] {
				continue
			}
			seen[key] = true
			all = append(all, m)
		}
	}

	add(DetectMyKad(text))
	add(DetectCard(text))
	add(DetectBankAccount(text))
	add(DetectPhone(text))
	add(DetectEmail(text))

	return all
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func atoi(s string) int {
	n := 0
	for _, ch := range s {
		n = n*10 + int(ch-'0')
	}
	return n
}
