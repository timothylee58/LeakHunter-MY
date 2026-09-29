// Package severity computes PDPA-aligned severity scores for PII findings.
package severity

import "github.com/leakhunter-my/leakhunter/internal/detector"

// Label is HIGH / MEDIUM / LOW.
type Label string

const (
	High   Label = "HIGH"
	Medium Label = "MEDIUM"
	Low    Label = "LOW"
)

var sensitivity = map[detector.PiiType]float64{
	detector.PiiMyKad:       3.0,
	detector.PiiPaymentCard: 3.0,
	detector.PiiBankAccount: 3.0,
	detector.PiiPhone:       2.0,
	detector.PiiEmail:       1.0,
}

var exposure = map[string]float64{
	"ERROR":    1.5,
	"CRITICAL": 1.5,
	"WARNING":  1.2,
	"INFO":     1.0,
	"DEBUG":    1.0,
	"UNKNOWN":  1.0,
}

// PDPATag maps each PII type to its PDPA 2010 Security Principle citation.
var PDPATag = map[detector.PiiType]string{
	detector.PiiMyKad:       "PDPA-S9: Biometric/identity data — must not be disclosed without consent",
	detector.PiiPaymentCard: "PDPA-S9: Financial data — PCI-DSS and PDPA protection required",
	detector.PiiBankAccount: "PDPA-S9: Financial data — restricted processing under PDPA",
	detector.PiiPhone:       "PDPA-S7: Contact data — collection must be notified",
	detector.PiiEmail:       "PDPA-S7: Contact data — collection must be notified",
}

// Score returns sensitivity × exposure multiplier for (piiType, logLevel).
func Score(pt detector.PiiType, logLevel string) float64 {
	s := sensitivity[pt]
	if s == 0 {
		s = 1.0
	}
	e := exposure[logLevel]
	if e == 0 {
		e = 1.0
	}
	return s * e
}

// Classify maps a numeric score to HIGH / MEDIUM / LOW.
func Classify(s float64) Label {
	switch {
	case s >= 3.0:
		return High
	case s >= 2.0:
		return Medium
	default:
		return Low
	}
}
