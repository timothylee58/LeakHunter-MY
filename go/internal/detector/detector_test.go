package detector_test

import (
	"testing"

	"github.com/leakhunter-my/leakhunter/internal/detector"
)

// ---------------------------------------------------------------------------
// MyKad IC
// ---------------------------------------------------------------------------

func TestDetectMyKad_valid(t *testing.T) {
	cases := []string{
		"900101-14-5678",
		"IC: 851231-12-3456",
		"customer ic=760415-07-1234",
	}
	for _, text := range cases {
		matches := detector.DetectMyKad(text)
		if len(matches) == 0 {
			t.Errorf("DetectMyKad(%q) expected match, got none", text)
		}
	}
}

func TestDetectMyKad_invalid_pb_code(t *testing.T) {
	// PB code 00 is never issued
	matches := detector.DetectMyKad("900101-00-5678")
	if len(matches) != 0 {
		t.Errorf("expected no match for never-issued PB code 00, got %+v", matches)
	}
}

func TestDetectMyKad_invalid_pb_code_17_to_20(t *testing.T) {
	// Codes 17, 18, 19, 20 are never issued
	for _, pb := range []string{"17", "18", "19", "20"} {
		text := "900101-" + pb + "-5678"
		matches := detector.DetectMyKad(text)
		if len(matches) != 0 {
			t.Errorf("expected no match for never-issued PB code %s", pb)
		}
	}
}

func TestDetectMyKad_invalid_date(t *testing.T) {
	// Month 13 is invalid
	matches := detector.DetectMyKad("901301-14-5678")
	if len(matches) != 0 {
		t.Errorf("expected no match for invalid month 13, got %+v", matches)
	}
}

func TestDetectMyKad_no_false_positive_sequence(t *testing.T) {
	// A random 14-digit number without dashes should not match
	matches := detector.DetectMyKad("order_id=12345678901234")
	if len(matches) != 0 {
		t.Errorf("unexpected match in plain digit sequence: %+v", matches)
	}
}

// ---------------------------------------------------------------------------
// Payment card
// ---------------------------------------------------------------------------

func TestDetectCard_visa_valid(t *testing.T) {
	// Canary Visa (Luhn-valid test number)
	matches := detector.DetectCard("card 4111 1111 1111 1111 charged")
	if len(matches) == 0 {
		t.Error("expected Visa match, got none")
	}
	if matches[0].Value != "4111 1111 1111 1111" {
		t.Errorf("unexpected value: %q", matches[0].Value)
	}
}

func TestDetectCard_fails_luhn(t *testing.T) {
	matches := detector.DetectCard("card 4111 1111 1111 1112")
	if len(matches) != 0 {
		t.Errorf("expected no match (bad Luhn), got %+v", matches)
	}
}

func TestDetectCard_too_short(t *testing.T) {
	matches := detector.DetectCard("card 411111111")
	if len(matches) != 0 {
		t.Errorf("expected no match (too short), got %+v", matches)
	}
}

// ---------------------------------------------------------------------------
// Bank account
// ---------------------------------------------------------------------------

func TestDetectBankAccount_near_keyword(t *testing.T) {
	cases := []string{
		"account 1234567890",
		"akaun: 1234567890",
		"acct 5140123478901",
		"bank no. 1234567890",
	}
	for _, text := range cases {
		matches := detector.DetectBankAccount(text)
		if len(matches) == 0 {
			t.Errorf("DetectBankAccount(%q) expected match, got none", text)
		}
	}
}

func TestDetectBankAccount_no_keyword(t *testing.T) {
	// 12 digits not near any banking keyword → no match
	matches := detector.DetectBankAccount("order ref 123456789012")
	if len(matches) != 0 {
		t.Errorf("expected no match without keyword, got %+v", matches)
	}
}

func TestDetectBankAccount_too_far_from_keyword(t *testing.T) {
	// keyword > 30 bytes away from digits
	text := "account " + "x x x x x x x x x x x x x x x x " + "1234567890"
	matches := detector.DetectBankAccount(text)
	if len(matches) != 0 {
		t.Errorf("expected no match (keyword too far), got %+v", matches)
	}
}

// ---------------------------------------------------------------------------
// Phone
// ---------------------------------------------------------------------------

func TestDetectPhone_valid(t *testing.T) {
	cases := []string{
		"+6012-345 6789",
		"+60123456789",
		"0123456789",
		"my number is 0123456789 ok",
	}
	for _, text := range cases {
		matches := detector.DetectPhone(text)
		if len(matches) == 0 {
			t.Errorf("DetectPhone(%q) expected match, got none", text)
		}
	}
}

func TestDetectPhone_rejects_non_my(t *testing.T) {
	// US number — should not match
	matches := detector.DetectPhone("+1 800 555 1234")
	if len(matches) != 0 {
		t.Errorf("expected no match for non-MY number, got %+v", matches)
	}
}

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------

func TestDetectEmail_valid(t *testing.T) {
	matches := detector.DetectEmail("contact canary.tan@leakhunter.test now")
	if len(matches) == 0 {
		t.Error("expected email match, got none")
	}
}

func TestDetectEmail_none(t *testing.T) {
	matches := detector.DetectEmail("no email here")
	if len(matches) != 0 {
		t.Errorf("unexpected email match: %+v", matches)
	}
}

// ---------------------------------------------------------------------------
// RunAll + allowlist
// ---------------------------------------------------------------------------

func TestRunAll_multiple_types(t *testing.T) {
	text := "ic=900101-14-5678 card=4111 1111 1111 1111 email=canary.tan@leakhunter.test"
	matches := detector.RunAll(text)
	types := make(map[detector.PiiType]bool)
	for _, m := range matches {
		types[m.PiiType] = true
	}
	for _, want := range []detector.PiiType{detector.PiiMyKad, detector.PiiPaymentCard, detector.PiiEmail} {
		if !types[want] {
			t.Errorf("RunAll missing pii_type %s", want)
		}
	}
}

func TestRunAll_allowlist_suppresses(t *testing.T) {
	detector.AddToAllowlist("900101-14-5678")
	defer detector.ClearAllowlist()

	matches := detector.RunAll("ic=900101-14-5678")
	for _, m := range matches {
		if m.PiiType == detector.PiiMyKad {
			t.Error("allowlisted value should be suppressed")
		}
	}
}
