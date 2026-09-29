package masking_test

import (
	"strings"
	"testing"

	"github.com/leakhunter-my/leakhunter/internal/detector"
	"github.com/leakhunter-my/leakhunter/internal/masking"
)

func TestMask_ic(t *testing.T) {
	got := masking.Mask(detector.PiiMyKad, "900101-14-5678")
	if !strings.HasPrefix(got, "******-**-") {
		t.Errorf("IC mask should start with ******-**-, got %q", got)
	}
	if strings.Contains(got, "900101") {
		t.Error("raw IC date should be masked")
	}
	if !strings.HasSuffix(got, "5678") {
		t.Errorf("IC mask should preserve last 4 digits, got %q", got)
	}
}

func TestMask_card(t *testing.T) {
	got := masking.Mask(detector.PiiPaymentCard, "4111 1111 1111 1111")
	if strings.Contains(got, "4111 1111 1111") {
		t.Errorf("card first groups should be masked, got %q", got)
	}
	if !strings.HasSuffix(got, "1111") {
		t.Errorf("card mask should preserve last 4 digits, got %q", got)
	}
}

func TestMask_email(t *testing.T) {
	got := masking.Mask(detector.PiiEmail, "canary.tan@leakhunter.test")
	if !strings.HasPrefix(got, "c***") {
		t.Errorf("email mask should start with first char + ***, got %q", got)
	}
	if !strings.Contains(got, "@leakhunter.test") {
		t.Errorf("email domain should be preserved, got %q", got)
	}
}

func TestMask_phone(t *testing.T) {
	got := masking.Mask(detector.PiiPhone, "+6012-345 6789")
	if !strings.HasPrefix(got, "+60") {
		t.Errorf("phone mask should preserve +60 prefix, got %q", got)
	}
	if !strings.HasSuffix(got, "6789") {
		t.Errorf("phone mask should preserve last 4 digits, got %q", got)
	}
}

func TestMaskPII_redacts_inline(t *testing.T) {
	text := "customer ic=900101-14-5678 email=canary.tan@leakhunter.test"
	result := masking.MaskPII(text)
	if strings.Contains(result, "900101-14-5678") {
		t.Error("IC should be redacted")
	}
	if strings.Contains(result, "canary.tan@leakhunter.test") {
		t.Error("email should be redacted")
	}
	if !strings.Contains(result, "[IC-REDACTED]") {
		t.Error("expected [IC-REDACTED] token")
	}
	if !strings.Contains(result, "[EMAIL-REDACTED]") {
		t.Error("expected [EMAIL-REDACTED] token")
	}
}

func TestMaskPII_clean_text_unchanged(t *testing.T) {
	text := "server started on port 8080"
	if masking.MaskPII(text) != text {
		t.Error("clean text should be returned unchanged")
	}
}
