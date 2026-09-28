"""Tests for the masking module."""
from __future__ import annotations

import logging
from pathlib import Path

import pytest

from leakhunter.masking import RedactFilter, RedactingFilter, SafeFormatter, mask, mask_file, mask_findings, mask_pii
from leakhunter.report import render_markdown
from leakhunter.scanner import scan_file
from tests.conftest import CANARY_CARD, CANARY_EMAIL, CANARY_IC, CANARY_PHONE


class TestMask:
    def test_ic_masked(self, leaky_log: Path) -> None:
        findings = scan_file(leaky_log)
        ic_findings = [f for f in findings if f.match.pii_type == "MYKAD"]
        assert ic_findings, "Leaky log must contain MYKAD"
        line = ic_findings[0].raw_line
        masked_line = mask_findings(line, ic_findings)
        assert "[IC-REDACTED]" in masked_line
        assert ic_findings[0].match.value not in masked_line

    def test_card_masked(self, leaky_log: Path) -> None:
        findings = scan_file(leaky_log)
        card_findings = [f for f in findings if f.match.pii_type == "PAYMENT_CARD"]
        assert card_findings
        line = card_findings[0].raw_line
        masked_line = mask_findings(line, card_findings)
        assert "[CARD-REDACTED]" in masked_line

    def test_email_masked(self, leaky_log: Path) -> None:
        findings = scan_file(leaky_log)
        email_findings = [f for f in findings if f.match.pii_type == "EMAIL"]
        assert email_findings
        line = email_findings[0].raw_line
        masked_line = mask_findings(line, email_findings)
        assert "[EMAIL-REDACTED]" in masked_line

    def test_original_value_absent_after_mask(self, leaky_log: Path) -> None:
        findings = scan_file(leaky_log)
        for f in findings:
            masked = mask_findings(f.raw_line, [f])
            assert f.match.value not in masked, (
                f"Value {f.match.value!r} still present after masking"
            )


class TestMaskPii:
    """Tests for the stateless mask_pii() helper."""

    def test_ic_redacted(self) -> None:
        result = mask_pii("customer ic=901123-08-7654 logged in")
        assert "[IC-REDACTED]" in result
        assert "901123-08-7654" not in result

    def test_email_redacted(self) -> None:
        result = mask_pii("contact: user@example.my")
        assert "[EMAIL-REDACTED]" in result
        assert "user@example.my" not in result

    def test_phone_redacted(self) -> None:
        result = mask_pii("call +60123456789 now")
        assert "[PHONE-REDACTED]" in result

    def test_clean_text_unchanged(self) -> None:
        text = "no sensitive data here"
        assert mask_pii(text) == text

    def test_multiple_types_in_one_string(self) -> None:
        text = "ic=901123-08-7654 email=a@b.my phone=+60123456789"
        result = mask_pii(text)
        assert "[IC-REDACTED]" in result
        assert "[EMAIL-REDACTED]" in result
        assert "[PHONE-REDACTED]" in result
        assert "901123-08-7654" not in result

    def test_canary_sentence_contains_no_detectable_pii(self) -> None:
        """mask_pii on a sentence containing every CANARY value leaves no raw PII."""
        sentence = (
            f"ic={CANARY_IC} card={CANARY_CARD} "
            f"email={CANARY_EMAIL} mobile={CANARY_PHONE}"
        )
        result = mask_pii(sentence)
        assert CANARY_IC    not in result, "IC must be redacted"
        assert CANARY_CARD  not in result, "card must be redacted"
        assert CANARY_EMAIL not in result, "email must be redacted"
        assert CANARY_PHONE not in result, "phone must be redacted"
        # Verify tokens are present
        assert "[IC-REDACTED]"    in result
        assert "[CARD-REDACTED]"  in result
        assert "[EMAIL-REDACTED]" in result
        assert "[PHONE-REDACTED]" in result


class TestSafeFormatter:
    def test_redacts_pii_in_log_record(self) -> None:
        fmt = SafeFormatter("%(message)s")
        record = logging.LogRecord(
            name="test", level=logging.INFO,
            pathname="test.py", lineno=1,
            msg="ic=901123-08-7654 logged in",
            args=(), exc_info=None,
        )
        output = fmt.format(record)
        assert "[IC-REDACTED]" in output
        assert "901123-08-7654" not in output

    def test_clean_record_unchanged(self) -> None:
        fmt = SafeFormatter("%(message)s")
        record = logging.LogRecord(
            name="test", level=logging.INFO,
            pathname="test.py", lineno=1,
            msg="payment processed successfully",
            args=(), exc_info=None,
        )
        output = fmt.format(record)
        assert "payment processed successfully" in output


class TestRedactFilter:
    def test_mutates_record_msg(self) -> None:
        f = RedactingFilter()
        record = logging.LogRecord(
            name="test", level=logging.INFO,
            pathname="test.py", lineno=1,
            msg="email=%s", args=("canary@example.my",),
            exc_info=None,
        )
        result = f.filter(record)
        assert result is True
        assert record.args is None
        assert "[EMAIL-REDACTED]" in record.msg
        assert "canary@example.my" not in record.msg

    def test_allows_clean_record(self) -> None:
        f = RedactingFilter()
        record = logging.LogRecord(
            name="test", level=logging.DEBUG,
            pathname="test.py", lineno=1,
            msg="cache cleared",
            args=(), exc_info=None,
        )
        assert f.filter(record) is True
        assert record.msg == "cache cleared"

    def test_scrubs_exc_text(self) -> None:
        """exc_text containing PII must be redacted."""
        f = RedactingFilter()
        record = logging.LogRecord(
            name="test", level=logging.ERROR,
            pathname="test.py", lineno=1,
            msg="payment failed",
            args=(), exc_info=None,
        )
        record.exc_text = "PaymentError: Declined card=4111 1111 1111 1111"
        f.filter(record)
        assert "4111 1111 1111 1111" not in record.exc_text
        assert "[CARD-REDACTED]" in record.exc_text

    def test_old_name_alias_still_works(self) -> None:
        assert RedactFilter is RedactingFilter


class TestMaskFile:
    def test_masked_file_created(self, leaky_log: Path) -> None:
        findings = scan_file(leaky_log)
        out = mask_file(leaky_log, findings)
        assert out.exists()
        assert out.suffix == ".masked"

    def test_original_not_modified(self, leaky_log: Path) -> None:
        original_content = leaky_log.read_text()
        findings = scan_file(leaky_log)
        mask_file(leaky_log, findings)
        assert leaky_log.read_text() == original_content, "Original log must not be modified"

    def test_masked_file_contains_no_pii(self, leaky_log: Path) -> None:
        findings = scan_file(leaky_log)
        out = mask_file(leaky_log, findings)
        masked_findings = scan_file(out)
        assert len(masked_findings) == 0, (
            f"Masked file still contains PII: {[f.match.value for f in masked_findings]}"
        )

    def test_clean_log_produces_identical_masked_file(self, clean_log: Path) -> None:
        findings = scan_file(clean_log)
        assert findings == [], "Clean log must have zero findings"
        out = mask_file(clean_log, findings)
        assert out.read_text() == clean_log.read_text()


class TestRenderMarkdown:
    def test_receipt_before_written(self, leaky_log: Path, tmp_path: Path) -> None:
        findings = scan_file(leaky_log)
        out = tmp_path / "receipt_before.md"
        render_markdown(findings, out, title="Before Fix")
        content = out.read_text()
        assert "# Before Fix" in content
        assert "HIGH" in content or "MEDIUM" in content or "LOW" in content

    def test_receipt_after_is_clean(self, leaky_log: Path, tmp_path: Path) -> None:
        findings = scan_file(leaky_log)
        masked_path = mask_file(leaky_log, findings)
        after_findings = scan_file(masked_path)
        out = tmp_path / "receipt_after.md"
        render_markdown(after_findings, out, title="After Fix")
        content = out.read_text()
        assert "No PII found" in content

    def test_receipt_contains_pdpa_tag(self, leaky_log: Path, tmp_path: Path) -> None:
        findings = scan_file(leaky_log)
        out = tmp_path / "receipt.md"
        render_markdown(findings, out)
        assert "PDPA" in out.read_text()
