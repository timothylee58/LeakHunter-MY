"""Tests for accuracy improvements: encoded PII detection, allowlist, SARIF output."""
from __future__ import annotations

import base64
import json
import urllib.parse
from pathlib import Path

import pytest

from leakhunter.detectors import _ALLOWLIST, add_to_allowlist, run_all
from leakhunter.sarif import write_sarif
from leakhunter.scanner import scan_file
from tests.conftest import CANARY_CARD, CANARY_IC


# ---------------------------------------------------------------------------
# URL-encoded PII detection
# ---------------------------------------------------------------------------

class TestUrlEncoded:
    def test_url_encoded_ic_detected(self) -> None:
        """IC embedded in a URL-encoded query string must be found."""
        encoded = urllib.parse.quote(CANARY_IC)
        text = f"GET /api?customer={encoded} HTTP/1.1"
        matches = run_all(text)
        assert any(m.pii_type == "MYKAD" for m in matches), (
            f"URL-encoded IC not detected in: {text!r}"
        )

    def test_url_encoded_email_detected(self) -> None:
        encoded = urllib.parse.quote("canary.tan@leakhunter.test")
        text = f"redirect_uri={encoded}"
        matches = run_all(text)
        assert any(m.pii_type == "EMAIL" for m in matches)

    def test_plain_text_still_works(self) -> None:
        matches = run_all(f"ic={CANARY_IC}")
        assert any(m.pii_type == "MYKAD" for m in matches)


# ---------------------------------------------------------------------------
# Base64-encoded PII detection
# ---------------------------------------------------------------------------

class TestBase64Encoded:
    def test_base64_ic_detected(self) -> None:
        """IC embedded in a base64-encoded blob must be found."""
        payload = f"customer_ic:{CANARY_IC}:verified"
        encoded = base64.b64encode(payload.encode()).decode()
        text = f"Authorization: Bearer {encoded}"
        matches = run_all(text)
        assert any(m.pii_type == "MYKAD" for m in matches), (
            f"Base64-encoded IC not detected. Encoded: {encoded!r}"
        )

    def test_base64_card_detected(self) -> None:
        payload = f"card={CANARY_CARD}"
        encoded = base64.b64encode(payload.encode()).decode()
        matches = run_all(f"data={encoded}")
        assert any(m.pii_type == "PAYMENT_CARD" for m in matches)

    def test_non_utf8_base64_not_crash(self) -> None:
        """Garbled base64 that decodes to non-UTF-8 bytes must not raise."""
        binary_b64 = base64.b64encode(bytes(range(256))).decode()
        result = run_all(f"blob={binary_b64}")
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------

class TestAllowlist:
    def setup_method(self) -> None:
        """Snapshot and restore the allowlist around each test."""
        self._snapshot = set(_ALLOWLIST)

    def teardown_method(self) -> None:
        _ALLOWLIST.clear()
        _ALLOWLIST.update(self._snapshot)

    def test_allowlisted_value_suppressed(self) -> None:
        add_to_allowlist(CANARY_IC)
        matches = run_all(f"ic={CANARY_IC}")
        assert not any(m.pii_type == "MYKAD" for m in matches), (
            "Allowlisted IC must not appear in findings"
        )

    def test_non_allowlisted_value_still_detected(self) -> None:
        add_to_allowlist(CANARY_IC)
        other_ic = "850312-14-5678"
        matches = run_all(f"ic={other_ic}")
        assert any(m.pii_type == "MYKAD" for m in matches)

    def test_allowlist_does_not_affect_other_types(self) -> None:
        add_to_allowlist(CANARY_IC)
        matches = run_all(f"ic={CANARY_IC} card={CANARY_CARD}")
        pii_types = {m.pii_type for m in matches}
        assert "MYKAD" not in pii_types
        assert "PAYMENT_CARD" in pii_types


# ---------------------------------------------------------------------------
# SARIF output
# ---------------------------------------------------------------------------

class TestSarif:
    def test_sarif_is_valid_json(self, leaky_log: Path, tmp_path: Path) -> None:
        findings = scan_file(leaky_log)
        out = tmp_path / "results.sarif"
        write_sarif(findings, out)
        data = json.loads(out.read_text())
        assert data["version"] == "2.1.0"
        assert "$schema" in data

    def test_sarif_has_correct_structure(self, leaky_log: Path, tmp_path: Path) -> None:
        findings = scan_file(leaky_log)
        out = tmp_path / "results.sarif"
        write_sarif(findings, out)
        data = json.loads(out.read_text())
        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "leakhunter-my"
        assert len(run["tool"]["driver"]["rules"]) == 5
        assert len(run["results"]) == len(findings)

    def test_sarif_no_raw_pii_in_messages(self, leaky_log: Path, tmp_path: Path) -> None:
        """SARIF messages must contain masked values, never raw PII."""
        findings = scan_file(leaky_log)
        out = tmp_path / "results.sarif"
        write_sarif(findings, out)
        content = out.read_text()
        for f in findings:
            assert f.match.value not in content, (
                f"Raw PII {f.match.value!r} found in SARIF output"
            )

    def test_sarif_empty_findings(self, tmp_path: Path) -> None:
        out = tmp_path / "empty.sarif"
        write_sarif([], out)
        data = json.loads(out.read_text())
        assert data["runs"][0]["results"] == []
