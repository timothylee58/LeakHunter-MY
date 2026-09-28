"""SARIF v2.1.0 report generation for GitHub Code Scanning."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from leakhunter.scanner import Finding

_TOOL_NAME    = "leakhunter-my"
_TOOL_VERSION = "0.1.0"
_TOOL_URL     = "https://github.com/leakhunter-my/leakhunter-my"

# Map severity to SARIF level
_SARIF_LEVEL: dict[str, str] = {
    "HIGH":   "error",
    "MEDIUM": "warning",
    "LOW":    "note",
}

# One SARIF rule per PII type
_RULES: list[dict] = [
    {
        "id": "LH001",
        "name": "MyKadIcLeak",
        "shortDescription": {"text": "Malaysian IC number in log output"},
        "fullDescription": {"text": "A Malaysian Identity Card (MyKad) number was detected. PDPA 2010 Section 9."},
        "helpUri": _TOOL_URL,
        "properties": {"tags": ["security", "pii", "pdpa"]},
        "defaultConfiguration": {"level": "error"},
    },
    {
        "id": "LH002",
        "name": "PaymentCardLeak",
        "shortDescription": {"text": "Payment card number in log output"},
        "fullDescription": {"text": "A payment card number (Luhn-valid) was detected. PCI-DSS + PDPA 2010 Section 9."},
        "helpUri": _TOOL_URL,
        "properties": {"tags": ["security", "pii", "pci-dss", "pdpa"]},
        "defaultConfiguration": {"level": "error"},
    },
    {
        "id": "LH003",
        "name": "BankAccountLeak",
        "shortDescription": {"text": "Bank account number in log output"},
        "fullDescription": {"text": "A bank account number was detected near a banking keyword. PDPA 2010 Section 9."},
        "helpUri": _TOOL_URL,
        "properties": {"tags": ["security", "pii", "pdpa"]},
        "defaultConfiguration": {"level": "error"},
    },
    {
        "id": "LH004",
        "name": "MobileNumberLeak",
        "shortDescription": {"text": "Malaysian mobile number in log output"},
        "fullDescription": {"text": "A Malaysian mobile number (+60 / 01X prefix) was detected. PDPA 2010 Section 7."},
        "helpUri": _TOOL_URL,
        "properties": {"tags": ["security", "pii", "pdpa"]},
        "defaultConfiguration": {"level": "warning"},
    },
    {
        "id": "LH005",
        "name": "EmailAddressLeak",
        "shortDescription": {"text": "Email address in log output"},
        "fullDescription": {"text": "An email address was detected in log output. PDPA 2010 Section 7."},
        "helpUri": _TOOL_URL,
        "properties": {"tags": ["security", "pii", "pdpa"]},
        "defaultConfiguration": {"level": "note"},
    },
]

_RULE_ID: dict[str, str] = {
    "MYKAD":        "LH001",
    "PAYMENT_CARD": "LH002",
    "BANK_ACCOUNT": "LH003",
    "MY_PHONE":     "LH004",
    "EMAIL":        "LH005",
}


def _finding_to_result(f: Finding) -> dict:
    """Convert a Finding to a SARIF result object."""
    from leakhunter.masking import mask as mask_value
    masked = mask_value(f.match.pii_type, f.match.value)

    rule_id = _RULE_ID.get(f.match.pii_type, "LH001")
    level   = _SARIF_LEVEL.get(f.severity, "warning")

    # Prefer source_ref (app code location) over log file location
    if f.source_ref:
        uri    = f.source_ref.pathname
        region = {"startLine": f.source_ref.lineno}
        snippet_text = f.source_ref.snippet or ""
    else:
        uri    = str(f.log_path)
        region = {"startLine": f.log_line_no}
        snippet_text = ""

    result: dict = {
        "ruleId": rule_id,
        "level":  level,
        "message": {
            "text": (
                f"{f.match.pii_type} detected ({masked}). "
                f"Severity: {f.severity}. {f.pdpa_tag}."
            )
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                    "region": region,
                    **({"contextRegion": {"snippet": {"text": snippet_text}}}
                       if snippet_text else {}),
                }
            }
        ],
    }
    return result


def write_sarif(findings: list[Finding], out: Path) -> None:
    """Write a SARIF v2.1.0 report to *out*.

    Suitable for upload to GitHub Code Scanning via
    ``github/codeql-action/upload-sarif@v3``.
    """
    out.parent.mkdir(parents=True, exist_ok=True)

    results = [_finding_to_result(f) for f in findings]

    payload = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name":            _TOOL_NAME,
                        "version":         _TOOL_VERSION,
                        "informationUri":  _TOOL_URL,
                        "rules":           _RULES,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }
        ],
    }

    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
