# =============================================================================
# Vulnerability gate: any uncategorized vulnerability fails the build. Only
# false-positive and operational-requirement pass; risk-adjustment does not.
# =============================================================================
import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("vuln_gate", REPO / "scripts" / "vuln-gate.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


vg = _load()

V_CRIT = {"id": "CVE-2026-1", "severity": "CRITICAL", "source": "grype"}
V_LOW = {"id": "CVE-2026-2", "severity": "LOW", "source": "zap"}


def test_no_vulns_passes():
    assert vg.find_unhandled([], {}) == []


def test_uncategorized_fails():
    assert vg.find_unhandled([V_CRIT], {}) == [V_CRIT]


def test_low_severity_still_fails_uncategorized():
    # "Low of any kind" must be fixed unless FP/OR
    assert vg.find_unhandled([V_LOW], {}) == [V_LOW]


def test_false_positive_passes():
    reg = {"CVE-2026-1": {"disposition": "false-positive", "justification": "x"}}
    assert vg.find_unhandled([V_CRIT], reg) == []


def test_operational_requirement_passes():
    reg = {"CVE-2026-1": {"disposition": "operational-requirement", "justification": "x"}}
    assert vg.find_unhandled([V_CRIT], reg) == []


def test_risk_adjustment_does_not_pass():
    # a risk-adjusted vuln still has a severity -> must be fixed
    reg = {"CVE-2026-1": {"disposition": "risk-adjustment", "adjusted_severity": "LOW"}}
    assert vg.find_unhandled([V_CRIT], reg) == [V_CRIT]


def test_remediate_disposition_does_not_pass():
    reg = {"CVE-2026-1": {"disposition": "remediate"}}
    assert vg.find_unhandled([V_CRIT], reg) == [V_CRIT]


def test_mixed_reports_only_unhandled():
    reg = {
        "CVE-2026-1": {"disposition": "false-positive"},
        "CVE-2026-2": {"disposition": "risk-adjustment"},  # does not pass
    }
    out = vg.find_unhandled([V_CRIT, V_LOW], reg)
    assert out == [V_LOW]


def test_vulns_from_vdr_extracts_cves():
    vdr = {"cve_findings": [
        {"cve": "CVE-2026-9", "severity": "HIGH", "source": "grype"},
        {"id": "CVE-2026-10", "max_severity": "medium"},
        {"title": "no id — skipped"},
    ]}
    vulns = vg.vulns_from_vdr(vdr)
    ids = {v["id"] for v in vulns}
    assert ids == {"CVE-2026-9", "CVE-2026-10"}
    assert any(v["severity"] == "MEDIUM" for v in vulns)


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
