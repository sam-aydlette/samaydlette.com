# =============================================================================
# Vulnerability gate: any uncategorized vulnerability fails the build. Only
# false-positive and operational-requirement pass; risk-adjustment does not.
# =============================================================================
import importlib.util
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REGISTER_PATH = REPO / "data" / "vuln-dispositions.json"
POAM_MD_PATH = REPO / "docs" / "poam.md"


def _module(name, filename):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / filename)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _load():
    return _module("vuln_gate", "vuln-gate.py")


vg = _load()
vdr_builder = _module("vdr_builder", "build-vdr-report.py")

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


def test_vulns_from_vdr_includes_zap_and_cves():
    vdr = {
        "findings": [
            {"source": "grype", "cve": "CVE-2026-9", "severity": "HIGH"},
            {"source": "zap", "tracking_id": "zap-10038-1", "severity": "MEDIUM"},  # no CVE
            {"source": "opa", "tracking_id": "opa-x", "severity": "HIGH"},  # config — excluded
        ],
        "cve_findings": [{"cve": "CVE-2026-10", "max_severity": "medium"}],
    }
    vulns = vg.vulns_from_vdr(vdr)
    ids = {v["id"] for v in vulns}
    assert ids == {"CVE-2026-9", "zap-10038-1", "CVE-2026-10"}  # ZAP included, config excluded


def test_zap_finding_must_be_categorized():
    vdr = {"findings": [{"source": "zap", "tracking_id": "zap-40012-1", "severity": "MEDIUM"}]}
    vulns = vg.vulns_from_vdr(vdr)
    assert vg.find_unhandled(vulns, {}) == vulns  # uncategorized ZAP alert fails
    handled = vg.find_unhandled(vulns, {"zap-40012-1": {"disposition": "false-positive"}})
    assert handled == []


# =============================================================================
# The REAL register: data/vuln-dispositions.json.
#
# The register has no schema and no fixture. A dispositioned vulnerability with
# no poam_ref — or one pointing at a POA&M id that does not exist — makes the
# vulnerability gate pass and the reconciliation gate fail closed on invariant
# (h) instead, i.e. it trades one red gate for another, at deploy time, in CI.
# These tests move that failure to the unit suite.
# =============================================================================


def _real_register():
    return json.loads(REGISTER_PATH.read_text())


def _formal_poam_ids():
    """POA&M ids docs/poam.md tracks as formal items: section headers and table
    rows. Mirrors scripts/reconcile.py::_formal_poam_ids_in_md, which is what
    invariant (g) parity is measured against."""
    ids = set()
    for line in POAM_MD_PATH.read_text().splitlines():
        m = (re.match(r"\s*#{1,6}\s*(POAM-\d{3})\b", line)
             or re.match(r"\s*\|\s*(POAM-\d{3})\b", line))
        if m:
            ids.add(m.group(1))
    return ids


def test_register_entries_are_well_formed():
    reg = _real_register()["dispositions"]
    for key, entry in reg.items():
        assert entry.get("disposition") in vg.PASS_DISPOSITIONS, (
            f"{key}: disposition {entry.get('disposition')!r} does not pass the gate")
        assert entry.get("justification"), f"{key}: no justification"
        assert entry.get("decided_by"), f"{key}: no decided_by"
        assert entry.get("decided_on"), f"{key}: no decided_on"


def test_every_register_entry_resolves_to_a_poam_item():
    reg = _real_register()["dispositions"]
    formal = _formal_poam_ids()
    unresolved = {k: v.get("poam_ref") for k, v in reg.items()
                  if v.get("poam_ref") not in formal}
    assert not unresolved, (
        f"register entries whose poam_ref is missing or not a formal POA&M item in "
        f"docs/poam.md: {unresolved}")


def test_register_example_documents_the_poam_ref_field():
    # The _example block is the register's only schema; if it does not show
    # poam_ref, the next operator writes an entry without one.
    example = _real_register()["_example"]
    assert all(e.get("poam_ref") for e in example.values()), (
        "the register's _example must carry a poam_ref so the required shape is "
        "self-documenting")


def test_register_dispositions_reach_the_vdr_builder():
    # End-to-end for the generator half: a real register entry must produce the
    # disposition AND poam_ref on a finding shaped like the one ingest_grype
    # emits. The register key is what vuln-gate.py resolves for that finding.
    reg = _real_register()["dispositions"]
    for key, entry in reg.items():
        finding = {"source": "grype", "tracking_id": key, "cve": None, "tool_id": None}
        assert vdr_builder.register_vuln_id(finding) == key
        disposition, poam_ref = vdr_builder.classify_vulnerability(finding, reg)
        assert disposition == entry["disposition"], key
        assert poam_ref == entry["poam_ref"], key


def test_undispositioned_vulnerability_gets_no_poam_ref():
    finding = {"source": "grype", "tracking_id": "grype-CVE-2099-0001-pkg:npm/x@1.0.0"}
    assert vdr_builder.classify_vulnerability(finding, {}) == (None, None)


def test_disposition_without_poam_ref_confers_nothing():
    # Fail closed: a disposition with no POA&M home must leave the finding open
    # so invariant (h) catches it, never publish as handled-but-untracked.
    reg = {"grype-x": {"disposition": "false-positive", "justification": "x"}}
    finding = {"source": "grype", "tracking_id": "grype-x"}
    assert vdr_builder.classify_vulnerability(finding, reg) == (None, None)


def test_non_passing_disposition_confers_nothing():
    reg = {"grype-x": {"disposition": "risk-adjustment", "poam_ref": "POAM-034"}}
    finding = {"source": "grype", "tracking_id": "grype-x"}
    assert vdr_builder.classify_vulnerability(finding, reg) == (None, None)


def test_config_findings_never_use_the_register():
    # Checkov/tfsec/OPA findings stay on classify_finding; the register path must
    # not become a second, ungoverned suppression route for config scanners.
    reg = {"CKV_AWS_999": {"disposition": "false-positive", "poam_ref": "POAM-034"}}
    for source in ("checkov", "tfsec", "opa"):
        finding = {"source": source, "tracking_id": "CKV_AWS_999", "tool_id": "CKV_AWS_999"}
        assert vdr_builder.classify_vulnerability(finding, reg) == (None, None), source


def test_builder_and_gate_agree_on_id_resolution_and_pass_set():
    # If these two drift, a finding could carry a poam_ref the vulnerability gate
    # never approved (or vice versa).
    assert vdr_builder.REGISTER_PASS_DISPOSITIONS == vg.PASS_DISPOSITIONS
    assert vdr_builder.VULN_SOURCES == vg.VULN_SOURCES
    for finding in (
        {"cve": "CVE-2026-1", "tracking_id": "grype-CVE-2026-1-pkg", "tool_id": "CVE-2026-1"},
        {"cve": None, "tracking_id": "grype-GHSA-x-pkg", "tool_id": "GHSA-x"},
        {"cve": None, "tracking_id": None, "tool_id": "GHSA-x"},
    ):
        gate_id = finding.get("cve") or finding.get("tracking_id") or finding.get("tool_id")
        assert vdr_builder.register_vuln_id(finding) == gate_id


def test_kev_still_blocks_a_dispositioned_vulnerability():
    # A register entry must never buy an actively-exploited CVE out of the gate.
    reg = {"CVE-2026-7777": {"disposition": "false-positive", "poam_ref": "POAM-034"}}
    finding = {
        "source": "grype", "tool_id": "CVE-2026-7777", "cve": "CVE-2026-7777",
        "tracking_id": "grype-CVE-2026-7777-pkg:npm/x@1.0.0",
        "title": "x", "severity": "HIGH", "resource": "pkg:npm/x@1.0.0",
    }
    report, blocking = vdr_builder.build_report(
        [finding], [], {"CVE-2026-7777"}, {}, disposition_register=reg)
    assert blocking == ["grype-CVE-2026-7777-pkg:npm/x@1.0.0"]
    assert report["findings"][0]["is_blocking"] is True
    # It still carries its POA&M home — blocking and untracked are different things.
    assert report["findings"][0]["poam_ref"] == "POAM-034"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
