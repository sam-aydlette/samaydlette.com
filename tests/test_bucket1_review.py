"""Fixes from the pre-merge review of the VDR decision engine (#479).

Each test names the defect it pins:
  1  "wont-fix" (no fix coming) keeps a vendor dependency in force until the maximum period
  2  the boundary map counts a finding open by its final disposition, not its label
  3  the same Terraform address in two root modules is two findings
  4  observed exploitation is never cleared by an override or a mitigation
  5  observed reachability is never cleared by a not-reachable mitigation
  6  the vulnerability gate requires the evidence on every finding under one ID
  7  a void mitigation does not hide a valid one for the same finding
  9  an accepted finding publishes the recorded justification when one exists
"""
import importlib.util
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _triage  # noqa: E402


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


vdr = _load("vdr_review", "build-vdr-report.py")
vg = _load("vg_review", "vuln-gate.py")
bg = _load("bg_review", "build-boundary-graph.py")
NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
NS = _triage.to_ns(NOW)


def item(**kw):
    base = {"id": "f1", "kind": "finding", "pain": "N5", "is_kev": False, "exploitation": None, "metrics": {},
            "epss": None, "fully_mitigated": False,
            "reach": {"observed": False, "component_id": "c", "is_package": False, "declared": True},
            "mitigation": None, "check_decision": None, "register": None, "advisory": "CVE-0000-0001",
            "resource": "pkg:npm/a@1", "fix_state": None, "clock": {"start_ns": NS, "first_evaluated_ns": NS}}
    base.update(kw)
    return base


def decide(it, overrides=None):
    return _triage.decide([it], now=NOW, epss_threshold=0.1, margin_days=5, lev_overrides=overrides)[0]


# 1 ---------------------------------------------------------------------------------
VD = {"key": "CVE-0000-0001", "entry": {"disposition": "vendor-dependency", "poam_ref": "P1"}}


def test_wont_fix_keeps_a_vendor_dependency_in_force():
    d = decide(item(fix_state="wont-fix", register=VD))
    assert d["record_status"] == "in-force" and d["disposition"] == "vendor-dependency"
    assert d["due_ns"] is not None and d["accepted"] is False
    assert decide(item(fix_state="not-fixed", register=VD))["record_status"] == "in-force"
    for state in ("fixed", "unknown", None):
        assert decide(item(fix_state=state, register=VD))["record_status"] == "invalid", state


def test_wont_fix_vendor_dependency_is_accepted_at_the_maximum_period():
    old = NS - 192 * 86400 * 10**9
    d = decide(item(fix_state="wont-fix", register=VD, clock={"start_ns": old, "first_evaluated_ns": old}))
    assert d["record_status"] == "in-force" and d["accepted"] is True


def test_gate_agrees_on_fix_states():
    entry = {"disposition": "vendor-dependency", "poam_ref": "P1"}
    for state in ("not-fixed", "wont-fix"):
        assert vg.handled({"fix_state": state}, entry, date(2026, 11, 3)), state
    for state in ("fixed", "unknown", None):
        assert not vg.handled({"fix_state": state}, entry, date(2026, 11, 3)), state


# 2 ---------------------------------------------------------------------------------
def test_boundary_map_counts_a_labelled_but_open_finding_as_open():
    vdr_doc = {"findings": [
        {"component_id": "c1", "current_disposition": "vendor-dependency", "final_disposition": "open"},
        {"component_id": "c1", "current_disposition": "false-positive", "final_disposition": "false-positive"},
    ], "risk_accepted": [{"component_id": "c1", "current_disposition": "risk-accepted"}]}
    assert bg.finding_counts(vdr_doc)["c1"]["open"] == 1


# 3 ---------------------------------------------------------------------------------
def _sarif(tmp_path, results):
    doc = {"version": "2.1.0", "runs": [{"results": [
        {"ruleId": "CKV_AWS_18", "level": "warning", "message": {"text": "m"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                                             "region": {"startLine": 1, "snippet": {"text": 'resource "aws_s3_bucket" "logs" {'}}}}]}
        for uri in results]}]}
    p = tmp_path / "c.sarif"
    p.write_text(json.dumps(doc))
    return str(p)


def test_same_address_in_two_root_modules_is_two_findings(tmp_path):
    fs = vdr.ingest_checkov(_sarif(tmp_path, ["infrastructure/main.tf", "infrastructure/bootstrap/main.tf"]))
    ids = [f["tracking_id"] for f in fs]
    assert len(set(ids)) == 2
    # The main stack's identity is unchanged, so no clock moves.
    assert "checkov-CKV_AWS_18-aws_s3_bucket.logs" in ids
    assert len(vdr.dedupe_findings(fs)) == 2


def test_tfsec_identity_includes_the_root_module(tmp_path):
    p = tmp_path / "t.json"
    p.write_text(json.dumps({"results": [
        {"rule_id": "AVD-AWS-0089", "resource": "aws_s3_bucket.logs",
         "location": {"filename": "/github/workspace/infrastructure/main.tf", "start_line": 3}},
        {"rule_id": "AVD-AWS-0089", "resource": "aws_s3_bucket.logs",
         "location": {"filename": "/github/workspace/infrastructure/bootstrap/main.tf", "start_line": 3}}]}))
    ids = [f["tracking_id"] for f in vdr.ingest_tfsec(str(p))]
    assert ids[0] == "tfsec-AVD-AWS-0089-aws_s3_bucket.logs" and len(set(ids)) == 2


# 4 ---------------------------------------------------------------------------------
def test_override_never_clears_observed_exploitation():
    ov = {"O1": {"advisory": "CVE-0000-0001", "selector": "*", "exclusions": [], "lev": False,
                 "review_by": "2027-01-01"}}
    d = decide(item(exploitation="active"), ov)
    assert d["lev"] is True and d["lev_basis"] == "exploitation-observed" and d["lev_override"] is None


def test_mitigation_never_clears_observed_exploitation():
    m = {"id": "M", "valid": True, "effect": "not-likely-exploitable"}
    d = decide(item(exploitation="active", mitigation=m))
    assert d["lev"] is True and d["lev_basis"] == "exploitation-observed"


# 5 ---------------------------------------------------------------------------------
def test_observed_reachability_beats_a_not_reachable_mitigation():
    m = {"id": "M", "valid": True, "effect": "not-reachable"}
    d = decide(item(reach={"observed": True, "component_id": "c", "is_package": False, "declared": False},
                    mitigation=m))
    assert d["irv"] is True and d["irv_basis"] == "observed"


# 6 ---------------------------------------------------------------------------------
def test_gate_needs_the_evidence_on_every_finding_under_one_id():
    report = {"findings": [
        {"source": "grype", "cve": "CVE-X", "fix_state": "not-fixed"},
        {"source": "grype", "cve": "CVE-X", "fix_state": "fixed"},
    ]}
    for order in (report["findings"], list(reversed(report["findings"]))):
        vulns = vg.vulns_from_vdr({"findings": order})
        reg = {"CVE-X": {"disposition": "vendor-dependency", "poam_ref": "P1"}}
        assert [v["id"] for v in vg.find_unhandled(vulns, reg, date(2026, 11, 3))] == ["CVE-X"]


def test_gate_mitigated_needs_every_finding_mitigated():
    vulns = vg.vulns_from_vdr({"findings": [
        {"source": "grype", "cve": "CVE-X", "mitigation": {"valid": True}},
        {"source": "grype", "cve": "CVE-X", "mitigation": None}]})
    reg = {"CVE-X": {"disposition": "mitigated", "poam_ref": "P1"}}
    assert vg.find_unhandled(vulns, reg, date(2026, 11, 3))


# 7 ---------------------------------------------------------------------------------
def test_void_mitigation_does_not_hide_a_valid_one(monkeypatch):
    comp = {"component_id": "cmp", "type": "aws_s3_bucket"}
    fp = vdr.component_fingerprint(comp)
    base = {"finding": "CVE-0000-0001", "effect": "not-reachable", "justification": "j",
            "verifying_check": {"signal": "deploy", "policy": "P"},
            "decided_by": "Operator", "decided_on": "2026-10-01", "review_by": "2027-01-01"}
    mits = {"MIT-001": {**base, "control": {"component_id": "cmp", "fingerprint": "0" * 64}},
            "MIT-002": {**base, "control": {"component_id": "cmp", "fingerprint": fp}}}
    inv = {"components": {"cmp": comp},
           "validations": [{"policy": {"id": "P"}, "component_refs": ["cmp"], "result": "pass"}]}
    st = vdr.mitigation_state({"cve": "CVE-0000-0001", "tracking_id": "t"}, mits, inv, None, date(2026, 11, 3))
    assert st["id"] == "MIT-002" and st["valid"] is True
    assert set(st["matched"]) == {"MIT-001", "MIT-002"}


# 9 ---------------------------------------------------------------------------------
def test_accepted_finding_publishes_the_recorded_justification():
    f = {"tracking_id": "t1", "source": "grype", "cve": "CVE-0000-0001", "tool_id": "CVE-0000-0001",
         "resource": "pkg:npm/a@1", "severity": "HIGH", "fix_state": "not-fixed"}
    reg = {"CVE-0000-0001": {"disposition": "vendor-dependency", "poam_ref": "P1",
                             "justification": "No upstream fix; tracked with the vendor."}}
    led = {"t1": {"first_detected": "2026-01-01T00:00:00+00:00", "first_evaluated": "2026-01-01T00:00:00+00:00"}}
    r = vdr.build_report([f], [], set(), led, now=NOW, disposition_register=reg)[0]["findings"][0]
    assert r["accepted"] is True
    assert r["acceptance_explanation"] == "No upstream fix; tracked with the vendor."
