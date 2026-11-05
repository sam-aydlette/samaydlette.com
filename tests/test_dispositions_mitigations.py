"""Dispositions and mitigations (REQ-DSP-1..4, vendor dependency, rule 1;
Appendix B T15, T16, T23, T24, T25).

A disposition past review_by is absent. A control-protected finding is
mitigated, never a false positive. A mitigation names a control in the
inventory and a verifying check; it is void when the control changes or the
check stops passing, and the finding returns to its pre-mitigation evaluation
on its pre-mitigation clock. Rule 1: a mitigation whose verifying check reads
live state (the signed runtime signal) makes the finding fully mitigated, which
is NLEV at the scale's lowest level. A vendor dependency lapses on the first
scan where a fix is available; an unknown fix state counts as available.
"""
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "dispositions"
PUBKEY = REPO / "infrastructure" / "keys" / "runtime-signing-key.json"


def _module(name, filename):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / filename)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


vdr = _module("vdr", "build-vdr-report.py")
vg = _module("vuln_gate", "vuln-gate.py")
CFG, _ = vdr.load_pain_config()
NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
TODAY = NOW.date()
FLOOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"


def iso(days_ago):
    return (NOW - timedelta(days=days_ago)).isoformat()


WAF = {"component_id": "aws::waf::edge", "type": "waf",
       "attributes": {"tf_address": "aws_wafv2_web_acl.edge", "setting": "block-xml"}}


def inventory(component=WAF, deploy_result="pass"):
    return {"index": {}, "tf": [], "classes": {}, "types": {},
            "components": {component["component_id"]: component},
            "validations": [{"policy": {"id": "terraform.compliance"}, "result": deploy_result,
                             "component_refs": [component["component_id"]]}]}


def runtime(result="pass", verified=True, fresh=True, cid="aws::waf::edge"):
    return {"verified": verified, "fresh": fresh, "reason": None,
            "validations": [{"policy": {"id": "terraform.compliance"}, "result": result,
                             "component_refs": [cid]}]}


def mitigation(effect="full", signal="runtime", fingerprint=None, review_by="2027-11-01", **kw):
    m = {"finding": "CVE-0000-0300",
         "control": {"component_id": "aws::waf::edge",
                     "fingerprint": fingerprint or vdr.component_fingerprint(WAF),
                     "setting": "block-xml"},
         "verifying_check": {"signal": signal, "policy": "terraform.compliance"},
         "effect": effect, "justification": "the edge rule rejects the payload",
         "decided_by": "Operator", "decided_on": "2026-10-01", "review_by": review_by}
    m.update(kw)
    return {"MIT-1": m}


def finding(**kw):
    f = {"tracking_id": "grype-CVE-0000-0300-pkg:npm/a@1", "source": "grype", "tool_id": "CVE-0000-0300",
         "cve": "CVE-0000-0300", "resource": "pkg:npm/a@1", "severity": "HIGH", "cvss_vector": FLOOR}
    f.update(kw)
    return f


def build(findings, register=None, mitigations=None, inv=None, rt=None, ledger=None, kev=()):
    report, blocking = vdr.build_report(list(findings), [], set(kev), ledger or {}, config=CFG, now=NOW,
                                        disposition_register=register or {}, mitigations=mitigations or {},
                                        inventory=inv or inventory(), runtime=rt or runtime())
    return report, blocking


REG_MITIGATED = {"CVE-0000-0300": {"disposition": "mitigated", "mitigation": "MIT-1", "decision_id": "DEC-003",
                                   "justification": "edge rule", "decided_by": "Operator",
                                   "decided_on": "2026-10-01", "review_by": "2027-10-01"}}


# --- T16 / REQ-DSP-2: past review_by is absent ---------------------------------------

def test_t16_lapsed_disposition_is_absent_in_the_report():
    reg = vg.load_register(FIX / "register-lapsed.json")
    f = finding(tracking_id="grype-CVE-0000-0200-pkg:npm/a@1", cve="CVE-0000-0200", tool_id="CVE-0000-0200")
    report, _ = build([f], register=reg)
    r = report["findings"][0]
    assert r["current_disposition"] == "open" and r["decision_id"] is None
    assert r["disposition_record"]["status"] == "lapsed"
    assert report["summary"]["lapsed_dispositions"] == ["CVE-0000-0200"]


def test_t16_lapsed_disposition_fails_the_vulnerability_gate():
    reg = vg.load_register(FIX / "register-lapsed.json")
    v = {"id": "CVE-0000-0200", "severity": "HIGH", "source": "grype"}
    assert vg.find_unhandled([v], reg, today=TODAY) == [v]


def test_t16_lapsed_decision_record_voids_a_config_suppression():
    f = {"tracking_id": "checkov-CKV_AWS_18-aws_s3_bucket.logs", "source": "checkov", "tool_id": "CKV_AWS_18",
         "resource": "aws_s3_bucket.logs", "severity": "LOW"}
    records = {"DEC-028": {"decided_by": "Operator", "decided_on": "2025-01-01", "review_by": "2026-01-01"}}
    report, _ = vdr.build_report([f], [], set(), {}, config=CFG, now=NOW, decision_records=records)
    r = report["findings"][0]
    assert r["current_disposition"] == "open"
    assert r["disposition_record"]["status"] == "lapsed"


# --- REQ-DSP-1: unrecorded fields are published as "not recorded" ------------------

def test_dsp1_unrecorded_fields_are_published():
    reg = {"CVE-0000-0300": {"disposition": "operational-requirement", "decision_id": "DEC-003"}}
    r = build([finding()], register=reg)[0]["findings"][0]
    rec = r["disposition_record"]
    assert rec["status"] == "in-force"
    assert rec["decided_by"] == "not recorded" and rec["review_by"] == "not recorded"


# --- T15 / REQ-DSP-4: control-protected means mitigated, never a false positive -----

def test_t15_false_positive_naming_a_control_is_refused():
    reg = vg.load_register(FIX / "register-fp-names-control.json")
    f = finding(tracking_id="grype-CVE-0000-0201-pkg:npm/a@1", cve="CVE-0000-0201", tool_id="CVE-0000-0201")
    r = build([f], register=reg)[0]["findings"][0]
    assert r["current_disposition"] == "open"
    assert r["disposition_record"]["status"] == "invalid"
    assert "mitigated" in r["disposition_record"]["reason"]


def test_t15_control_protected_finding_is_fully_mitigated_at_the_lowest_level():
    r = build([finding()], register=REG_MITIGATED, mitigations=mitigation())[0]["findings"][0]
    assert r["current_disposition"] == "mitigated"
    assert r["fully_mitigated"] is True
    assert r["likely_exploitable"] is False and r["lev_basis"] == "fully-mitigated"
    assert r["current_pain"] == vdr._rules.impact_levels()[0]
    assert r["remediation_due_at"] is None and r["is_blocking"] is False


def test_fully_mitigated_is_not_accepted_at_the_maximum_period():
    led = {finding()["tracking_id"]: {"first_detected": iso(300), "first_evaluated": iso(300)}}
    r = build([finding()], register=REG_MITIGATED, mitigations=mitigation(), ledger=led)[0]["findings"][0]
    assert r["accepted"] is False


def test_fully_mitigated_kev_still_blocks():
    r = build([finding()], register=REG_MITIGATED, mitigations=mitigation(), kev={"CVE-0000-0300"})[0]["findings"][0]
    assert r["is_blocking"] is True


# --- T23: the control is named ---------------------------------------------------------

def test_t23_mitigation_names_its_control():
    r = build([finding()], register=REG_MITIGATED, mitigations=mitigation())[0]["findings"][0]
    m = r["mitigation"]
    assert m["id"] == "MIT-1" and m["valid"] is True
    assert m["control"]["component_id"] == "aws::waf::edge" and m["control"]["setting"] == "block-xml"


# --- Rule 1: only a live-read verifying check makes a finding fully mitigated --------

def test_rule1_full_effect_needs_a_live_read():
    r = build([finding()], register=REG_MITIGATED, mitigations=mitigation(signal="deploy"))[0]["findings"][0]
    assert r["mitigation"]["valid"] is False
    assert "live" in r["mitigation"]["void_reason"]
    assert r["fully_mitigated"] is False and r["current_disposition"] == "open"


def test_rule1_unverified_runtime_signal_is_not_a_live_read():
    r = build([finding()], register=REG_MITIGATED, mitigations=mitigation(),
              rt=runtime(verified=False))[0]["findings"][0]
    assert r["mitigation"]["valid"] is False and r["fully_mitigated"] is False


def test_rule1_stale_runtime_signal_is_not_a_live_read():
    r = build([finding()], register=REG_MITIGATED, mitigations=mitigation(),
              rt=runtime(fresh=False))[0]["findings"][0]
    assert r["mitigation"]["valid"] is False


def test_partial_mitigation_may_use_the_deploy_check():
    m = mitigation(effect="not-reachable", signal="deploy")
    r = build([finding()], mitigations=m)[0]["findings"][0]
    assert r["mitigation"]["valid"] is True
    assert r["internet_reachable"] is False and r["irv_basis"] == "mitigation"
    assert r["fully_mitigated"] is False


def test_lapsed_mitigation_is_void():
    r = build([finding()], register=REG_MITIGATED, mitigations=mitigation(review_by="2026-10-31"))[0]["findings"][0]
    assert r["mitigation"]["valid"] is False and "review_by" in r["mitigation"]["void_reason"]


# --- T24: the control changes --------------------------------------------------------

def _expired_ledger():
    # First evaluated 200 days ago; a mitigation moved the clock 30 days ago.
    return {finding()["tracking_id"]: {
        "first_detected": iso(200), "first_evaluated": iso(200), "clock_start": iso(30),
        "clock_basis": [{"start": iso(200), "mitigation": None}, {"start": iso(30), "mitigation": "MIT-1"}]}}


def test_t24_control_change_voids_the_mitigation_and_restores_the_old_clock():
    changed = {**WAF, "attributes": {**WAF["attributes"], "setting": "allow-all"}}
    m = mitigation(fingerprint=vdr.component_fingerprint(WAF))
    report, blocking = build([finding()], register=REG_MITIGATED, mitigations=m, inv=inventory(changed),
                             ledger=_expired_ledger())
    r = report["findings"][0]
    assert r["mitigation"]["valid"] is False and "changed" in r["mitigation"]["void_reason"]
    assert r["fully_mitigated"] is False and r["current_disposition"] == "open"
    assert r["clock_start"] == iso(200)
    assert r["is_overdue"] is True and r["is_blocking"] is True  # G3 fails in the same build
    assert blocking == [finding()["tracking_id"]]
    assert "mitigation MIT-1 void" in r["rating_history"][-1]["reason"]


def test_t24_valid_mitigation_keeps_its_clock():
    report, _ = build([finding()], register=REG_MITIGATED, mitigations=mitigation(), ledger=_expired_ledger())
    assert report["findings"][0]["clock_start"] == iso(30)


# --- T25: the observer finds the control no longer works ------------------------------

def test_t25_failing_live_check_voids_the_mitigation():
    report, blocking = build([finding()], register=REG_MITIGATED, mitigations=mitigation(),
                             rt=runtime(result="fail"), ledger=_expired_ledger())
    r = report["findings"][0]
    assert r["mitigation"]["valid"] is False and "check" in r["mitigation"]["void_reason"]
    assert r["clock_start"] == iso(200) and r["is_blocking"] is True


def test_t25_control_missing_from_the_inventory_voids_the_mitigation():
    other = {"component_id": "aws::waf::other", "type": "waf", "attributes": {}}
    r = build([finding()], register=REG_MITIGATED, mitigations=mitigation(), inv=inventory(other),
              rt=runtime(cid="aws::waf::other"))[0]["findings"][0]
    assert r["mitigation"]["valid"] is False


# --- The signed runtime signal ------------------------------------------------------------

def test_runtime_signal_genuine_verifies_against_the_committed_key():
    sig = json.loads((FIX / "runtime-signal-genuine.json").read_text())
    at = datetime.fromisoformat(sig["emitted_at"].replace("Z", "+00:00")) + timedelta(hours=1)
    rt = vdr.load_runtime_signal(FIX / "runtime-signal-genuine.json", PUBKEY, now=at)
    assert rt["verified"] is True and rt["fresh"] is True and rt["validations"]


def test_runtime_signal_tampered_is_rejected():
    rt = vdr.load_runtime_signal(FIX / "runtime-signal-tampered.json", PUBKEY, now=NOW)
    assert rt["verified"] is False and rt["validations"] == []


def test_runtime_signal_rejected_when_the_pinned_key_record_is_altered(tmp_path):
    rec = json.loads(PUBKEY.read_text())
    rec["public_key_sha256"] = "0" * 64
    bad = tmp_path / "key.json"
    bad.write_text(json.dumps(rec))
    sig = json.loads((FIX / "runtime-signal-genuine.json").read_text())
    at = datetime.fromisoformat(sig["emitted_at"].replace("Z", "+00:00")) + timedelta(hours=1)
    assert vdr.load_runtime_signal(FIX / "runtime-signal-genuine.json", bad, now=at)["verified"] is False


def test_runtime_signal_missing_is_not_verified(tmp_path):
    rt = vdr.load_runtime_signal(tmp_path / "absent.json", PUBKEY, now=NOW)
    assert rt["verified"] is False


def test_runtime_signal_stale_is_not_fresh():
    sig = json.loads((FIX / "runtime-signal-genuine.json").read_text())
    at = datetime.fromisoformat(sig["emitted_at"].replace("Z", "+00:00")) + timedelta(days=10)
    assert vdr.load_runtime_signal(FIX / "runtime-signal-genuine.json", PUBKEY, now=at)["fresh"] is False


# --- Vendor dependency ----------------------------------------------------------------

REG_VD = {"CVE-0000-0300": {"disposition": "vendor-dependency", "decision_id": "DEC-003", "justification": "no fix",
                            "decided_by": "Operator", "decided_on": "2026-10-01", "review_by": "2027-10-01"}}


def test_vendor_dependency_in_force_while_no_fix():
    r = build([finding(fix_state="not-fixed")], register=REG_VD)[0]["findings"][0]
    assert r["current_disposition"] == "vendor-dependency" and r["fix_state"] == "not-fixed"
    assert r["remediation_due_at"] is not None  # the clock never pauses


@pytest.mark.parametrize("state", ["fixed", "unknown", None, "wont-fix"])
def test_vendor_dependency_lapses_when_a_fix_may_exist(state):
    r = build([finding(fix_state=state)], register=REG_VD)[0]["findings"][0]
    assert r["current_disposition"] == "open"
    assert r["disposition_record"]["status"] == "invalid"


def test_overdue_vendor_dependency_fails_the_deadline_gate():
    led = {finding()["tracking_id"]: {"first_detected": iso(100), "first_evaluated": iso(100)}}
    r = build([finding(fix_state="not-fixed")], register=REG_VD, ledger=led)[0]["findings"][0]
    assert r["current_disposition"] == "vendor-dependency"
    assert r["is_overdue"] is True and r["is_blocking"] is True


def test_gate_passes_vendor_dependency_only_without_a_fix():
    v = {"id": "CVE-0000-0300", "severity": "HIGH", "source": "grype", "fix_state": "not-fixed"}
    assert vg.find_unhandled([v], REG_VD, today=TODAY) == []
    v2 = {**v, "fix_state": "fixed"}
    assert vg.find_unhandled([v2], REG_VD, today=TODAY) == [v2]


def test_gate_passes_mitigated_only_with_a_valid_mitigation():
    v = {"id": "CVE-0000-0300", "severity": "HIGH", "source": "grype", "mitigation_valid": True}
    assert vg.find_unhandled([v], REG_MITIGATED, today=TODAY) == []
    v2 = {**v, "mitigation_valid": False}
    assert vg.find_unhandled([v2], REG_MITIGATED, today=TODAY) == [v2]


def test_gate_reads_evidence_from_the_vdr():
    report, _ = build([finding(fix_state="not-fixed")], register=REG_VD)
    vulns = vg.vulns_from_vdr(report)
    assert vulns[0]["fix_state"] == "not-fixed"
    assert vg.find_unhandled(vulns, REG_VD, today=TODAY) == []


def test_under_investigation_is_recorded_but_does_not_pass():
    reg = {"CVE-0000-0300": {**REG_VD["CVE-0000-0300"], "disposition": "under-investigation"}}
    r = build([finding()], register=reg)[0]["findings"][0]
    assert r["current_disposition"] == "under-investigation" and r["final_disposition"] == "open"
    v = {"id": "CVE-0000-0300", "severity": "HIGH", "source": "grype"}
    assert vg.find_unhandled([v], reg, today=TODAY) == [v]


def test_unknown_disposition_is_invalid():
    reg = {"CVE-0000-0300": {**REG_VD["CVE-0000-0300"], "disposition": "risk-adjustment"}}
    r = build([finding()], register=reg)[0]["findings"][0]
    assert r["current_disposition"] == "open" and r["disposition_record"]["status"] == "invalid"


# --- Fix state from the scanners ---------------------------------------------------------

def test_grype_fix_state_is_kept(tmp_path):
    p = tmp_path / "g.json"
    p.write_text(json.dumps({"matches": [{
        "vulnerability": {"id": "GHSA-x", "severity": "High", "fix": {"state": "not-fixed", "versions": []}},
        "artifact": {"name": "a", "version": "1", "purl": "pkg:npm/a@1"}}]}))
    f = vdr.ingest_grype(str(p))[0]
    assert f["fix_state"] == "not-fixed" and f["fix_versions"] == []


def test_dependabot_patched_version_sets_fix_state(tmp_path):
    p = tmp_path / "d.json"
    base = {"number": 1, "state": "open", "created_at": "2026-10-01T00:00:00Z",
            "security_advisory": {"ghsa_id": "GHSA-y", "severity": "high"},
            "dependency": {"package": {"ecosystem": "npm", "name": "a"}}}
    fixed = {**base, "security_vulnerability": {"first_patched_version": {"identifier": "1.2.3"}}}
    unfixed = {**base, "number": 2, "security_advisory": {"ghsa_id": "GHSA-z", "severity": "high"},
               "security_vulnerability": {"first_patched_version": None}}
    p.write_text(json.dumps([fixed, unfixed]))
    out = {f["tool_id"]: f for f in vdr.ingest_dependabot(str(p))}
    assert out["GHSA-y"]["fix_state"] == "fixed" and out["GHSA-y"]["fix_versions"] == ["1.2.3"]
    assert out["GHSA-z"]["fix_state"] == "not-fixed"


# --- Register hygiene ---------------------------------------------------------------------

def test_dispositions_without_a_current_finding_are_reported():
    reg = {"CVE-0000-0999": REG_VD["CVE-0000-0300"]}
    report, _ = build([finding()], register=reg)
    assert report["summary"]["unmatched_dispositions"] == ["CVE-0000-0999"]


def test_mitigations_without_a_current_finding_are_reported():
    m = mitigation(finding="CVE-0000-0998")
    report, _ = build([finding()], mitigations=m)
    assert report["summary"]["unmatched_mitigations"] == ["MIT-1"]


# --- Governed files -----------------------------------------------------------------------

def test_committed_mitigations_file_loads():
    vdr.load_mitigations(REPO / "data" / "mitigations.json")


def test_malformed_mitigation_fails_closed(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"mitigations": {"MIT-1": {"finding": "x", "effect": "full"}}}))
    with pytest.raises(SystemExit):
        vdr.load_mitigations(p)


def test_unknown_mitigation_effect_fails_closed(tmp_path):
    p = tmp_path / "m.json"
    m = mitigation()["MIT-1"]
    p.write_text(json.dumps({"mitigations": {"MIT-1": {**m, "effect": "partial"}}}))
    with pytest.raises(SystemExit):
        vdr.load_mitigations(p)


def test_fingerprint_is_stable_and_order_independent():
    a = {"component_id": "c", "attributes": {"x": 1, "y": 2}}
    b = {"attributes": {"y": 2, "x": 1}, "component_id": "c"}
    assert vdr.component_fingerprint(a) == vdr.component_fingerprint(b)
    assert vdr.component_fingerprint(a).startswith("sha256:")
