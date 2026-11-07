"""KSI method count: facts (scripts/_ksi_methods.py), decision (policies/compliance/ksi.rego)."""

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _ksi_methods as km  # noqa: E402

NOW = datetime(2026, 11, 7, 12, tzinfo=timezone.utc)
FEEDS = [{"feed": f, "status": "ok"} for f in ("grype", "dependabot", "checkov", "tfsec")]


def _iso(hours_ago):
    return (NOW - timedelta(hours=hours_ago)).isoformat().replace("+00:00", "Z")


def _signal(results, emitted_hours_ago=1, divergence="converged"):
    """A KSI signal with one S3 bucket validated per entry of `results` (rule IDs that fired)."""
    comps, vals = [], []
    for i, fired in enumerate(results):
        cid = f"aws::object_store::b{i}"
        comps.append({"component_id": cid, "attributes": {"tf_type": "aws_s3_bucket"}})
        vals.append({"policy": {"id": "terraform.compliance"}, "result": "fail" if fired else "pass",
                     "component_refs": [cid], "violations": [{"id": r} for r in fired]})
    return {"emitted_at": _iso(emitted_hours_ago), "components": comps, "validations": vals,
            "divergence": {"status": divergence}}


def _inputs(**over):
    base = {
        "deploy_signal": _signal([[]]),
        "vdr": {"methodology": {"detection": {"feeds": FEEDS}}},
        "beacon": {"finished_at": _iso(2), "reconcile": "success", "detection": {"feeds": FEEDS}},
        "runtime_signal": _signal([[]]),
    }
    base.update(over)
    return base


def _status(**over):
    return km.decide(km.facts(now=NOW, **_inputs(**over)))


# --- registers -------------------------------------------------------------------

def test_the_committed_registers_load():
    known = km.catalog_ksis()
    assert len(known) == 46
    assert {m["key"] for m in km.load_methods(known=known)} == {
        "grype", "dependabot", "checkov-tfsec", "runtime-divergence", "reconcile", "plan-gate"}
    assert km.load_applicability(known=known) == [{
        "ksi_id": "KSI-SVC-RUD", "approved": True,
        "not_applicable": km.load_applicability(known=known)[0]["not_applicable"]}]


@pytest.mark.parametrize("bad", [
    {"ksis": ["KSI-NOT-REAL"]},
    {"stages": ["someday"]},
    {"observe": {"kind": "vibes"}},
    {"observe": {"kind": "detection-feed", "feeds": []}},
    {"measure": ""},
    {"extra": 1},
])
def test_known_bad_methods_fail(tmp_path, bad):
    m = {"key": "k", "ksis": ["KSI-SCR-MON"], "observe": {"kind": "plan-gate"}, "stages": ["deploy"], "measure": "m"}
    m.update(bad)
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"schema": "ksi-methods/2", "methods": [m]}))
    with pytest.raises(SystemExit):
        km.load_methods(p)


def test_an_unsigned_scope_cut_is_not_approved(tmp_path):
    p = tmp_path / "a.json"
    p.write_text(json.dumps({"schema": "ksi-applicability/2", "ksis": [
        {"ksi_id": "KSI-SVC-RUD", "status": "Not Applicable", "not_applicable": "t",
         "approval": {"by": "AI-drafted", "on": "2026-11-07"}}]}))
    assert km.load_applicability(p)[0]["approved"] is False


# --- the count: a bad input changes the result --------------------------------------

def test_plan_and_live_of_the_same_rule_make_two_methods():
    assert _status()["ksis"]["KSI-RPL-ABO"]["status"] == "Implemented"


def test_a_live_violation_fails_the_ksi():
    out = _status(runtime_signal=_signal([["versioning_disabled"]]))["ksis"]["KSI-RPL-ABO"]
    assert out["status"] == "Not Demonstrated"
    assert out["failing"] == ["opa:versioning_disabled@live"]


def test_a_stale_runtime_signal_earns_no_live_credit():
    out = _status(runtime_signal=_signal([[]], emitted_hours_ago=30))
    assert out["ksis"]["KSI-RPL-ABO"]["passing"] == 1
    assert "KSI-RPL-ABO" in out["short"]


def test_a_stale_beacon_earns_no_nightly_credit():
    fresh = _status()["ksis"]["KSI-SCR-MIT"]
    stale = _status(beacon={**_inputs()["beacon"], "finished_at": _iso(30)})["ksis"]["KSI-SCR-MIT"]
    assert (fresh["passing"], stale["passing"]) == (2, 1)


def test_a_failing_feed_fails_its_method():
    feeds = [dict(f, status="stale") if f["feed"] == "grype" else f for f in FEEDS]
    out = _status(vdr={"methodology": {"detection": {"feeds": feeds}}})["ksis"]["KSI-SCR-MIT"]
    assert out["failing"] == ["check:grype@deploy"]


def test_a_missing_feed_is_not_a_method():
    feeds = [f for f in FEEDS if f["feed"] != "tfsec"]
    out = _status(vdr={"methodology": {"detection": {"feeds": feeds}}})["ksis"]["KSI-CNA-IBP"]
    assert out["methods"] == [{"method": "check:checkov-tfsec", "stage": "nightly", "passed": True}]


def test_divergence_fails_the_runtime_method():
    out = _status(runtime_signal=_signal([[]], divergence="diverged"))["ksis"]["KSI-SVC-ACM"]
    assert "check:runtime-divergence@live" in out["failing"]


def test_the_approved_scope_cut_is_not_applicable_and_not_short():
    out = _status()
    assert out["ksis"]["KSI-SVC-RUD"]["status"] == "Not Applicable"
    assert "KSI-SVC-RUD" not in out["short"]


# --- annotations the count depends on ---------------------------------------------------

def test_tagging_rules_declare_the_types_the_config_tags():
    cfg = json.loads((REPO / "infrastructure" / "policy" / "config" / "data.json").read_text())
    gate = cfg.get("gate") or cfg["config"]["gate"]
    rules = {r["id"]: r for r in km.rule_annotations()}
    assert rules["missing_classification_tag"]["resource_types"] == sorted(gate["taggable_types"])
    assert rules["missing_required_tags"]["resource_types"] == sorted(gate["governance_tag_types"])


def test_a_rule_with_ksis_but_no_resource_types_fails_the_annotation_check(tmp_path):
    (tmp_path / "p.rego").write_text("""package policy.x

# METADATA
# custom:
#   id: x
#   category: infrastructure
#   severity: HIGH
#   nist_controls: []
#   ksi_ids: [KSI-SCR-MON]
violations contains v if {
\tsome v in input.nothing
}
""")
    cmd = [sys.executable, str(REPO / "scripts" / "check-policy-annotations.py"), "--policy-dir", str(tmp_path)]
    bad = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert bad.returncode == 1 and "resource_types" in bad.stderr
    (tmp_path / "p.rego").write_text((tmp_path / "p.rego").read_text().replace(
        "#   ksi_ids: [KSI-SCR-MON]\n", "#   ksi_ids: [KSI-SCR-MON]\n#   resource_types: [aws_s3_bucket]\n"))
    assert subprocess.run(cmd, capture_output=True, text=True, check=False).returncode == 0
