"""The triage policy decides the VDR report (T7, G17).

policies/triage.rego takes the facts the builder collects and returns every
decision the report publishes: likely exploitability (Figure 7), reachability,
dispositions in force, the remediation timeframe from FedRAMP's rules, the
deadline, the maximum period and blocking. The builder makes one `opa eval` per
report and fails closed on any error.

Parity: the golden report was produced by the Python decision code as of T6. The
same inputs through the current builder must give an identical report.
"""
import importlib.util
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "triage"
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(FIX))
import _triage  # noqa: E402
import golden_cases  # noqa: E402


def _vdr():
    spec = importlib.util.spec_from_file_location("vdr_t7", REPO / "scripts" / "build-vdr-report.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


vdr = _vdr()
NOW = golden_cases.NOW
NS = _triage.to_ns(NOW)


def item(**kw):
    base = {"id": "f1", "kind": "finding", "pain": "N2", "is_kev": False, "exploitation": None, "metrics": {},
            "epss": None, "fully_mitigated": False,
            "reach": {"observed": False, "component_id": "c", "is_package": False, "declared": True},
            "mitigation": None, "check_decision": None, "register": None, "advisory": "CVE-0000-0001",
            "resource": "r", "fix_state": None, "clock": {"start_ns": NS, "first_evaluated_ns": NS}}
    base.update(kw)
    return base


def decide(items, rules_dir=_triage._rules.RULES_DIR, **kw):
    return _triage.decide(items, now=NOW, epss_threshold=0.1, margin_days=5,
                          lev_overrides=kw.get("lev_overrides"), rules_dir=rules_dir)


# --- parity with the T6 Python decisions -------------------------------------------

def test_golden_report_is_unchanged(monkeypatch):
    expected = json.loads((FIX / "golden-report.json").read_text())
    got = json.loads(json.dumps(golden_cases.build(vdr, golden_cases.cases(), monkeypatch), sort_keys=True))
    assert got["blocking"] == expected["blocking"]
    for g, e in zip(got["report"]["findings"], expected["report"]["findings"], strict=True):
        assert g == e, g["tracking_id"]
    assert got == expected


def test_golden_cases_cover_every_decision_branch():
    rep = json.loads((FIX / "golden-report.json").read_text())["report"]
    f = rep["findings"]
    assert {x["lev_basis"] for x in f} >= {"fully-mitigated", "known-exploited", "exploitation-observed", "floor",
                                          "no-direct-impact", "prediction", "no-score", "mitigation", "override"}
    assert {x["irv_basis"] for x in f} >= {"observed", "unresolved", "package-host-unrecorded", "inventory",
                                          "mitigation"}
    assert {(x["disposition_record"] or {}).get("status") for x in f} >= {"in-force", "lapsed", "invalid"}
    assert {x["block_reason"].split(" ")[0] for x in f if x["block_reason"]} >= {"KEV", "N5+LEV+IRV", "past"}
    assert any(x["will_be_overdue"] for x in f) and any(x["accepted"] for x in f)
    assert {r["lev_basis"] for r in rep["risk_accepted"]} >= {"no-score", "no-direct-impact"}


# --- the policy reads FedRAMP's rules ---------------------------------------------------

def test_timeframe_comes_from_data_rules():
    floor = {"AV": "N", "PR": "N", "UI": "N", "C": "H", "I": "N", "A": "N"}
    assert decide([item(metrics=floor)], FIX / "rules-minimal")[0]["sla_days"] == 48
    assert decide([item(metrics=floor)], FIX / "rules-changed-n2")[0]["sla_days"] == 7


def test_maximum_period_and_scale_come_from_data_rules():
    d = decide([item()], FIX / "rules-minimal")[0]
    assert d["accepted_ns"] == NS + 192 * 86400 * 10**9
    fm = decide([item(fully_mitigated=True, pain="N4")], FIX / "rules-minimal")[0]
    assert fm["pain"] == "N1" and fm["sla_days"] is None and fm["needs_remediation"] is False


def test_policy_table_equals_the_builders_rules_reader():
    for (pain, lev, irv), days in _triage._rules.class_c_timeframes().items():
        assert vdr.class_c_sla_days(pain, lev, irv) == days


# --- fail closed (known-bad fixtures) ---------------------------------------------------------

def test_rules_without_maximum_period_fail_closed():
    with pytest.raises(SystemExit, match="VER-TFR-MAV"):
        decide([item()], FIX / "rules-no-mav")


def test_rules_missing_a_timeframe_cell_fail_closed():
    with pytest.raises(SystemExit, match="no Class C timeframe"):
        decide([item(pain="N4", epss=0.0)], FIX / "rules-missing-cell")


def test_impact_off_the_rules_scale_fails_closed():
    with pytest.raises(SystemExit, match="not on the rules' scale"):
        decide([item(pain="N9")])


def test_broken_policy_fails_closed():
    with pytest.raises(SystemExit, match="opa eval exited"):
        _triage.evaluate("data.vdr.triage.decisions", {"items": []}, policy=FIX / "broken.rego")


def test_missing_opa_fails_closed(monkeypatch):
    monkeypatch.setattr(_triage.shutil, "which", lambda name: None)
    with pytest.raises(SystemExit, match="'opa' is not on PATH"):
        decide([item()])


def test_a_decision_out_of_order_fails_closed(monkeypatch):
    real = _triage.evaluate

    def swapped(query, doc, *a, **k):
        out = real(query, doc, *a, **k)
        out["decisions"].reverse()
        return out

    monkeypatch.setattr(_triage, "evaluate", swapped)
    with pytest.raises(SystemExit, match="in the place of"):
        decide([item(id="a"), item(id="b")])


# --- one evaluation per report; no decisions left in Python -----------------------------------

def test_builder_evaluates_the_policy_once_per_report(monkeypatch):
    calls = []
    real = subprocess.run

    def counting(cmd, *a, **k):
        if cmd and str(cmd[0]).endswith("opa"):
            calls.append(cmd)
        return real(cmd, *a, **k)

    monkeypatch.setattr(_triage.subprocess, "run", counting)
    golden_cases.build(vdr, golden_cases.cases(), monkeypatch)
    assert len(calls) == 1
    assert calls[0][calls[0].index("-d") + 1] == str(_triage.POLICY)


def test_no_decision_code_remains_in_the_builder():
    src = (REPO / "scripts" / "build-vdr-report.py").read_text()
    for gone in ("def evaluate_disposition", "def irv_determination", "def clock_for", "CLOSING_DISPOSITIONS",
                 "REGISTER_PASS_DISPOSITIONS", "DISPOSITIONS = {"):
        assert gone not in src, gone
    assert not re.search(r'return (True|False), "(floor|prediction|no-score|known-exploited)"', src)
    assert not re.search(r"timedelta\(days=(sla|mav)", src)


def test_kev_blocks_even_when_dispositioned_false_positive():
    reg = {"key": "CVE-0000-0001", "entry": {"disposition": "false-positive", "poam_ref": "POAM-1"}}
    d = decide([item(is_kev=True, register=reg)])[0]
    assert d["closed"] is True and d["blocking"] is True and d["block_rule"] == "kev"


def test_vocabulary_matches_the_vulnerability_gate():
    spec = importlib.util.spec_from_file_location("vg_t7", REPO / "scripts" / "vuln-gate.py")
    vg = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vg)
    v = _triage.vocabulary()
    assert v["pass"] == vg.PASS_DISPOSITIONS
    assert v["pass"] <= v["dispositions"]


def test_nanosecond_round_trip_is_exact():
    dt = datetime.fromisoformat("2026-07-26T12:00:00.123456+00:00")
    assert _triage.from_ns(_triage.to_ns(dt)) == dt.isoformat()


def test_nightly_and_deploy_pin_the_same_opa():
    def pins(name):
        text = (REPO / ".github" / "workflows" / name).read_text()
        return {k: re.search(rf"^  {k}: (\S+)", text, re.M).group(1) for k in ("OPA_VERSION", "OPA_SHA256")}
    assert pins("evidence-nightly.yml") == pins("deploy-with-opa.yml")
