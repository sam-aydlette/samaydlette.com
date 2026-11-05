"""Gate modes are governed decision records (REQ-GAT-1, REQ-GAT-4, T53), and every
gate rejects a committed known-bad input (REQ-GAT-2).

The register (infrastructure/schemas/gate-modes.json) names the mode of every
check that implements a gate. The loader fails the build on a mode changed
without a decision record. The known-bad inputs under tests/fixtures/gates/ are
each rejected by the gate's own entry point, for that gate's reason.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
REGISTER = REPO / "infrastructure" / "schemas" / "gate-modes.json"
SCHEMA = REPO / "infrastructure" / "schemas" / "gate-modes.schema.json"
FIX = REPO / "tests" / "fixtures" / "gates"
TODAY = date(2026, 11, 4)

sys.path.insert(0, str(REPO / "scripts"))
import _gates  # noqa: E402


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def good():
    return json.loads(REGISTER.read_text())


def entry(cfg, check):
    return next(e for e in cfg["checks"] if e["check"] == check)


def write(tmp_path, cfg):
    p = tmp_path / "gate-modes.json"
    p.write_text(json.dumps(cfg))
    return p


# ---- the register -------------------------------------------------------------------

def test_committed_register_loads_and_matches_its_schema():
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(good(), json.loads(SCHEMA.read_text()))
    reg = _gates.load_gate_modes(REGISTER, today=TODAY)
    assert set(reg["checks"]) == set(_gates.CHECKS)
    assert len(reg["sha256"]) == 64


def test_every_gate_has_a_check():
    assert set(_gates.CHECKS.values()) == set(_gates.GATES)


def test_t53_mode_changed_without_a_decision_record_fails_the_build():
    with pytest.raises(SystemExit, match="vdr.past-deadline: mode detect-and-recover differs from the method default with no reason"):
        _gates.load_gate_modes(FIX / "gate-modes-undecided.json", today=TODAY)


@pytest.mark.parametrize("field", ["decided_by", "decided_on", "review_by"])
def test_an_entry_without_its_decision_fields_fails(tmp_path, field):
    cfg = good()
    del entry(cfg, "vdr.kev")[field]
    with pytest.raises(SystemExit, match=f"missing keys \\['{field}'\\]"):
        _gates.load_gate_modes(write(tmp_path, cfg), today=TODAY)


def test_a_lapsed_deviation_fails(tmp_path):
    cfg = good()
    e = entry(cfg, "runtime-divergence.observer-fault")
    assert e["mode"] == "detect-and-recover"
    e["review_by"] = "2026-11-01"
    with pytest.raises(SystemExit, match="lapsed on 2026-11-01"):
        _gates.load_gate_modes(write(tmp_path, cfg), today=TODAY)


def test_a_lapsed_default_does_not_weaken_anything(tmp_path):
    cfg = good()
    entry(cfg, "vdr.kev")["review_by"] = "2026-01-01"
    assert _gates.blocks(_gates.load_gate_modes(write(tmp_path, cfg), today=TODAY), "vdr.kev")


def test_an_unrecorded_check_fails(tmp_path):
    cfg = good()
    cfg["checks"] = [e for e in cfg["checks"] if e["check"] != "reconcile.e"]
    with pytest.raises(SystemExit, match="no recorded mode: \\['reconcile.e'\\]"):
        _gates.load_gate_modes(write(tmp_path, cfg), today=TODAY)


def test_an_unknown_check_or_wrong_gate_fails(tmp_path):
    cfg = good()
    cfg["checks"].append({**entry(cfg, "vdr.kev"), "check": "vdr.made-up"})
    with pytest.raises(SystemExit, match="not a check any gate implements"):
        _gates.load_gate_modes(write(tmp_path, cfg), today=TODAY)
    cfg = good()
    entry(cfg, "vdr.kev")["gate"] = "G3"
    with pytest.raises(SystemExit, match="implements G1"):
        _gates.load_gate_modes(write(tmp_path, cfg), today=TODAY)


def test_missing_register_fails(tmp_path):
    with pytest.raises(SystemExit, match="not found"):
        _gates.load_gate_modes(tmp_path / "absent.json", today=TODAY)


def test_g1_records_that_it_is_stricter_than_the_method():
    e = entry(good(), "vdr.kev")
    assert e["mode"] == "block" and "Stricter than the method" in e["reason"]


def test_events_are_recorded_for_the_status_beacon(tmp_path, monkeypatch):
    reg = _gates.load_gate_modes(REGISTER, today=TODAY)
    events = tmp_path / "events.jsonl"
    monkeypatch.setenv(_gates.EVENTS_ENV, str(events))
    _gates.record_event(reg, "runtime-divergence.observer-fault", "stale", now=datetime(2026, 11, 4, tzinfo=timezone.utc))
    assert _gates.read_events(events) == [{"check": "runtime-divergence.observer-fault", "gate": "G7",
                                           "mode": "detect-and-recover", "detail": "stale",
                                           "at": "2026-11-04T00:00:00+00:00"}]


# ---- G1, G2, G3 through the VDR builder ----------------------------------------------

def _build(tmp_path, case, register=None):
    work = tmp_path / case
    shutil.copytree(FIX / case, work)
    sig = "ksi-signal.json" if (work / "ksi-signal.json").exists() else "absent.json"
    env = {k: v for k, v in os.environ.items() if k != "GITHUB_ACTIONS"}
    if register:
        env["GATE_MODES_FILE"] = str(register)
    r = subprocess.run([sys.executable, str(REPO / "scripts" / "build-vdr-report.py"),
                        "--grype", "grype.json", "--kev", "kev.json", "--previous-vdr", "previous-vdr.json",
                        "--ksi-signal", sig, "--checkov-yaml", "absent.yaml", "--opa", "absent.json",
                        "--md-output", "", "--output", "out.json"],
                       cwd=work, capture_output=True, text=True, env=env)
    report = json.loads((work / "out.json").read_text())
    return r, report


@pytest.mark.parametrize("case,reason", [
    ("g1-kev", "KEV (CISA Known Exploited Vulnerability)"),
    ("g2-top-impact", "N5+LEV+IRV"),
    ("g3-past-deadline", "past Class C SLA"),
])
def test_known_bad_input_is_rejected_for_its_gate(tmp_path, case, reason):
    r, report = _build(tmp_path, case)
    assert r.returncode == 1, r.stderr
    (f,) = report["findings"]
    assert f["is_blocking"] and f["block_reason"].startswith(reason)
    assert "VDR build-block" in r.stderr


def test_the_report_publishes_the_modes_it_ran_under(tmp_path):
    _, report = _build(tmp_path, "g1-kev")
    gates = report["methodology"]["gates"]
    assert gates["sha256"] == _gates.load_gate_modes(REGISTER)["sha256"]
    assert {c["check"]: c["mode"] for c in gates["checks"]}["vdr.kev"] == "block"


def test_a_recorded_detect_and_recover_mode_publishes_instead_of_blocking(tmp_path):
    cfg = good()
    e = entry(cfg, "vdr.past-deadline")
    e.update(mode="detect-and-recover", reason="fixture", review_by="2099-01-01")
    r, report = _build(tmp_path, "g3-past-deadline", register=write(tmp_path, cfg))
    assert r.returncode == 0, r.stderr
    assert "G3 vdr.past-deadline (detect-and-recover)" in r.stderr
    assert report["summary"]["blocking"] == 1  # still published as blocking-tier; the run continues


def test_the_builder_refuses_an_undecided_register(tmp_path):
    work = tmp_path / "w"
    shutil.copytree(FIX / "g1-kev", work)
    r = subprocess.run([sys.executable, str(REPO / "scripts" / "build-vdr-report.py"), "--grype", "grype.json",
                        "--kev", "kev.json", "--ksi-signal", "absent.json", "--checkov-yaml", "absent.yaml",
                        "--opa", "absent.json", "--md-output", "", "--output", "out.json"],
                       cwd=work, capture_output=True, text=True,
                       env={**{k: v for k, v in os.environ.items() if k != "GITHUB_ACTIONS"},
                            "GATE_MODES_FILE": str(FIX / "gate-modes-undecided.json")})
    assert r.returncode != 0 and "differs from the method default with no reason" in r.stderr
    assert not (work / "out.json").exists()


# ---- the vulnerability gate (G3) ---------------------------------------------------

def test_vuln_gate_rejects_its_known_bad_input():
    r = subprocess.run([sys.executable, str(REPO / "scripts" / "vuln-gate.py"),
                        "--vdr", str(FIX / "vuln-gate-unhandled.json")], capture_output=True, text=True)
    assert r.returncode == 1 and "CVE-2099-0004" in r.stderr


# ---- the runtime divergence gate (G4, G7) -------------------------------------------

def test_divergence_gate_rejects_its_known_bad_input():
    rd = _load("rd_gate", "check-runtime-divergence.py")
    signal = json.loads((FIX / "runtime-divergence-diverged.json").read_text())
    code, lines = rd.evaluate(signal, 48, now=datetime(2026, 11, 4, 12, tzinfo=timezone.utc))
    assert code == rd.BLOCK and any("KSI-FIXTURE-01" in line for line in lines)


def test_divergence_observer_fault_follows_its_recorded_mode(tmp_path, monkeypatch):
    rd = _load("rd_gate2", "check-runtime-divergence.py")
    signal = {"emitted_at": "2026-11-04T06:00:00+00:00", "divergence": {"status": "degraded", "unassessed": [{"ksi_id": "K"}]}}
    now = datetime(2026, 11, 4, 12, tzinfo=timezone.utc)
    assert rd.evaluate(signal, 48, now=now)[0] == rd.PASS
    cfg = good()
    entry(cfg, "runtime-divergence.observer-fault").update(mode="block")
    entry(cfg, "runtime-divergence.observer-fault").pop("reason")
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("GATE_MODES_FILE", str(write(tmp_path, cfg)))
    assert rd.evaluate(signal, 48, now=now)[0] == rd.BLOCK


# ---- reconcile (G4, G5, G6) ------------------------------------------------------------

def test_reconcile_names_the_invariants_its_broken_fixture_violates(tmp_path):
    broken = REPO / "tests" / "fixtures" / "broken"
    r = subprocess.run([sys.executable, str(REPO / "scripts" / "reconcile.py"), "--artifacts-dir", str(broken)],
                       capture_output=True, text=True)
    assert r.returncode == 1
    failed = {line.split("(")[1][0] for line in r.stderr.splitlines() if line.strip().startswith("✗ (")}
    assert {"b", "c", "d", "e"} <= failed, r.stderr


def test_reconcile_check_names_cover_every_invariant():
    rec = _load("rec_names", "reconcile.py")
    letters = set(rec.INVARIANT_TITLES)
    assert {f"reconcile.{x}" for x in letters} <= set(_gates.CHECKS)


def test_reconcile_unreadable_tags_now_block():
    assert _gates.blocks(_gates.load_gate_modes(REGISTER, today=TODAY), "reconcile.i.unreadable")


# ---- publication: the trust center queues a detect-and-recover event ---------------

def test_trust_center_queues_each_gate_event_once_with_its_opening_time():
    tc = _load("tc_gates", "build-trust-center.py")
    inp = {"vdr": {"methodology": {"gate_events": [
               {"check": "detection.zap.missing", "gate": "G7", "mode": "detect-and-recover",
                "detail": "no report", "at": "2026-11-04T08:00:00+00:00"}]}},
           "vdr_status": {"gate_events": [
               {"check": "detection.zap.missing", "gate": "G7", "mode": "detect-and-recover",
                "detail": "no report", "at": "2026-11-03T08:00:00+00:00"},
               {"check": "not-a-check", "at": "garbage"}]}}
    events = tc.gate_events(inp)
    assert list(events) == ["detection.zap.missing"]
    assert events["detection.zap.missing"]["at"] == "2026-11-03T08:00:00+00:00"
    assert tc.OPTIONS["gate_detect_recover"] and tc.WHY_YOURS["gate_detect_recover"]
    assert "gate_detect_recover" in tc.SINCE_SOURCE


def test_ci_never_honors_a_register_override(monkeypatch):
    monkeypatch.setenv("GATE_MODES_FILE", str(FIX / "gate-modes-undecided.json"))
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    with pytest.raises(SystemExit, match="not honored in CI"):
        _gates.load_gate_modes(today=TODAY)


def test_event_detail_cannot_forge_a_workflow_command(tmp_path, monkeypatch, capsys):
    reg = _gates.load_gate_modes(REGISTER, today=TODAY)
    monkeypatch.setenv(_gates.EVENTS_ENV, str(tmp_path / "e.jsonl"))
    _gates.record_event(reg, "detection.zap.missing", "x\n::error::forged\r\n")
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and "::error::forged" not in err
    assert "\n" not in _gates.read_events(tmp_path / "e.jsonl")[0]["detail"]
