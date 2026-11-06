"""CDS-CSO-FID for the trust-center, scope and assessor files: each carries the
offering's FedRAMP ID at top level, and the deploy gate checks every one."""
import importlib.util
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _freshness  # noqa: E402
import _frr  # noqa: E402
import _offering  # noqa: E402
import _rules  # noqa: E402

FID = _offering.fedramp_id()
NOW = datetime(2026, 11, 5, 12, tzinfo=timezone.utc)
MINE = ("availability-probe.json", "trust-center.json", "trust-manifest.json", "availability.json", "policy-index.json",
        "assessor-guide.json", "simulated-assessment.json", "agency-access-exercise.json", "frr-evidence.json")


def _load(name, script):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / script)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


gate = _load("check_fedramp_id_g5", "check-fedramp-id.py")


def test_the_gate_lists_every_trust_center_file():
    assert set(MINE) <= set(gate.REPORTS)


def test_known_bad_a_site_file_without_a_fedramp_id_fails():
    bad = REPO / "tests" / "fixtures" / "cycle" / "bad" / "site-file-without-fedramp-id.json"
    assert gate.main([str(bad)]) == 1
    assert gate.problems("x.json", {"fedRampId": "something else"}, FID)
    assert gate.problems("x.json", {"fedRampId": FID}, FID) == []


def test_the_gate_runs_after_the_last_listed_file_is_built_and_before_publication():
    wf = (REPO / ".github" / "workflows" / "deploy-with-opa.yml").read_text()
    deploy = wf.split("\n  deploy:\n", 1)[1]
    gate_at = deploy.index("- name: FedRAMP ID in every FedRAMP report (CDS-CSO-FID)")
    for builder in ("- name: Build the trust center", "- name: Build the human-readable views and the trust manifest",
                    "- name: Build the assessor guide", "- name: Agency access register check",
                    "- name: Build Certification Package Overview (CPO)"):
        assert deploy.index(builder) < gate_at, builder
    assert gate_at < deploy.index("- name: Publication redaction gate")


def test_the_assessor_guide_and_manifest_carry_it(tmp_path):
    guide = _load("ag_fid", "build-assessor-guide.py").build(
        _frr.load(_frr.DEFAULT_PATH), _rules.applicable_provider_rules(),
        json.loads((REPO / "infrastructure" / "schemas" / "ksi-catalog.json").read_text()),
        {x["path"]: x for x in _freshness.load_freshness_config(
            REPO / "infrastructure" / "schemas" / "freshness-config.json")["artifacts"]}, NOW)
    assert guide["fedRampId"] == FID
    man = _load("tm_fid", "build-trust-manifest.py").build(
        _freshness.load_freshness_config(REPO / "infrastructure" / "schemas" / "freshness-config.json"),
        tmp_path, {"entries": []}, NOW)
    assert man["fedRampId"] == FID


def test_the_availability_feeds_carry_it(tmp_path):
    probe = _load("probe_fid", "availability-probe.py")
    now = datetime.now(timezone.utc)
    feed = probe.build({}, {"t": probe._iso(now), "probed": [k for k, *_ in probe.TARGETS], "fail": {}}, now)
    assert feed["fedRampId"] == FID
    (tmp_path / "f.json").write_text(json.dumps(feed))
    av = _load("av_fid", "build-availability.py")
    assert av.main(["--probe-feed", str(tmp_path / "f.json"), "--ksi-signal", str(tmp_path / "none.json"),
                    "--output", str(tmp_path / "a.json"), "--md-output", str(tmp_path / "a.md")]) == 0
    assert json.loads((tmp_path / "a.json").read_text())["fedRampId"] == FID


def test_the_agency_exercise_log_carries_it(tmp_path):
    aa = _load("aa_fid", "agency-access.py")
    out = tmp_path / "log.json"
    assert aa.main(["exercise", "--output", str(out), "--md-output", str(tmp_path / "log.md"),
                    "--today", date(2026, 11, 5).isoformat()]) == 0
    assert json.loads(out.read_text())["fedRampId"] == FID


def test_frr_evidence_carries_it(tmp_path, monkeypatch):
    ev = _load("ev_fid", "check-frr-evidence.py")
    ref = "tests/test_sdr.py::test_every_applicable_rule_is_listed_once"
    monkeypatch.setattr(ev._frr, "load", lambda _p: {"records": [
        {"frr_id": "SDR-CSO-FRR", "status": "Implemented", "evidence": [{"kind": "test", "ref": ref}]}]})
    out = tmp_path / "frr-evidence.json"
    ev.main(["--junit", str(REPO / "tests" / "fixtures" / "frr-evidence" / "passing.xml"), "--output", str(out)])
    assert json.loads(out.read_text())["fedRampId"] == FID
