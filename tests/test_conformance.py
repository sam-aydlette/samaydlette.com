"""REQ-GOV-2: every output names the profile version it conforms to and carries
the signed results of that version's conformance tests.

data/method-profile.json maps Appendix B (T1-T74) to the tests that implement
them; scripts/build-conformance.py runs them and records the results. These
tests pin the profile's validation (fail closed), the result logic, and that the
outputs carry the profile.
"""
import copy
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parent.parent
PROFILE = REPO / "data" / "method-profile.json"
FIX = REPO / "tests" / "fixtures" / "conformance"
NOW = datetime(2026, 11, 4, 12, tzinfo=timezone.utc)


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


bc = _load("build_conformance", "build-conformance.py")


def good():
    return json.loads(PROFILE.read_text())


def write(tmp_path, prof):
    p = tmp_path / "profile.json"
    p.write_text(json.dumps(prof))
    return p


def test_committed_profile_covers_every_appendix_b_test_and_names_real_tests():
    prof = bc.load_profile()
    assert list(prof["tests"]) == bc.IDS
    for tid, t in prof["tests"].items():
        for node in t.get("pytest") or []:
            file, func = node.split("::")
            assert (REPO / file).is_file(), f"{tid}: {file} does not exist"
            assert f"def {func}(" in (REPO / file).read_text(), f"{tid}: {node} does not exist"


def test_the_profile_records_the_tests_this_change_added():
    tests = good()["tests"]
    assert tests["T52"]["status"] == "implemented"
    assert any("test_detection_gate.py" in n for n in tests["T52"]["pytest"])
    assert tests["T53"]["status"] == "implemented"
    assert any("test_gate_modes.py" in n for n in tests["T53"]["pytest"])


@pytest.mark.parametrize("mutate,match", [
    (lambda p: p["tests"].pop("T40"), "must map exactly"),
    (lambda p: p["tests"]["T1"].update(status="done"), "status must be one of"),
    (lambda p: p["tests"]["T1"].update(status="not-implemented", pytest=[], reason=""), "needs a reason"),
    (lambda p: p["tests"]["T53"].update(pytest=[]), "needs at least one pytest node"),
    (lambda p: p["tests"]["T53"].update(pytest=["tests/x.py"]), "node IDs"),
    (lambda p: p.update(review_by="soon"), "review_by must be an ISO date"),
])
def test_an_invalid_profile_fails_closed(tmp_path, mutate, match):
    prof = good()
    mutate(prof)
    with pytest.raises(SystemExit, match=match):
        bc.load_profile(write(tmp_path, prof))


def test_a_failing_or_missing_mapped_test_is_a_failure():
    prof = copy.deepcopy(bc.load_profile())
    node = prof["tests"]["T53"]["pytest"][0]
    outcome = {n: "passed" for t in prof["tests"].values() for n in t.get("pytest") or []}
    doc, missing = bc.build(prof, outcome, "c" * 40, NOW)
    assert not missing and doc["summary"]["failed"] == 0
    assert next(r for r in doc["tests"] if r["id"] == "T53")["result"] == "passed"

    doc, _ = bc.build(prof, {**outcome, node: "failed"}, "c" * 40, NOW)
    assert next(r for r in doc["tests"] if r["id"] == "T53")["result"] == "failed"
    assert doc["summary"]["failed"] >= 1

    del outcome[node]
    _, missing = bc.build(prof, outcome, "c" * 40, NOW)
    assert missing == [node]


def test_a_skipped_mapped_test_does_not_count_as_passing():
    prof = bc.load_profile()
    outcome = {n: "passed" for t in prof["tests"].values() for n in t.get("pytest") or []}
    node = prof["tests"]["T53"]["pytest"][0]
    doc, _ = bc.build(prof, {**outcome, node: "skipped"}, "c" * 40, NOW)
    assert next(r for r in doc["tests"] if r["id"] == "T53")["result"] == "failed"


def test_results_name_the_profile_and_the_method_they_were_built_against():
    prof = bc.load_profile()
    outcome = {n: "passed" for t in prof["tests"].values() for n in t.get("pytest") or []}
    doc, _ = bc.build(prof, outcome, "c" * 40, NOW)
    assert doc["schema"] == "conformance-results/1" and doc["profile_version"] == prof["profile_version"]
    assert len(doc["method"]["sha256"]) == 64 and doc["commit"] == "c" * 40
    s = doc["summary"]
    assert s["implemented"] + s["partial"] + s["not-implemented"] + s["not-applicable"] == 74


def test_the_vdr_names_the_conformance_results_and_refuses_a_missing_file(tmp_path):
    vdr = _load("vdr_conf", "build-vdr-report.py")
    p = tmp_path / "conformance-results.json"
    p.write_text(json.dumps({"schema": "conformance-results/1", "profile_version": "x/1", "generated_at": "t",
                             "summary": {"failed": 0}}))
    prof = vdr.load_conformance(p)
    assert prof["profile_version"] == "x/1" and len(prof["conformance_sha256"]) == 64
    with pytest.raises(SystemExit, match="not found"):
        vdr.load_conformance(tmp_path / "absent.json")
    p.write_text(json.dumps({"schema": "other"}))
    with pytest.raises(SystemExit, match="not a conformance-results/1"):
        vdr.load_conformance(p)


def test_the_deploy_publishes_signed_results_and_both_workflows_pass_them_to_the_vdr():
    deploy = (REPO / ".github" / "workflows" / "deploy-with-opa.yml").read_text()
    nightly = (REPO / ".github" / "workflows" / "evidence-nightly.yml").read_text()
    assert "scripts/build-conformance.py" in deploy
    assert "--bundle conformance-results.bundle conformance-results.json" in deploy
    # The suite runs in the credential-less test job, never in the deploy job,
    # which downloads its results before the VDR build.
    jobs = yaml.safe_load(deploy)["jobs"]
    steps = {job: [s.get("name", "") for s in jobs[job]["steps"]] for job in ("test", "deploy")}
    assert "Run the conformance suite (REQ-GOV-2)" in steps["test"]
    assert not any("conformance suite" in s for s in steps["deploy"])
    assert "test" in jobs["deploy"]["needs"]
    assert steps["deploy"].index("Download the conformance results") < steps["deploy"].index(
        "Build VDR Report (FedRAMP 20x Class C)")
    for wf in (deploy, nightly):
        assert "--conformance conformance-results.json" in wf
    assert "verify-blob --bundle conformance-results.bundle" in nightly
    sys.path.insert(0, str(REPO / "scripts"))
    from _freshness import load_freshness_config
    art = next(a for a in load_freshness_config()["artifacts"] if a["path"] == ".well-known/conformance-results.json")
    assert art["signed"] and art["signature"] == ".well-known/conformance-results.bundle"


PROFILE_STAMP = {"profile_version": "vdr-method/2026-11-04", "conformance_sha256": "a" * 64,
                 "conformance_generated_at": "2026-11-04T12:00:00+00:00",
                 "summary": {"implemented": 30, "partial": 10, "not-implemented": 30, "not-applicable": 4,
                             "passed": 40, "failed": 0}}


def test_the_trend_carries_the_profile_of_the_report_it_came_from(tmp_path):
    import subprocess
    report = tmp_path / "r.json"
    report.write_text(json.dumps({"system_id": "urn:test:sys", "emitted_at": "2026-11-04T10:00:00+00:00",
                                  "methodology": {"profile": PROFILE_STAMP},
                                  "summary": {"unique_cves": 0, "unique_cves_open": 0, "blocking": 0, "kev": 0,
                                              "by_pain": {}, "total_findings": 0, "risk_accepted": 0}}))
    trend = tmp_path / "t.json"
    subprocess.run([sys.executable, str(REPO / "scripts" / "build-vdr-trend.py"), "--report", str(report),
                    "--trend", str(trend)], check=True, capture_output=True)
    assert json.loads(trend.read_text())["profile"] == PROFILE_STAMP


def test_the_trust_center_shows_conformance_and_never_reads_partial_coverage_as_whole():
    sys.path.insert(0, str(REPO / "tests"))
    import test_build_trust_center as t
    vdr = t.inputs()["vdr"]
    doc = t.build(vdr={**vdr, "methodology": {"profile": PROFILE_STAMP}})
    assert doc["profile"] == PROFILE_STAMP
    item = next(p for p in doc["picture"] if p["id"] == "conformance")
    assert item["status"] == "attention" and "10 partly, 30 not yet" in item["detail"]
    whole = {**PROFILE_STAMP, "summary": {**PROFILE_STAMP["summary"], "partial": 0, "not-implemented": 0}}
    assert t.picture(t.build(vdr={**vdr, "methodology": {"profile": whole}}))["conformance"] == "ok"
    failing = {**whole, "summary": {**whole["summary"], "failed": 1}}
    assert t.picture(t.build(vdr={**vdr, "methodology": {"profile": failing}}))["conformance"] == "attention"
    assert t.picture(t.build())["conformance"] == "not_observed"


def test_the_nightly_status_names_the_profile():
    nightly = (REPO / ".github" / "workflows" / "evidence-nightly.yml").read_text()
    assert "--slurpfile prof conformance-status.json" in nightly and "profile:" in nightly


@pytest.mark.parametrize("fixture,match", [
    ("profile-missing-test.json", "a mapped test is missing"),
    ("profile-unbacked-claim.json", "needs at least one pytest node"),
])
def test_known_bad_profiles_stop_the_build(tmp_path, fixture, match):
    with pytest.raises(SystemExit, match=match):
        bc.main(["--profile", str(FIX / fixture), "--output", str(tmp_path / "out.json")])
    assert not (tmp_path / "out.json").exists()
