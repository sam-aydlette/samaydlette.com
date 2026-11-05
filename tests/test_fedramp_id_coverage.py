"""CDS-CSO-FID across everything published: every freshness-governed JSON
artifact is checked by the FedRAMP ID gate (scripts/check-fedramp-id.py
REPORTS) or exempt with a reason, and each builder that writes one stamps the
offering's FedRAMP ID (scripts/_offering.stamp_fedramp_id)."""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _fedramp_schema as fs  # noqa: E402
import _offering  # noqa: E402

FID = _offering.fedramp_id()
FIX = REPO / "tests" / "fixtures" / "fedramp-id"
FRESHNESS = REPO / "infrastructure" / "schemas" / "freshness-config.json"


def _load(name, script):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / script)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


gate = _load("check_fedramp_id_cov", "check-fedramp-id.py")


# --- coverage ---------------------------------------------------------------------------

def test_every_governed_json_artifact_is_checked_or_exempt_with_a_reason():
    paths = [a["path"] for a in json.loads(FRESHNESS.read_text())["artifacts"]]
    assert gate.uncovered(paths) == []
    governed = {p.rsplit("/", 1)[-1] for p in paths}
    assert set(gate.EXEMPT) <= governed, "an exemption names nothing that is published"
    assert all(r.strip() for r in gate.EXEMPT.values())


def test_known_bad_an_unlisted_artifact_and_an_unexplained_exemption_fail():
    bad = json.loads((FIX / "freshness-uncovered.json").read_text())
    paths = [a["path"] for a in bad["artifacts"]] + [bad["exempt_artifact"]]
    problems = gate.uncovered(paths, exempt=bad["exempt"])
    assert any("new-unstamped-report.json is published but neither checked" in p for p in problems)
    assert any("boundary-corroboration.json is published but neither checked" in p for p in problems)
    assert not any("iiw.csv" in p or "security-decision-record" in p for p in problems)


def test_known_bad_a_fedramp_schema_report_without_the_id_fails():
    assert gate.main([str(FIX / "incident-report-without-fedramp-id.json")]) == 1


def test_the_gate_checks_every_incident_report_by_glob(tmp_path, monkeypatch):
    good = {"$schema": fs.stamp("incident"), "providerExtensions": {"fedRampId": FID}}
    (tmp_path / "incident-INC-1-01-initial.json").write_text(json.dumps(good))
    (tmp_path / "incident-INC-1-02-ongoing.json").write_text(json.dumps({"$schema": fs.stamp("incident")}))
    monkeypatch.chdir(tmp_path)
    assert gate._expand(["incident-INC-*.json"]) == ["incident-INC-1-01-initial.json",
                                                     "incident-INC-1-02-ongoing.json"]
    assert gate.main(gate._expand(["incident-INC-*.json"])) == 1


def test_the_nightly_and_the_incident_publisher_run_the_gate_on_what_they_publish():
    wf = REPO / ".github" / "workflows"
    nightly = (wf / "evidence-nightly.yml").read_text()
    at = nightly.index("- name: FedRAMP ID in every republished report (CDS-CSO-FID)")
    assert at < nightly.index("- name: Publish VDR + trend to /.well-known/")
    step = nightly[at:nightly.index("- name:", at + 10)]
    for f in ("vdr-report.json", "vdr-trend.json", "vdr-detail-report.json", "vdr-accepted-vulnerabilities.json",
              "vdr-history.json", "vdr-non-machine-vv.json", "vdr-monthly.json"):
        assert f in step, f
    inc = (wf / "incident-reports.yml").read_text()
    assert inc.index("check-fedramp-id.py incident-*.json") < inc.index("- name: Publish incident reports")


# --- the stamp --------------------------------------------------------------------------

def test_the_stamp_puts_the_id_where_each_kind_of_file_carries_it():
    site = _offering.stamp_fedramp_id({"$schema": "x", "a": 1})
    assert list(site)[:2] == ["$schema", "fedRampId"] and site["fedRampId"] == FID
    assert list(_offering.stamp_fedramp_id({"a": 1})) == ["fedRampId", "a"]
    report = _offering.stamp_fedramp_id({"$schema": fs.stamp("scn"), "providerExtensions": {"k": 1}})
    assert report["providerExtensions"] == {"k": 1, "fedRampId": FID} and "fedRampId" not in report
    assert gate.problems("r.json", report, FID) == [] and gate.problems("s.json", site, FID) == []


# --- each builder stamps what it writes ---------------------------------------------------

def test_scn_notifications_index_log_and_feed_carry_it(tmp_path):
    scn = _load("build_scn_fid", "build-scn.py")
    (tmp_path / "new.json").write_text("[]")
    assert scn.main(["--out-dir", str(tmp_path), "--commit", "abc123",
                     "--new-evaluations", str(tmp_path / "new.json")]) == 0
    index = json.loads((tmp_path / "significant-change-notifications.json").read_text())
    assert index["fedRampId"] == FID
    assert index["notifications"]
    for d in index["notifications"]:
        assert d["providerExtensions"]["fedRampId"] == FID and d["serviceOfferingFedrampId"] == FID
        assert fs.validate(d, "scn") == []
    assert json.loads((tmp_path / "scn-evaluations.json").read_text())["fedRampId"] == FID
    assert f"<subtitle>FedRAMP ID: {FID}</subtitle>" in (tmp_path / "significant-change-notifications.atom").read_text()
    assert gate.main([str(tmp_path / "significant-change-notifications.json"),
                      str(tmp_path / "scn-evaluations.json")]) == 0


def test_a_scn_notification_that_fails_the_schema_is_not_written(tmp_path, monkeypatch):
    scn = _load("build_scn_bad", "build-scn.py")
    real = scn.scn_document

    def broken(*a, **k):
        doc = real(*a, **k)
        doc.pop("changeType")
        return doc
    monkeypatch.setattr(scn, "scn_document", broken)
    (tmp_path / "new.json").write_text("[]")
    with pytest.raises(SystemExit, match="does not validate"):
        scn.main(["--out-dir", str(tmp_path), "--commit", "abc123", "--new-evaluations", str(tmp_path / "new.json")])
    assert not list((tmp_path / "scn").glob("*.json"))


def test_incident_log_reports_and_deliveries_carry_it(tmp_path):
    (tmp_path / "vdr.json").write_text('{"findings": []}')
    subprocess.run([sys.executable, str(REPO / "scripts" / "build-incident-report.py"), "--incidents",
                    str(REPO / "data" / "incidents.json"), "--vdr", str(tmp_path / "vdr.json"),
                    "--out-dir", str(tmp_path)], check=True, capture_output=True)
    subprocess.run([sys.executable, str(REPO / "scripts" / "deliver-incident-reports.py"), "--dir", str(tmp_path)],
                   check=True, capture_output=True)
    files = sorted(tmp_path.glob("incident-*.json"))
    assert len(files) >= 3
    for f in files:
        doc = json.loads(f.read_text())
        if f.name.startswith("incident-INC-"):
            assert doc["providerExtensions"]["fedRampId"] == FID and fs.validate(doc, "incident") == []
        else:
            assert doc["fedRampId"] == FID
    assert gate.main([str(f) for f in files]) == 0


def test_an_incident_report_that_fails_the_schema_is_not_written(tmp_path, monkeypatch):
    bir = _load("bir_bad", "build-incident-report.py")
    real = bir.report_document

    def broken(*a, **k):
        doc = real(*a, **k)
        doc.pop("reportType")
        return doc
    monkeypatch.setattr(bir, "report_document", broken)
    import _incidents
    with pytest.raises(SystemExit, match="does not validate"):
        bir.build(_incidents.load(REPO / "data" / "incidents.json"), {"findings": []},
                  __import__("datetime").datetime.now(__import__("datetime").timezone.utc), tmp_path)
    assert not list(tmp_path.glob("incident-INC-*.json"))


def test_the_inbox_simulation_carries_it(tmp_path):
    out = tmp_path / "sim.json"
    subprocess.run([sys.executable, str(REPO / "scripts" / "build-fsi-simulation.py"),
                    "--messages", str(REPO / "data" / "fsi-simulation" / "messages.json"),
                    "--offering", str(_offering.OFFERING_PATH), "--output", str(out)], check=True,
                   capture_output=True)
    assert json.loads(out.read_text())["fedRampId"] == FID


def test_the_non_machine_status_carries_it(tmp_path):
    out = tmp_path / "nmv.json"
    subprocess.run([sys.executable, str(REPO / "scripts" / "check-non-machine-vv.py"), "--today", "2026-11-05",
                    "--out", str(out)], check=True, capture_output=True)
    assert json.loads(out.read_text())["fedRampId"] == FID


def test_the_vdr_trend_carries_it(tmp_path):
    report = tmp_path / "r.json"
    report.write_text(json.dumps({"system_id": "urn:test:sys", "emitted_at": "2026-11-05T10:00:00+00:00",
                                  "summary": {"unique_cves": 0, "unique_cves_open": 0, "blocking": 0, "kev": 0,
                                              "by_pain": {}, "total_findings": 0, "risk_accepted": 0}}))
    subprocess.run([sys.executable, str(REPO / "scripts" / "build-vdr-trend.py"), "--report", str(report),
                    "--trend", str(tmp_path / "t.json")], check=True, capture_output=True)
    assert json.loads((tmp_path / "t.json").read_text())["fedRampId"] == FID


def test_the_reconcile_report_carries_it():
    rc = _load("reconcile_fid", "reconcile.py")
    assert rc.build_report({"signal_id": "s"}, "c", {})["fedRampId"] == FID


@pytest.mark.parametrize("script", [
    "build-vdr-report.py", "build-vdr-monthly.py", "build-ksi-signal.py", "build-mas.py", "build-scg.py",
    "check-secure-config.py", "build-boundary-graph.py", "build-conformance.py", "build-access-summary.py",
])
def test_each_remaining_builder_stamps_before_it_writes(script):
    """Builders that need AWS or a full build to run: the stamp is in the
    source. The deploy's gate over REPORTS is what proves the output."""
    assert "_offering.stamp_fedramp_id(" in (REPO / "scripts" / script).read_text()


def test_the_ksi_signal_schema_admits_it_and_the_runtime_emitter_copies_it():
    schema = json.loads((REPO / "infrastructure" / "schemas" / "ksi-signal.schema.json").read_text())
    assert schema["properties"]["fedRampId"]["type"] == "string"
    js = (REPO / "infrastructure" / "lambda" / "index.js").read_text()
    assert "fedRampId: deploySignal.fedRampId" in js
