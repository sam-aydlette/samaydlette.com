"""The monthly vulnerability detection and response activity report
(VER-TFR-MHR, VER-RPT-HLO, VER-RPT-PER): scripts/build-vdr-monthly.py."""
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "vdr-monthly"
sys.path.insert(0, str(REPO / "scripts"))
import _decisions  # noqa: E402

_spec = importlib.util.spec_from_file_location("vdr_monthly", REPO / "scripts" / "build-vdr-monthly.py")
mo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mo)

REG = _decisions.load()
ACTS = mo.validate_activities(json.loads((REPO / "data" / "vdr-activities.json").read_text()))
NOW = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)


def vdr(checked_at="2026-11-20T06:00:00+00:00", **meth):
    return {"report_id": "r1", "ksi_signal_id": "k1", "findings": [], "risk_accepted": [],
            "methodology": {"detection": {"checked_at": checked_at, "feeds": [
                {"feed": "grype", "file": "grype-python.json", "status": "ok", "count": 0},
                {"feed": "checkov", "file": "checkov-results.sarif", "status": "ok", "count": 3},
                {"feed": "kev", "file": "kev-catalog.json", "status": "ok", "count": 9,
                 "source_date": "2026-11-19T20:00:00+00:00"},
                {"feed": "previous-vdr", "file": "previous-vdr-report.json", "status": "ok", "count": 1}]},
                            **meth}}


MRH = {"activeVulnerabilities": [], "acceptedVulnerabilities": []}


def nmv(on="2026-11-05", status="ok"):
    return {"schema": "non-machine-vv/2", "status": status, "generatedAt": f"{on}T07:00:00+00:00",
            "resources": [{"id": "NMR-POL-AC", "lastVerified": on, "result": "pass"}]}


def build(v=None, previous=None, retained=None, now=NOW, acts=ACTS, n=None):
    return mo.build(v or vdr(), MRH, REG, acts, n or nmv(), retained, previous, now)


def by_type(doc):
    return {o["type"]: o for o in doc["overview"]}


def test_every_activity_type_is_stated_with_none_this_period_when_quiet():
    doc = build()
    o = by_type(doc)
    assert [x["type"] for x in doc["overview"]] == [t["type"] for t in mo.ACTIVITY_TYPES]
    for quiet in ("code-sast", "dast-site", "dast-api", "runtime-vv", "vdp", "bug-bounty", "pentest", "assessment"):
        assert o[quiet]["summary"] == "none this period" and o[quiet]["runsInPeriod"] == 0
    assert o["sca"]["runsInPeriod"] == 1 and o["iac-sast"]["runsInPeriod"] == 1
    assert o["threat-intel"]["runsInPeriod"] == 1 and o["non-machine-vv"]["runsInPeriod"] == 1
    md = mo.render(doc)
    assert md.count("none this period") >= 8
    assert "| Penetration testing | none this period (program not active:" in md
    assert "Runtime runs counted from: latest run only" in md


def test_the_period_is_the_calendar_month_to_date():
    doc = build()
    assert doc["period"] == {"month": "2026-11", "from": "2026-11-01T00:00:00+00:00", "to": NOW.isoformat()}
    # A run on the last day of the previous month is not this month's.
    doc = build(v=vdr(checked_at="2026-10-31T23:59:59+00:00"))
    assert by_type(doc)["sca"]["runsInPeriod"] == 0
    # The 2026-10-26/27 manual ZAP scans count in October, not November.
    oct_doc = build(now=datetime(2026, 10, 30, tzinfo=timezone.utc), n=nmv(on="2026-10-01"))
    assert by_type(oct_doc)["dast-site"]["runsInPeriod"] == 1
    assert by_type(build())["dast-site"]["runsInPeriod"] == 0


def test_runs_accumulate_over_the_month_from_the_previous_report():
    first = build(v=vdr(checked_at="2026-11-10T06:00:00+00:00"), now=datetime(2026, 11, 10, 7, tzinfo=timezone.utc))
    second = build(previous=json.loads(json.dumps(first)))
    assert by_type(second)["sca"]["runsInPeriod"] == 2
    assert by_type(build(previous=json.loads(json.dumps(second))))["sca"]["runsInPeriod"] == 2  # no double count


def test_a_finished_month_moves_to_previous_months():
    october = build(v=vdr(checked_at="2026-10-30T06:00:00+00:00"), now=datetime(2026, 10, 31, tzinfo=timezone.utc),
                    n=nmv(on="2026-10-01"))
    nov = build(previous=json.loads(json.dumps(october)))
    assert nov["previousMonths"][0]["period"]["month"] == "2026-10"
    assert by_type(nov)["sca"]["runsInPeriod"] == 1  # October's runs are not carried into November
    assert "## Previous months" in mo.render(nov)
    with pytest.raises(SystemExit, match="later month"):
        build(previous=json.loads(json.dumps(nov)), now=datetime(2026, 10, 31, tzinfo=timezone.utc))


def test_retained_runtime_runs_are_all_counted():
    runs = {"runs": [{"signal_id": "a", "emitted_at": "2026-11-18T03:00:00Z", "validations": 5, "failed": 0},
                     {"signal_id": "b", "emitted_at": "2026-11-19T03:00:00Z", "validations": 5, "failed": 1}]}
    doc = build(retained=runs)
    o = by_type(doc)["runtime-vv"]
    assert o["runsInPeriod"] == 2 and o["failedRuns"] == 1
    assert doc["runtimeRunsBasis"].startswith("retained runs")


def test_without_retention_the_one_verified_run_counts():
    rt = {"verified": True, "emitted_at": "2026-11-20T03:00:00Z", "signal_id": "s", "validations": 7, "failed": 0}
    doc = build(v=vdr(runtime_verification=rt))
    assert by_type(doc)["runtime-vv"]["runsInPeriod"] == 1 and doc["runtimeRunsBasis"].startswith("latest run only")
    unverified = dict(rt, verified=False)
    assert by_type(build(v=vdr(runtime_verification=unverified)))["runtime-vv"]["runsInPeriod"] == 0


def test_dast_and_code_sast_count_when_the_vdr_records_them():
    doc = build(v=vdr(dast={"scanner": "zap", "status": "ok", "generated_at": "2026-11-17T07:30:00+00:00",
                            "alerts": 2}))
    assert by_type(doc)["dast-site"]["runsInPeriod"] == 1


# --- fail closed: known-bad inputs ---------------------------------------------------------

@pytest.mark.parametrize("name,msg", [
    ("activities-unknown-kind.json", "kind 'tabletop' is not one of"),
    ("activities-missing-program.json", "programs must state exactly"),
    ("activities-ends-before-start.json", "end_date is before date"),
])
def test_a_malformed_activity_record_is_refused(name, msg):
    with pytest.raises(SystemExit, match=msg):
        mo.validate_activities(json.loads((FIX / name).read_text()))


def test_a_missing_input_fails(tmp_path):
    (tmp_path / "vdr-report.json").write_text(json.dumps(vdr()))
    (tmp_path / "vdr-history.json").write_text(json.dumps(MRH))
    with pytest.raises(SystemExit, match="non-machine status .* not found"):
        mo.main(["--vdr", str(tmp_path / "vdr-report.json"), "--history", str(tmp_path / "vdr-history.json"),
                 "--non-machine", str(tmp_path / "absent.json"), "--out-dir", str(tmp_path)])


def test_main_writes_json_and_markdown(tmp_path):
    (tmp_path / "vdr-report.json").write_text(json.dumps(vdr()))
    (tmp_path / "vdr-history.json").write_text(json.dumps(MRH))
    (tmp_path / "nmv.json").write_text(json.dumps(nmv()))
    assert mo.main(["--vdr", str(tmp_path / "vdr-report.json"), "--history", str(tmp_path / "vdr-history.json"),
                    "--non-machine", str(tmp_path / "nmv.json"), "--out-dir", str(tmp_path),
                    "--now", NOW.isoformat()]) == 0
    assert json.loads((tmp_path / "vdr-monthly.json").read_text())["schema"] == "vdr-monthly/1"
    assert (tmp_path / "vdr-monthly.md").read_text().startswith("# Vulnerability detection and response: 2026-11")


def test_the_nightly_and_deploy_build_sign_and_publish_it():
    for wf in ("deploy-with-opa.yml", "evidence-nightly.yml"):
        text = (REPO / ".github" / "workflows" / wf).read_text()
        assert "build-vdr-monthly.py" in text, wf
        assert "--bundle vdr-monthly.bundle vdr-monthly.json" in text, wf
    fresh = json.loads((REPO / "infrastructure" / "schemas" / "freshness-config.json").read_text())
    assert any(a["path"] == ".well-known/vdr-monthly.json" and a["max_age_hours"] == 24 for a in fresh["artifacts"])


def test_the_signed_run_history_the_vdr_carries_is_counted():
    rt = {"verified": True, "emitted_at": "2026-11-20T03:00:00Z", "signal_id": "s", "validations": 7, "failed": 0,
          "run_history": [{"signal_id": "a", "emitted_at": "2026-11-19T03:00:00Z", "validations": 7, "failed": 1},
                          {"signal_id": "s", "emitted_at": "2026-11-20T03:00:00Z", "validations": 7, "failed": 0}]}
    doc = build(v=vdr(runtime_verification=rt))
    assert by_type(doc)["runtime-vv"]["runsInPeriod"] == 2 and doc["runtimeRunsBasis"].startswith("retained runs")
