"""Daily KSI metrics (SDR-CSX-KMT): scripts/_ksi_metrics.py, the one writer both
workflows run (scripts/build-ksi-metrics.py), the SDR's check that it carries this
deploy's statuses, and the signature check on the history it appends to
(scripts/fetch-verified.sh)."""

import functools
import http.server
import importlib.util
import json
import os
import subprocess
import sys
import threading
from datetime import datetime, timedelta
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "tests"))
import _common  # noqa: E402
import _ksi_metrics as km  # noqa: E402
from test_ksi_methods import NOW, _inputs, _iso  # noqa: E402

SYSTEM = {f: 0 for f in km.SYSTEM_FIELDS}


def _day(beacon="default", now=NOW, source="nightly"):
    inputs = _inputs() if beacon == "default" else _inputs(beacon=beacon)
    result, facts = km.evaluate(now=now, **inputs)
    return km.point(result, facts, inputs["beacon"], inputs["runtime_signal"], SYSTEM, now, source)


GOOD_BEACON = {**_inputs()["beacon"], "result": "success",
               "gate_results": [{"check": "reconcile.a", "result": "pass"}]}
FAILED_BEACON = {**GOOD_BEACON, "result": "failure", "reconcile": "failure",
                 "gate_results": [{"check": "reconcile.a", "result": "fail"}]}


# --- one day's point --------------------------------------------------------------------

def test_a_failed_nightly_changes_the_days_ksi_statuses_and_validation_status():
    good, bad = _day(GOOD_BEACON), _day(FAILED_BEACON)
    changed = {k for k in good["ksis"] if good["ksis"][k] != bad["ksis"][k]}
    assert changed, "a failing nightly check changed no KSI's daily point"
    assert all(any(f.endswith("@nightly") for f in bad["ksis"][k]["failing"]) for k in changed)
    assert good["persistent_validation"]["nightly"] == {"fresh": True, "result": "success", "failing_checks": []}
    assert bad["persistent_validation"]["nightly"] == {"fresh": True, "result": "failure",
                                                       "failing_checks": ["reconcile.a"]}


def test_a_stale_beacon_is_recorded_as_no_persistent_validation_that_day():
    pv = _day({**GOOD_BEACON, "finished_at": _iso(30)})["persistent_validation"]
    assert pv["nightly"] == {"fresh": False, "result": None, "failing_checks": []}
    assert pv["runtime"] == {"fresh": True, "divergence": "converged"}


def test_every_ksi_has_a_status_every_day():
    p = _day()
    assert set(p["ksis"]) == set(km._ksi_methods.catalog_ksis())
    assert p["date"] == "2026-11-07" and p["source"] == "nightly"


def test_only_the_two_workflows_write_points():
    with pytest.raises(SystemExit, match="unknown source"):
        _day(source="laptop")


# --- the history ------------------------------------------------------------------------

def _p(date, status="Implemented", failing=(), source="nightly"):
    return {"date": date, "source": source, "evaluated_at": f"{date}T01:00:00+00:00",
            "ksis": {"KSI-A": {"status": status, "passing": 2, "failing": list(failing)}},
            "persistent_validation": {"nightly": {"fresh": True, "result": "success", "failing_checks": []},
                                      "runtime": {"fresh": True, "divergence": "converged"}}, **SYSTEM}


def test_a_later_evaluation_of_the_same_day_replaces_the_earlier_one():
    h = km.append([_p("2026-11-06"), _p("2026-11-07", source="deploy")], _p("2026-11-07", "Not Demonstrated"))
    assert [(x["date"], x["source"], x["ksis"]["KSI-A"]["status"]) for x in h] == [
        ("2026-11-06", "nightly", "Implemented"), ("2026-11-07", "nightly", "Not Demonstrated")]


def test_the_history_keeps_one_year():
    start = datetime(2025, 1, 1)
    h = []
    for n in range(400):
        h = km.append(h, _p((start + timedelta(days=n)).date().isoformat()))
    assert len(h) == km.HISTORY_DAYS == 366 and h[-1]["date"] == "2026-02-04"


def test_summaries_are_per_ksi_over_30_days_and_the_year():
    h = [_p(f"2026-09-{d:02d}", "Not Demonstrated", ["opa:x@plan"]) for d in range(1, 11)] + \
        [_p(f"2026-10-{d:02d}") for d in range(1, 31)]
    s = km.summaries(h)
    assert s["summary_30d"]["ksis"]["KSI-A"] == {"days": 30, "days_implemented": 30,
                                                 "days_with_failing_method": 0, "status": "Implemented"}
    assert s["summary_1y"]["ksis"]["KSI-A"] == {"days": 40, "days_implemented": 30,
                                                "days_with_failing_method": 10, "status": "Implemented"}
    assert s["summary_1y"]["persistent_validation"]["nightly_days_passed"] == 40


def test_the_first_history_starts_from_the_sdrs_points_without_ksi_data():
    sdr = {"metrics": {"daily_metric_data": [{"date": "2026-10-01", "vdr_blocking": 1, "ksi_in_scope": 46}]}}
    doc = km.update(None, sdr, _p("2026-11-07"), now=NOW, source="nightly", fedramp_id="F", signal_id="s",
                    commit="c", run_url=None)
    old, new = doc["daily_metric_data"]
    assert old["source"] == "sdr" and old["ksis"] is None and old["persistent_validation"] is None
    assert old["vdr_blocking"] == 1 and new["ksis"]
    assert doc["summary_30d"]["days_with_ksi_data"] == 1 and doc["fedramp_id"] == "F"
    # Once a history is published, the SDR's points are never read again.
    again = km.update(doc, {"metrics": {"daily_metric_data": [{"date": "2026-01-01"}]}}, _p("2026-11-08"),
                      now=NOW, source="nightly", fedramp_id="F", signal_id="s", commit="c", run_url=None)
    assert [x["date"] for x in again["daily_metric_data"]] == ["2026-10-01", "2026-11-07", "2026-11-08"]


@pytest.mark.parametrize("doc", [
    {"schema": "other", "daily_metric_data": []},
    {"schema": km.SCHEMA, "daily_metric_data": {}},
    {"schema": km.SCHEMA, "daily_metric_data": [{"date": "2026-11-07"}]},           # no source
    {"schema": km.SCHEMA, "daily_metric_data": [{"date": "2026-11-07", "source": "laptop"}]},
])
def test_a_history_that_is_not_ksi_metrics_fails_closed(tmp_path, doc):
    p = tmp_path / "h.json"
    p.write_text(json.dumps(doc))
    with pytest.raises(SystemExit, match="KSI metrics"):
        km.load(p)


def test_no_published_history_is_none():
    assert km.load(None) is None and km.load("/nonexistent/ksi-metrics.json") is None


# --- the writer both workflows run --------------------------------------------------------

def _mod(name, file):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_the_cli_writes_the_published_document(tmp_path, monkeypatch):
    sig = tmp_path / "ksi-signal.json"
    sig.write_text(json.dumps({**_inputs()["deploy_signal"], "signal_id": "sig-1"}))
    beacon = tmp_path / "vdr-status.json"
    beacon.write_text(json.dumps(GOOD_BEACON))
    out = tmp_path / "ksi-metrics.json"
    bkm = _mod("build_ksi_metrics", "build-ksi-metrics.py")
    monkeypatch.setattr(bkm._controls, "load", lambda *a: [{"control-id": "ac-2"}, {"control-id": "ac-3"}])
    monkeypatch.setattr(km, "verified_runtime", lambda path, now: None)
    assert bkm.main(["--source", "deploy", "--ksi-signal", str(sig), "--vdr", str(tmp_path / "absent.json"),
                     "--vdr-status", str(beacon), "--runtime-signal", str(tmp_path / "absent.json"),
                     "--output", str(out)]) == 0
    doc = km.load(out)
    last = doc["daily_metric_data"][-1]
    assert doc["ksi_signal_id"] == "sig-1" and doc["updated_by"]["source"] == "deploy"
    assert doc["fedramp_id"] == _common.fedramp_id()
    assert last["source"] == "deploy" and last["controls_in_scope"] == 2
    assert last["persistent_validation"]["runtime"] == {"fresh": False, "divergence": None}


# --- the SDR carries this deploy's point -------------------------------------------------

def _sdr_check(doc, statuses, now=NOW):
    sdr = _mod("build_sdr_kmt", "build-sdr.py")
    return sdr.build_metrics(doc, {"ksis": {k: {"status": v} for k, v in statuses.items()}}, now)


def _doc(*points):
    return km.document(list(points), now=NOW, source="deploy", fedramp_id="F", signal_id="s", commit="c",
                       run_url=None)


def test_the_sdr_carries_the_history_with_this_deploys_point_as_current():
    m = _sdr_check(_doc(_p("2026-11-06"), _p("2026-11-07", source="deploy")), {"KSI-A": "Implemented"})
    assert m["current"]["date"] == "2026-11-07" and len(m["daily_metric_data"]) == 2
    assert m["history_uri"] == km.URI and m["summary_30d"]["ksis"]["KSI-A"]["days"] == 2


@pytest.mark.parametrize("doc, statuses", [
    (_doc(_p("2026-11-07", source="nightly")), {"KSI-A": "Implemented"}),   # not this deploy's point
    (_doc(_p("2026-11-06", source="deploy")), {"KSI-A": "Implemented"}),    # not today's
    (_doc(_p("2026-11-07", source="deploy")), {"KSI-A": "Not Demonstrated"}),  # other statuses
    (None, {"KSI-A": "Implemented"}),
])
def test_the_sdr_refuses_a_history_that_is_not_this_deploys(doc, statuses):
    with pytest.raises(SystemExit, match="SDR-CSX-KMT"):
        _sdr_check(doc, statuses)


# --- the signature check on the history ---------------------------------------------------

@pytest.fixture
def site(tmp_path):
    root = tmp_path / "site" / ".well-known"
    root.mkdir(parents=True)
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(tmp_path / "site"))
    handler.log_message = lambda *a: None
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield root, f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _fetch(tmp_path, origin, *ids):
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    # A cosign stand-in: the bundle verifies when it names the identity asked for.
    (b / "cosign").write_text("""#!/bin/bash
while [ $# -gt 0 ]; do
  case "$1" in --bundle) bundle=$2; shift ;; --certificate-identity) id=$2; shift ;; esac; shift
done
[ "$(cat "$bundle")" = "$id" ]
""")
    (b / "cosign").chmod(0o755)
    out = tmp_path / "work" / "prev.json"
    out.parent.mkdir(exist_ok=True)
    env = {**os.environ, "PATH": f"{b}:{os.environ['PATH']}", "SITE_ORIGIN": origin}
    r = subprocess.run(["bash", str(REPO / "scripts" / "fetch-verified.sh"), "ksi-metrics", str(out), *ids],
                       capture_output=True, text=True, env=env, check=False)
    return r, out


def test_a_history_signed_by_either_workflow_is_kept(tmp_path, site):
    root, origin = site
    (root / "ksi-metrics.json").write_text("{}")
    (root / "ksi-metrics.bundle").write_text("nightly")
    r, out = _fetch(tmp_path, origin, "deploy", "nightly")
    assert r.returncode == 0 and out.is_file() and not Path(f"{out}.bundle").exists()


@pytest.mark.parametrize("signer, bundle", [("someone-else", True), ("nightly", False)])
def test_a_history_that_does_not_verify_is_refused_and_removed(tmp_path, site, signer, bundle):
    root, origin = site
    (root / "ksi-metrics.json").write_text("{}")
    if bundle:
        (root / "ksi-metrics.bundle").write_text(signer)
    r, out = _fetch(tmp_path, origin, "deploy", "nightly")
    assert r.returncode == 1 and not out.exists()


def test_only_a_404_means_no_history_yet(tmp_path, site):
    _, origin = site
    r, out = _fetch(tmp_path, origin, "deploy")
    assert r.returncode == 0 and not out.exists() and "No published ksi-metrics yet" in r.stdout
    r, out = _fetch(tmp_path, "http://127.0.0.1:9", "deploy")   # nothing listening: not a 404
    assert r.returncode == 1 and not out.exists()
