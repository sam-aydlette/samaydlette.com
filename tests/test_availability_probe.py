"""CDS-CSO-AVR / CDS-TRC-USH: availability is measured outside AWS, with
incidents, and the deploy refuses a missing or stale independent feed."""
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import pytest

REPO = Path(__file__).resolve().parent.parent


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


probe = _load("availability_probe_t", "availability-probe.py")
avail = _load("build_availability_t", "build-availability.py")
NOW = datetime(2026, 11, 5, 12, tzinfo=timezone.utc)
KEYS = [k for k, *_ in probe.TARGETS]


def _sample(t, fail=None):
    return {"t": probe._iso(t), "probed": KEYS, "fail": fail or {}}


def test_core_services_are_probed_including_the_app_and_its_sign_in():
    urls = {u for _k, _s, u, _ok in probe.TARGETS}
    assert any(u.endswith("/silk-reeling/") for u in urls)
    hosts = {urlparse(u).hostname or "" for u in urls}
    assert any(h == "amazoncognito.com" or h.endswith(".amazoncognito.com") for h in hosts)
    assert any("/.well-known/" in u for u in urls) and any(u.endswith("/trust/") for u in urls)
    assert all(u.startswith("https://") for u in urls)


def test_a_failed_probe_records_the_status():
    s = probe.probe_once(lambda url: 503 if "trust" in url else 200, NOW)
    assert s["fail"] == {"trust-center": "HTTP 503"}


def test_consecutive_failures_make_an_incident_and_a_single_one_is_transient():
    t = [NOW - timedelta(minutes=15 * i) for i in range(6, 0, -1)]
    samples = [_sample(t[0]), _sample(t[1], {"site": "HTTP 503"}), _sample(t[2], {"site": "HTTP 503"}),
               _sample(t[3]), _sample(t[4], {"trust-center": "no response (timeout)"}), _sample(t[5])]
    incs, transient = probe.incidents(samples)
    assert incs == [{"service": "site", "service_name": "Website", "start": probe._iso(t[1]),
                     "end": probe._iso(t[3]), "failed_probes": 2, "failing_check": "HTTP 503"}]
    assert transient == {"trust-center": 1}


def test_an_ongoing_incident_has_no_end():
    samples = [_sample(NOW - timedelta(minutes=30), {"site": "HTTP 500"}), _sample(NOW, {"site": "HTTP 500"})]
    (inc,), _ = probe.incidents(samples)
    assert inc["end"] is None


def test_history_is_kept_35_days_and_its_start_is_carried():
    old = [_sample(NOW - timedelta(days=d)) for d in (40, 34, 1)]
    prev = {"feed_type": "availability-status", "history_began": "2026-09-01T00:00:00Z", "samples": old}
    doc = probe.build(prev, _sample(NOW), NOW)
    assert len(doc["samples"]) == 3 and doc["history_began"] == "2026-09-01T00:00:00Z"
    assert doc["availability"]["site"]["probes"] == 2  # 30-day window: day 1 and now


def test_availability_percent_counts_failures():
    prev = {"feed_type": "availability-status", "samples": [_sample(NOW - timedelta(hours=1), {"site": "HTTP 502"})]}
    doc = probe.build(prev, _sample(NOW), NOW)
    assert doc["availability"]["site"]["availability_percent"] == 50.0
    assert doc["current"]["site"] == "up"


def test_the_known_bad_stale_feed_fails_the_deploy_guard():
    why = probe.check_fresh(REPO / "tests" / "fixtures" / "availability" / "known-bad-stale-feed.json", 2, NOW)
    assert why and "not running" in why[0]


def test_a_missing_feed_fails_the_deploy_guard(tmp_path):
    assert probe.check_fresh(tmp_path / "absent.json", 2, NOW)


def test_the_onsite_feed_is_built_from_the_independent_one_never_from_a_deploy(tmp_path):
    feed = probe.build({}, _sample(datetime.now(timezone.utc)), datetime.now(timezone.utc))
    (tmp_path / "f.json").write_text(json.dumps(feed))
    assert avail.main(["--probe-feed", str(tmp_path / "f.json"), "--ksi-signal", str(tmp_path / "none.json"),
                       "--output", str(tmp_path / "a.json"), "--md-output", str(tmp_path / "a.md")]) == 0
    doc = json.loads((tmp_path / "a.json").read_text())
    assert doc["independent_service"]["json"].startswith("https://raw.githubusercontent.com/")
    assert "deploy" not in json.dumps(doc["daily"]) and doc["measured_at"] == feed["generated_at"]
    assert "Independent status page" in (tmp_path / "a.md").read_text()


def test_the_onsite_builder_refuses_a_stale_feed(tmp_path):
    with pytest.raises(SystemExit):
        avail.main(["--probe-feed", str(REPO / "tests" / "fixtures" / "availability" / "known-bad-stale-feed.json"),
                    "--output", str(tmp_path / "a.json"), "--md-output", str(tmp_path / "a.md")])


def test_the_monitor_runs_outside_aws_on_a_schedule_and_pushes_only_its_branch():
    wf = (REPO / ".github" / "workflows" / "availability-probe.yml").read_text()
    assert "cron: '*/15 * * * *'" in wf
    assert "permissions: {}" in wf and "contents: write" in wf
    assert "aws-actions" not in wf and "id-token" not in wf
    assert "HEAD:refs/heads/availability-status" in wf
    assert wf.count("git -c http.extraheader") == 1 and "push --quiet --force" in wf


def test_the_deploy_reads_the_independent_feed_before_the_sdr():
    wf = (REPO / ".github" / "workflows" / "deploy-with-opa.yml").read_text()
    step = wf.index("- name: Read the independent availability feed (fails when missing or stale)")
    assert step < wf.index("- name: Build Security Decision Record")
    assert "--check-fresh availability-probe.json --max-age-hours 2" in wf[step:step + 600]
    assert "--probe-feed availability-probe.json" in wf


def test_an_ongoing_incident_fails_the_monitor_run_after_publishing(tmp_path):
    samples = [_sample(NOW - timedelta(minutes=15), {"site": "HTTP 500"})]
    doc = probe.build({"feed_type": "availability-status", "samples": samples}, _sample(NOW, {"site": "HTTP 500"}), NOW)
    (tmp_path / "f.json").write_text(json.dumps(doc))
    assert probe.main(["--fail-on-incident", str(tmp_path / "f.json")]) == 1
    ok = probe.build({}, _sample(NOW), NOW)
    (tmp_path / "g.json").write_text(json.dumps(ok))
    assert probe.main(["--fail-on-incident", str(tmp_path / "g.json")]) == 0
    wf = (REPO / ".github" / "workflows" / "availability-probe.yml").read_text()
    assert wf.index("Publish the status feed") < wf.index("--fail-on-incident")
