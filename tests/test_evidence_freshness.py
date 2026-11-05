"""The staleness gate: published evidence older than the policy window must fail.

The failure this guards against actually happened. The published VDR sat at one
`emitted_at` for twelve days while every gate reported green, because no check
anywhere compared the *served* artifact's age to the 24-hour policy. These tests
pin the comparison itself, so the gate cannot quietly stop asserting it.
"""

import hashlib
import importlib.util
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "check-evidence-freshness.py"


def load_module():
    spec = importlib.util.spec_from_file_location("_freshness", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


freshness = load_module()


def write_artifact(tmp_path, emitted_at, name="vdr-report.json"):
    path = tmp_path / name
    path.write_text(json.dumps({"emitted_at": emitted_at, "findings": []}))
    return path.as_uri()


def hours_ago(hours):
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


def test_fresh_artifact_passes(tmp_path):
    url = write_artifact(tmp_path, hours_ago(2))
    assert freshness.main(["--url", url]) == 0


def test_stale_artifact_fails(tmp_path):
    """The twelve-day case. 296 hours old must not read as compliant."""
    url = write_artifact(tmp_path, hours_ago(296))
    assert freshness.main(["--url", url]) == 1


def test_boundary_just_inside_the_window_passes(tmp_path):
    url = write_artifact(tmp_path, hours_ago(23.5))
    assert freshness.main(["--url", url]) == 0


def test_boundary_just_outside_the_window_fails(tmp_path):
    url = write_artifact(tmp_path, hours_ago(24.5))
    assert freshness.main(["--url", url]) == 1


def test_zulu_suffix_is_parsed(tmp_path):
    """The KSI signal emits '...Z'; the VDR emits '+00:00'. Both must parse."""
    stamp = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    url = write_artifact(tmp_path, stamp)
    assert freshness.main(["--url", url]) == 0


def test_missing_emitted_at_is_a_failure_not_a_pass(tmp_path):
    """An artifact with no timestamp must never read as fresh."""
    path = tmp_path / "vdr-report.json"
    path.write_text(json.dumps({"findings": []}))
    assert freshness.main(["--url", path.as_uri()]) == 2


def test_unfetchable_artifact_is_a_failure_not_a_pass(tmp_path):
    """A 404 or a network fault is not evidence of freshness."""
    url = (tmp_path / "does-not-exist.json").as_uri()
    assert freshness.main(["--url", url]) == 2


def test_unparseable_artifact_is_a_failure(tmp_path):
    path = tmp_path / "vdr-report.json"
    path.write_text("not json at all")
    assert freshness.main(["--url", path.as_uri()]) == 2


def test_sha256_mismatch_fails_even_when_fresh(tmp_path):
    """Post-publish edge check: a fresh but wrong-bytes serve is still a failure."""
    url = write_artifact(tmp_path, hours_ago(1))
    assert freshness.main(["--url", url, "--expect-sha256", "0" * 64]) == 1


def test_sha256_match_passes(tmp_path):
    url = write_artifact(tmp_path, hours_ago(1))
    raw = Path(url[len("file://"):]).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    assert freshness.main(["--url", url, "--expect-sha256", digest]) == 0


def _config(tmp_path, window):
    cfg = json.loads((REPO / "infrastructure" / "schemas" / "freshness-config.json").read_text())
    for a in cfg["artifacts"]:
        if a["path"] == ".well-known/vdr-report.json":
            a["max_age_hours"] = window
    p = tmp_path / "freshness-config.json"
    p.write_text(json.dumps(cfg))
    return str(p)


@pytest.mark.parametrize("window", [1, 48])
def test_the_window_comes_from_the_governed_config(tmp_path, window):
    url = write_artifact(tmp_path, hours_ago(24))
    expected = 1 if window == 1 else 0
    assert freshness.main(["--url", url, "--config", _config(tmp_path, window)]) == expected


def test_there_is_no_flag_that_overrides_the_governed_window(tmp_path):
    url = write_artifact(tmp_path, hours_ago(30))
    with pytest.raises(SystemExit):
        freshness.main(["--url", url, "--max-age-hours", "48"])


def test_an_invalid_or_missing_config_fails_closed(tmp_path):
    url = write_artifact(tmp_path, hours_ago(1))
    bad = REPO / "tests" / "fixtures" / "freshness" / "freshness-config-invalid.json"
    assert freshness.main(["--url", url, "--config", str(bad)]) == 2
    assert freshness.main(["--url", url, "--config", str(tmp_path / "absent.json")]) == 2


def test_an_artifact_without_a_governed_window_cannot_pass(tmp_path):
    url = write_artifact(tmp_path, hours_ago(1), name="unlisted.json")
    assert freshness.main(["--url", url]) == 2


def test_each_artifact_is_measured_by_its_own_field_and_window(tmp_path):
    # The trust center carries generated_at and a 30-day deploy-cadence window.
    path = tmp_path / "trust-center.json"
    path.write_text(json.dumps({"generated_at": hours_ago(200)}))
    assert freshness.main(["--url", path.as_uri()]) == 0
    path.write_text(json.dumps({"generated_at": hours_ago(800)}))
    assert freshness.main(["--url", path.as_uri()]) == 1
    # A nested field (the SDR's metadata.lastUpdated, FedRAMP's schema).
    sdr = tmp_path / "security-decision-record.json"
    sdr.write_text(json.dumps({"metadata": {"lastUpdated": hours_ago(5)}}))
    assert freshness.main(["--url", sdr.as_uri()]) == 0


def test_an_artifact_without_a_timestamp_field_is_measured_by_last_modified(tmp_path):
    csv = tmp_path / "iiw.csv"
    csv.write_text("a,b\n")
    assert freshness.main(["--url", csv.as_uri()]) == 0  # just written: Last-Modified is now
    old = (datetime.now(timezone.utc) - timedelta(days=40)).timestamp()
    os.utime(csv, (old, old))
    assert freshness.main(["--url", csv.as_uri()]) == 1


def _site(tmp_path, age_hours):
    """Every listed artifact under a file:// site, all aged `age_hours`."""
    cfg = json.loads((REPO / "infrastructure" / "schemas" / "freshness-config.json").read_text())
    stamp = hours_ago(age_hours)
    for a in cfg["artifacts"]:
        f = tmp_path / a["path"]
        f.parent.mkdir(parents=True, exist_ok=True)
        doc = {}
        if a["timestamp"]["source"] == "json":
            node = doc
            *parents, leaf = a["timestamp"]["field"].split(".")
            for k in parents:
                node = node.setdefault(k, {})
            node[leaf] = stamp
        f.write_text(json.dumps(doc))
        t = (datetime.now(timezone.utc) - timedelta(hours=age_hours)).timestamp()
        os.utime(f, (t, t))
    return tmp_path.as_uri()


def test_all_checks_every_listed_artifact(tmp_path):
    site = _site(tmp_path, 1)
    assert freshness.main(["--all", site]) == 0
    stale = tmp_path / ".well-known" / "vdr-report.json"
    stale.write_text(json.dumps({"emitted_at": hours_ago(30)}))
    assert freshness.main(["--all", site]) == 1
    (tmp_path / ".well-known" / "trust-center.json").unlink()
    assert freshness.main(["--all", site]) == 2
