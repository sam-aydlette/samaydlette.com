"""The staleness gate: published evidence older than the policy window must fail.

The failure this guards against actually happened. The published VDR sat at one
`emitted_at` for twelve days while every gate reported green, because no check
anywhere compared the *served* artifact's age to the 24-hour policy. These tests
pin the comparison itself, so the gate cannot quietly stop asserting it.
"""

import hashlib
import importlib.util
import json
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


@pytest.mark.parametrize("max_age", ["1", "48"])
def test_threshold_is_honoured(tmp_path, max_age):
    url = write_artifact(tmp_path, hours_ago(24))
    expected = 1 if max_age == "1" else 0
    assert freshness.main(["--url", url, "--max-age-hours", max_age]) == expected
