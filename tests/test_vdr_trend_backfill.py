"""Reconstructed trend points merge without ever rewriting live history.

The ledger lost three months of points to a sync ordering bug. The daily data
survived as vdr-report.json object versions, and scripts/backfill-vdr-trend.py
rebuilds points from them through the live builder's own point_from_report(), so
a reconstructed point and a live one are the same function of the same input.

The merge runs on every deploy. That is only safe because existing points always
win: a reconstruction can fill gaps but must never overwrite what the pipeline
actually recorded, and re-running must change nothing.
"""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "backfill-vdr-trend.py"
DATA = REPO / "data" / "vdr-trend-backfill.json"
WORKFLOW = REPO / ".github" / "workflows" / "deploy-with-opa.yml"

_spec = importlib.util.spec_from_file_location(
    "vdr_trend_builder", REPO / "scripts" / "build-vdr-trend.py"
)
builder = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(builder)


def run_merge(points_file, trend_file):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--points", str(points_file), "--trend", str(trend_file)],
        capture_output=True, text=True, check=True,
    )


def point(date, **kw):
    base = {"date": date, "unique_cves": 0, "open_cves": 0, "blocking": 0,
            "kev": 0, "by_pain": {}, "total_findings": 0, "risk_accepted": 0}
    base.update(kw)
    return base


def write(path, obj):
    path.write_text(json.dumps(obj))
    return path


# --- merge semantics --------------------------------------------------------

def test_gaps_are_filled(tmp_path):
    pts = write(tmp_path / "p.json", {"points": [point("2026-06-01"), point("2026-06-02")]})
    led = write(tmp_path / "t.json", {"points": [point("2026-06-03")]})
    run_merge(pts, led)
    got = json.loads(led.read_text())
    assert [p["date"] for p in got["points"]] == ["2026-06-01", "2026-06-02", "2026-06-03"]


def test_live_points_are_never_overwritten(tmp_path):
    """The reconstruction must lose every collision with recorded history."""
    pts = write(tmp_path / "p.json", {"points": [point("2026-06-01", risk_accepted=99)]})
    led = write(tmp_path / "t.json", {"points": [point("2026-06-01", risk_accepted=13)]})
    run_merge(pts, led)
    got = json.loads(led.read_text())
    assert len(got["points"]) == 1
    assert got["points"][0]["risk_accepted"] == 13, "live point must win"


def test_merge_is_idempotent(tmp_path):
    pts = write(tmp_path / "p.json", {"points": [point("2026-06-01"), point("2026-06-02")]})
    led = write(tmp_path / "t.json", {"points": [point("2026-06-03")]})
    run_merge(pts, led)
    first = led.read_text()
    run_merge(pts, led)
    assert led.read_text() == first


def test_missing_points_file_is_not_an_error(tmp_path):
    led = write(tmp_path / "t.json", {"points": [point("2026-06-03")]})
    r = run_merge(tmp_path / "absent.json", led)
    assert "nothing to merge" in r.stdout
    assert json.loads(led.read_text())["points"] == [point("2026-06-03")]


def test_rolling_window_is_respected(tmp_path):
    many = [point(f"2026-01-{d:02d}") for d in range(1, 29)]
    pts = write(tmp_path / "p.json", {"points": many})
    led = write(tmp_path / "t.json", {"points": []})
    subprocess.run([sys.executable, str(SCRIPT), "--points", str(pts),
                    "--trend", str(led), "--keep-days", "10"], check=True, capture_output=True)
    got = json.loads(led.read_text())
    assert len(got["points"]) == 10
    assert got["points"][-1]["date"] == "2026-01-28"  # keeps the most recent


def test_points_stay_chronological(tmp_path):
    pts = write(tmp_path / "p.json", {"points": [point("2026-06-05"), point("2026-06-01")]})
    led = write(tmp_path / "t.json", {"points": [point("2026-06-03")]})
    run_merge(pts, led)
    dates = [p["date"] for p in json.loads(led.read_text())["points"]]
    assert dates == sorted(dates)


def test_mode_arguments_are_mutually_required(tmp_path):
    r = subprocess.run([sys.executable, str(SCRIPT), "--bucket", "b"],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "--bucket and --out" in r.stderr


# --- the committed reconstruction ------------------------------------------

def test_committed_backfill_matches_the_published_point_shape():
    """A reconstructed point must be indistinguishable from a live one."""
    data = json.loads(DATA.read_text())
    expected = set(builder.point_from_report(
        {"emitted_at": "2026-01-01T00:00:00Z", "summary": {}}
    ).keys())
    assert data["points"], "the committed reconstruction is empty"
    for p in data["points"]:
        assert set(p.keys()) == expected, f"point {p.get('date')} has a different shape"


def test_committed_backfill_is_sorted_and_unique():
    dates = [p["date"] for p in json.loads(DATA.read_text())["points"]]
    assert dates == sorted(dates)
    assert len(dates) == len(set(dates))


def test_pipeline_merges_before_appending_today():
    """Order matters: today's point must be the last word, not the backfill's."""
    text = WORKFLOW.read_text()
    assert "backfill-vdr-trend.py" in text, "the pipeline must merge the reconstruction"
    assert text.index("backfill-vdr-trend.py") < text.index("build-vdr-trend.py --report")
