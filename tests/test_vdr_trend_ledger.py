"""The RA-5(6) vuln trend ledger accumulates, and the deploy must not clobber it.

`website/.well-known/vdr-trend.json` is the one artifact that is BOTH committed
(as a seed) and published (as an accumulating ledger). The deploy's
`aws s3 sync website/ --delete` therefore uploaded the one-point seed over the
live ledger on every run, a few hundred lines before the trend step fetched
"the published ledger" and appended to it. The ledger was permanently pinned at
two points -- the seed and today -- for three months.

Two guards here:

  1. The builder genuinely accumulates (so a regression in the upsert is caught
     directly rather than inferred from the published file months later).
  2. The workflow excludes the ledger from the content sync, and the sync still
     precedes the trend build, which is what makes the exclusion necessary.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parent.parent
BUILDER = REPO / "scripts" / "build-vdr-trend.py"
WORKFLOW = REPO / ".github" / "workflows" / "deploy-with-opa.yml"
LEDGER_KEY = ".well-known/vdr-trend.json"


# --- the builder accumulates ------------------------------------------------

def write_report(path, date, **summary):
    path.write_text(json.dumps({
        "system_id": "urn:test:sys",
        "emitted_at": f"{date}T10:00:00+00:00",
        "summary": {"unique_cves": 0, "unique_cves_open": 0, "blocking": 0,
                    "kev": 0, "by_pain": {}, "total_findings": 0,
                    "risk_accepted": 0, **summary},
    }))


def run_builder(report, trend):
    subprocess.run([sys.executable, str(BUILDER), "--report", str(report),
                    "--trend", str(trend)], check=True, capture_output=True)
    return json.loads(trend.read_text())


def test_successive_runs_append_rather_than_replace(tmp_path):
    trend = tmp_path / "trend.json"
    for day in ("2026-05-08", "2026-05-09", "2026-05-10"):
        report = tmp_path / "r.json"
        write_report(report, day)
        out = run_builder(report, trend)
    assert [p["date"] for p in out["points"]] == ["2026-05-08", "2026-05-09", "2026-05-10"]


def test_same_day_upserts_instead_of_duplicating(tmp_path):
    trend, report = tmp_path / "trend.json", tmp_path / "r.json"
    write_report(report, "2026-05-08", risk_accepted=15)
    run_builder(report, trend)
    write_report(report, "2026-05-08", risk_accepted=13)
    out = run_builder(report, trend)
    assert [p["date"] for p in out["points"]] == ["2026-05-08"]
    assert out["points"][0]["risk_accepted"] == 13


def test_starting_from_a_seed_preserves_the_seed(tmp_path):
    """The exact live shape: a one-point seed plus today must give two points.

    This is what the published ledger looked like every day for three months.
    It is correct behaviour for ONE run -- the bug was that every run started
    from the seed again.
    """
    trend, report = tmp_path / "trend.json", tmp_path / "r.json"
    trend.write_text(json.dumps({"points": [{"date": "2026-05-08", "open_cves": 0}]}))
    write_report(report, "2026-08-06")
    out = run_builder(report, trend)
    assert [p["date"] for p in out["points"]] == ["2026-05-08", "2026-08-06"]


# --- the deploy must not overwrite the published ledger ---------------------

def sync_step_body():
    wf = yaml.safe_load(WORKFLOW.read_text())
    for job in wf["jobs"].values():
        for step in job.get("steps", []):
            if "aws s3 sync website/" in (step.get("run") or ""):
                return step["run"]
    pytest.fail("no step running `aws s3 sync website/` was found")


def test_content_sync_excludes_the_accumulating_ledger():
    """Without this exclusion the sync replaces the live ledger with the seed."""
    body = sync_step_body()
    assert f'--exclude "{LEDGER_KEY}"' in body, (
        f"`aws s3 sync website/ ... --delete` must exclude {LEDGER_KEY}; the "
        "published object is the source of truth for this file and the sync "
        "would otherwise overwrite it with the committed seed."
    )


def test_sync_still_precedes_the_trend_build():
    """The exclusion matters only because the sync runs first; pin that order.

    If the trend build ever moves ahead of the sync this test still passes and
    the exclusion becomes harmless -- but if someone removes the exclusion
    believing order protects them, the test above fails and says why.
    """
    text = WORKFLOW.read_text()
    assert text.index("aws s3 sync website/") < text.index("build-vdr-trend.py")
