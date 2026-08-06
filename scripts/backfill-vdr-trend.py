#!/usr/bin/env python3
# =============================================================================
# VDR TREND BACKFILL  (RA-5(6) history reconstruction)
# =============================================================================
# Repairs a trend ledger that lost its history, and keeps it repaired.
#
# The ledger accumulated only two points across three months because the website
# content sync uploaded the committed one-point seed over the published ledger
# before the trend step fetched it (fixed separately). The daily data was never
# lost, only unaccumulated: every deploy also published a signed vdr-report.json,
# and the bucket is versioned, so each run survives as an object version.
#
# TWO MODES, DELIBERATELY SPLIT
#
#   reconstruct:  --bucket BUCKET --out FILE
#       Reads stored vdr-report.json object versions and writes a plain points
#       file. Needs s3:ListBucketVersions + s3:GetObjectVersion, which an
#       operator has and the CI deploy role does not. Run once, by hand; the
#       output is committed and reviewed in a pull request.
#
#   merge:        --points FILE --trend LEDGER
#       Merges that reviewed file into the ledger. Reads no AWS API at all, so
#       CI runs it with no new permission, and the ledger it produces is signed
#       and published by the same run that built it.
#
# The split is what keeps this honest. Hand-uploading a reconstructed ledger
# would leave the published object disagreeing with its signature until the next
# deploy re-signed it -- an unverifiable artifact on a site whose whole claim is
# that you can verify it. Instead the reconstruction is committed as reviewable
# input, and the generator still produces the artifact.
#
# Every point is derived from an authentic published report through the same
# point_from_report() the live builder uses, so a reconstructed point and a live
# one are the same function of the same input. This is not a hand-edit of a
# generated artifact.
#
# IDEMPOTENT: existing ledger points always win, so merging cannot rewrite
# history the live pipeline already recorded and a second run is a no-op. Safe
# to run on every deploy, which also means the ledger self-heals if it is ever
# reset again.
#
# Usage:
#   backfill-vdr-trend.py --bucket samaydlette.com --out data/vdr-trend-backfill.json
#   backfill-vdr-trend.py --points ../data/vdr-trend-backfill.json --trend vdr-trend.json
# =============================================================================

import argparse
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

# build-vdr-trend.py has a hyphen, so it cannot be imported by name. Loading it
# by path is what keeps reconstructed points identical to live ones.
_spec = importlib.util.spec_from_file_location(
    "vdr_trend_builder", Path(__file__).resolve().parent / "build-vdr-trend.py"
)
if _spec is None or _spec.loader is None:  # pragma: no cover - packaging error
    raise SystemExit("backfill: cannot load scripts/build-vdr-trend.py")
_builder = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_builder)

REPORT_KEY = ".well-known/vdr-report.json"


def list_report_versions(bucket, key):
    """(last_modified, version_id) for every stored version, oldest first."""
    out = subprocess.run(
        ["aws", "s3api", "list-object-versions", "--bucket", bucket,
         "--prefix", key, "--output", "json"],
        capture_output=True, text=True, check=True,
    )
    data = json.loads(out.stdout) if out.stdout.strip() else {}
    return sorted(
        (v["LastModified"], v["VersionId"])
        for v in data.get("Versions", []) if v.get("Key") == key
    )


def last_version_per_day(versions):
    """One version per calendar day -- the last, matching upsert-by-date."""
    chosen = {}
    for ts, vid in versions:
        chosen[ts[:10]] = vid
    return [(day, chosen[day]) for day in sorted(chosen)]


def fetch_report(bucket, key, version_id):
    """Download one stored version to a temp file and parse it.

    get-object writes the body to a path and its own metadata to stdout, so a
    real file keeps the two from being interleaved.
    """
    with tempfile.NamedTemporaryFile(suffix=".json") as tmp:
        subprocess.run(
            ["aws", "s3api", "get-object", "--bucket", bucket, "--key", key,
             "--version-id", version_id, tmp.name],
            capture_output=True, check=True,
        )
        return json.loads(Path(tmp.name).read_text())


def reconstruct(bucket, key):
    versions = list_report_versions(bucket, key)
    if not versions:
        return [], 0
    points, skipped, seen = [], 0, set()
    for day, vid in last_version_per_day(versions):
        try:
            point = _builder.point_from_report(fetch_report(bucket, key, vid))
        except Exception as e:  # noqa: BLE001 - one bad version must not abort the rest
            print(f"backfill: skipping {day} ({type(e).__name__})", file=sys.stderr)
            skipped += 1
            continue
        # An object version's timestamp and the report's own emitted_at can
        # straddle midnight; the report's own date is authoritative.
        if point["date"] in seen:
            continue
        seen.add(point["date"])
        points.append(point)
    points.sort(key=lambda p: p["date"])
    return points, skipped


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bucket", help="reconstruct mode: bucket holding the report versions")
    ap.add_argument("--key", default=REPORT_KEY)
    ap.add_argument("--out", help="reconstruct mode: where to write the points file")
    ap.add_argument("--points", help="merge mode: reviewed points file to merge")
    ap.add_argument("--trend", help="merge mode: ledger to merge into")
    ap.add_argument("--keep-days", type=int, default=190)
    a = ap.parse_args()

    if a.bucket or a.out:
        if not (a.bucket and a.out):
            ap.error("reconstruct mode needs both --bucket and --out")
        points, skipped = reconstruct(a.bucket, a.key)
        if not points:
            print(f"backfill: no stored versions of {a.key}; nothing to reconstruct")
            return 0
        Path(a.out).write_text(json.dumps(
            {"source": f"s3://{a.bucket}/{a.key} object versions",
             "note": "Reconstructed RA-5(6) trend points. Merged into the published "
                     "ledger by the pipeline; existing points always win.",
             "points": points}, indent=2) + "\n")
        print(f"backfill: wrote {len(points)} point(s) to {a.out} "
              f"({points[0]['date']} .. {points[-1]['date']}, {skipped} unreadable)")
        return 0

    if not (a.points and a.trend):
        ap.error("merge mode needs both --points and --trend")

    pp = Path(a.points)
    if not pp.exists():
        print(f"backfill: no points file at {a.points}; nothing to merge")
        return 0
    incoming = json.loads(pp.read_text()).get("points", [])

    tp = Path(a.trend)
    trend = json.loads(tp.read_text()) if tp.exists() else {"points": []}
    existing = trend.get("points", [])
    before = {p["date"] for p in existing if p.get("date")}

    # Existing points win: merge_points lets `incoming` overwrite, so feed the
    # reconstruction first and the live points second.
    points = _builder.merge_points(incoming, existing, a.keep_days)
    added = len([p for p in points if p["date"] not in before])

    trend["points"] = points
    trend.setdefault("control", "RA-5(6) — automated vulnerability trend analysis")
    tp.write_text(json.dumps(trend, indent=2) + "\n")
    print(f"backfill: merged {added} reconstructed point(s); ledger now "
          f"{len(points)} point(s), {points[0]['date']} .. {points[-1]['date']}"
          if points else "backfill: ledger empty")
    return 0


if __name__ == "__main__":
    sys.exit(main())
