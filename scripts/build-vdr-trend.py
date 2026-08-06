#!/usr/bin/env python3
# =============================================================================
# VDR VULN TREND LEDGER  (RA-5(6) Automated Trend Analyses)
# =============================================================================
# Appends each VDR run's vulnerability summary to a rolling history, published at
# /.well-known/vdr-trend.json so the live trust dashboard can render the cross-run
# trend. This is the automated trend analysis RA-5(6) asks for, made public.
#
# One point per day (upsert by the VDR report's emitted_at date), rolling window
# of ~6 months. The point tracks the CVE-keyed ledger (unique/open CVEs), the
# blocking + KEV counts, the PAIN histogram, and risk-accepted config findings.
#
# Run after build-vdr-report.py in CI:
#   build-vdr-trend.py --report website/.well-known/vdr-report.json
# =============================================================================

import argparse
import json
from pathlib import Path


# The published point shape. Exported so backfill-vdr-trend.py reconstructs
# historical points through exactly this function — a second implementation
# would drift from the live one silently, and the ledger is meant to be one
# comparable series, not two shapes concatenated at a seam.
def point_from_report(rpt):
    s = rpt.get("summary", {})
    date = (rpt.get("emitted_at") or "")[:10]
    if not date:
        raise SystemExit("VDR report has no emitted_at date")
    return {
        "date": date,
        "unique_cves": s.get("unique_cves", 0),
        "open_cves": s.get("unique_cves_open", 0),
        "blocking": s.get("blocking", 0),
        "kev": s.get("kev", 0),
        "by_pain": s.get("by_pain", {}),
        "total_findings": s.get("total_findings", 0),
        "risk_accepted": s.get("risk_accepted", 0),
    }


# Upsert by date, chronological, trimmed to the rolling window. Shared with the
# backfill so both paths order and trim identically.
def merge_points(existing, incoming, keep_days):
    by_date = {p["date"]: p for p in existing if p.get("date")}
    for p in incoming:
        by_date[p["date"]] = p
    points = sorted(by_date.values(), key=lambda p: p["date"])
    return points[-keep_days:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", default="website/.well-known/vdr-report.json")
    ap.add_argument("--trend", default="website/.well-known/vdr-trend.json")
    ap.add_argument("--keep-days", type=int, default=190)
    a = ap.parse_args()

    rpt = json.loads(Path(a.report).read_text())
    point = point_from_report(rpt)
    date = point["date"]

    tp = Path(a.trend)
    trend = json.loads(tp.read_text()) if tp.exists() else {"points": []}
    points = merge_points(trend.get("points", []), [point], a.keep_days)

    trend["system_id"] = rpt.get("system_id")
    trend["control"] = "RA-5(6) — automated vulnerability trend analysis"
    trend["updated_at"] = rpt.get("emitted_at")
    trend["points"] = points
    tp.write_text(json.dumps(trend, indent=2) + "\n")
    print(f"vdr-trend: {len(points)} point(s); latest {date} "
          f"open_cves={point['open_cves']} blocking={point['blocking']} kev={point['kev']}")


if __name__ == "__main__":
    main()
