#!/usr/bin/env python3
# =============================================================================
# AVAILABILITY FEED BUILDER  (CR26 CDS-CSO-AVR, CDS-TRC-USH)
# =============================================================================
# CDS-CSO-AVR (Class C MUST): a web service showing current and historical
# availability of core services over at least the past 30 days, including
# availability incidents, human- and machine-readable, and available even when
# the offering is not.
#
# The measurement is made outside AWS: scripts/availability-probe.py runs on
# GitHub Actions every 15 minutes and publishes its feed on GitHub (the
# repository's availability-status branch), which stays reachable when the
# offering's CloudFront or S3 is down. That is the service the rule asks for.
#
# This builder republishes the same measurements on the site, signed with the
# rest of the certification data, so the package carries them: the deploy reads
# the independent feed (and fails when it is missing or stale), and this writes
# availability.json + availability.md from it: current status, 30-day
# availability and incidents per service, and a daily roll-up. It never records
# a deploy as availability.
#
#   build-availability.py --probe-feed availability-probe.json --ksi-signal ksi-signal.json
# =============================================================================

import argparse
import importlib.util
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _offering  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "availability_probe", Path(__file__).resolve().parent / "availability-probe.py")
assert _spec is not None and _spec.loader is not None
probe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(probe)

MAX_FEED_AGE_HOURS = 2.0


def _fail(msg):
    raise SystemExit(f"::error::availability: {msg} (fail-closed)")


def daily(samples, now, days=probe.WINDOW_DAYS):
    """[{date, services: {key: {probes, up}}}] for the past `days` days."""
    since = (now - timedelta(days=days)).date()
    by_day = defaultdict(lambda: defaultdict(lambda: {"probes": 0, "up": 0}))
    for s in samples:
        d = probe._parse(s["t"]).date()
        if d < since:
            continue
        for key in s.get("probed", []):
            cell = by_day[d.isoformat()][key]
            cell["probes"] += 1
            cell["up"] += 0 if key in s.get("fail", {}) else 1
    return [{"date": d, "services": {k: dict(v) for k, v in sorted(svcs.items())}}
            for d, svcs in sorted(by_day.items())]


def build(feed, signal_id, now):
    return {
        "feed_type": "availability",
        "fedRampId": _offering.fedramp_id(),
        "rules": ["CDS-CSO-AVR", "CDS-TRC-USH"],
        "emitted_at": now.isoformat(),
        "ksi_signal_id": signal_id,
        "measured_by": feed["monitor"],
        "independent_service": feed["published_at"],
        "independent_note": "This file is a signed copy carried in the certification package. The service "
                            "that stays available when the offering is down is the independent one above, "
                            "served by GitHub.",
        "measured_at": feed["generated_at"],
        "history_began": feed["history_began"],
        "history_note": feed["history_note"],
        "incident_rule": feed["incident_rule"],
        "current": feed["current"],
        "current_failures": feed["current_failures"],
        "window_days": feed["window_days"],
        "availability": feed["availability"],
        "incidents": feed["incidents"],
        "transient_failures": feed["transient_failures"],
        "daily": daily(feed["samples"], now),
    }


def render_markdown(doc):
    out = ["# Service availability", "",
           f"_Measured independently: {doc['measured_by']}_", "",
           f"- **Last probe:** {doc['measured_at']} | **Emitted:** {doc['emitted_at']}",
           f"- **Independent status page (available when this site is not):** {doc['independent_service']['human']}",
           f"- **History began:** {doc['history_began']}. {doc['history_note']}",
           f"- **Incident rule:** {doc['incident_rule']}", "",
           "| Service | Now | Availability (30 days) | Probes |", "|---|---|---|---|"]
    for key, a in doc["availability"].items():
        pct = "n/a" if a["availability_percent"] is None else f"{a['availability_percent']}%"
        out.append(f"| {a['service']} | {doc['current'].get(key, 'n/a')} | {pct} | {a['probes']} |")
    out += ["", "## Availability incidents (past 30 days)", ""]
    if not doc["incidents"]:
        out.append("None.")
    else:
        out += ["| Service | Start | End | Failed probes | Failing check |", "|---|---|---|---|---|"]
        for i in reversed(doc["incidents"]):
            out.append(f"| {i['service_name']} | {i['start']} | {i['end'] or 'ongoing'} | "
                       f"{i['failed_probes']} | {i['failing_check']} |")
    out += ["", "## Daily (passing probes / probes)", "", "| Date | " + " | ".join(doc["availability"]) + " |",
            "|---|" + "---|" * len(doc["availability"])]
    for day in reversed(doc["daily"]):
        cells = []
        for key in doc["availability"]:
            c = day["services"].get(key)
            cells.append(f"{c['up']}/{c['probes']}" if c else "—")
        out.append(f"| {day['date']} | " + " | ".join(cells) + " |")
    out += ["", "---", "_Source of truth: the signed `availability.json` (CDS-CSO-AVR)._"]
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe-feed", required=True,
                    help="the independent monitor's availability-status.json, fetched from GitHub")
    ap.add_argument("--ksi-signal", default="ksi-signal.json")
    ap.add_argument("--output", default="availability.json")
    ap.add_argument("--md-output", default="availability.md")
    a = ap.parse_args(argv)

    now = datetime.now(timezone.utc)
    why = probe.check_fresh(a.probe_feed, MAX_FEED_AGE_HOURS, now)
    if why:
        _fail("; ".join(why))
    feed = json.loads(Path(a.probe_feed).read_text())
    signal_id = None
    if Path(a.ksi_signal).exists():
        signal_id = json.loads(Path(a.ksi_signal).read_text()).get("signal_id")
    doc = build(feed, signal_id, now)
    Path(a.output).write_text(json.dumps(doc, indent=2) + "\n")
    if a.md_output:
        Path(a.md_output).write_text(render_markdown(doc) + "\n")
    down = sorted(k for k, v in doc["current"].items() if v != "up")
    print(f"availability: {len(doc['incidents'])} incident(s) in {doc['window_days']} days; down now: {down or 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
