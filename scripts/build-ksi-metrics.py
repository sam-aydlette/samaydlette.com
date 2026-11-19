#!/usr/bin/env python3
"""Add today's point to the daily KSI metric history (SDR-CSX-KMT).

Both workflows run this, with the same evaluator and format
(scripts/_ksi_metrics.py): the deploy just before it builds the SDR, which
carries the history (and checks that today's statuses are its own), and the
nightly every day, after it writes its status beacon:

    build-ksi-metrics.py --source nightly --ksi-signal ksi-signal.json \\
        --vdr vdr-report.json --vdr-status vdr-status.json \\
        --runtime-signal ksi-signal-runtime.json \\
        --previous ksi-metrics-previous.json --sdr security-decision-record.json

Every input is one the workflow already verified: the inventory, the VDR, the
nightly's beacon (only when it was signed), the runtime signal (checked here
against its key), and the published history and SDR (their signatures checked
by scripts/fetch-verified.sh; the history is absent before the first one, when
it starts from the SDR's points). Writes ksi-metrics.json.

Stdlib only, fail-closed.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _controls  # noqa: E402
import _ksi_metrics  # noqa: E402
from _common import commit, fedramp_id, run_url  # noqa: E402


def _optional(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError, TypeError):
        return None


def build(*, signal_path, catalog_path, vdr, beacon, runtime_path, previous, sdr, now, source, sha, run):
    signal = json.loads(Path(signal_path).read_text())
    irs = _controls.load(signal_path, catalog_path)
    runtime = _ksi_metrics.verified_runtime(runtime_path, now)
    ksi_result, facts = _ksi_metrics.evaluate(deploy_signal=signal, vdr=vdr, beacon=beacon,
                                              runtime_signal=runtime, now=now)
    system = _ksi_metrics.system_metrics(len(facts["ksis"]), len({ir["control-id"] for ir in irs}), vdr, signal)
    new = _ksi_metrics.point(ksi_result, facts, beacon, runtime, system, now, source)
    meta = {"fedramp_id": fedramp_id(), "signal_id": signal.get("signal_id"), "commit": sha, "run_url": run}
    return _ksi_metrics.update(previous, sdr, new, now=now, source=source, **meta)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--ksi-signal", default="ksi-signal.json")
    ap.add_argument("--catalog", default="schemas/ksi-catalog.json")
    ap.add_argument("--vdr", default="vdr-report.json")
    ap.add_argument("--source", choices=("deploy", "nightly"), required=True)
    ap.add_argument("--vdr-status", default=None, help="the nightly's beacon, only when its signature verified")
    ap.add_argument("--runtime-signal", default="ksi-signal-runtime.json")
    ap.add_argument("--previous", default=None, help="the published history, signature verified")
    ap.add_argument("--sdr", default=None, help="the published SDR, signature verified (the first history)")
    ap.add_argument("--output", default="ksi-metrics.json")
    a = ap.parse_args(argv)
    now = datetime.now(timezone.utc)
    doc = build(signal_path=a.ksi_signal, catalog_path=a.catalog, vdr=_optional(a.vdr) or {},
                beacon=_optional(a.vdr_status) if a.vdr_status else None, runtime_path=a.runtime_signal,
                previous=_ksi_metrics.load(a.previous), sdr=_optional(a.sdr) if a.sdr else None,
                now=now, source=a.source, sha=commit(), run=run_url())
    _ksi_metrics.write(doc, a.output)
    today = doc["daily_metric_data"][-1]
    by = {}
    for v in today["ksis"].values():
        by[v["status"]] = by.get(v["status"], 0) + 1
    print(f"ksi-metrics: {len(doc['daily_metric_data'])} day(s); today {dict(sorted(by.items()))}; "
          f"nightly {today['persistent_validation']['nightly']['result']}, "
          f"runtime {today['persistent_validation']['runtime']['divergence']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
