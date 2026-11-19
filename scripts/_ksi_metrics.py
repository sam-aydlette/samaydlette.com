"""Daily KSI metrics (SDR-CSX-KMT): one point per day, up to a year.

FedRAMP 20x Class C needs, in the Security Decision Record, for each applicable
KSI: a summary of each metric over the past 30 days, a summary up to the past
year, and all daily metric data, including the status of persistent
validation, up to the past year.

One module owns that history, and both workflows write it through one CLI,
scripts/build-ksi-metrics.py: the deploy just before it builds the SDR (which
carries the history, scripts/build-sdr.py), and the nightly every day between
deploys.

Each KSI's status comes from one evaluator, `evaluate()`: the facts in
scripts/_ksi_methods.py, decided by policies/compliance/ksi.rego. A day
evaluated twice keeps its last point.

The history a writer appends to is the published `ksi-metrics.json`, its
signature verified by the workflow against the deploy's or the nightly's
identity before it reaches this module. Until the first one is published, it
starts from the system-level points the verified SDR carried, which have no
per-KSI data.

Stdlib only (the runtime signal check needs `cryptography`, as in the VDR
builder), fail-closed.
"""

import importlib.util
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ksi_methods  # noqa: E402

SCHEMA = "ksi-metrics/1"
HISTORY_DAYS = 366
URI = "https://samaydlette.com/.well-known/ksi-metrics.json"
SYSTEM_FIELDS = ("ksi_in_scope", "controls_in_scope", "signal_validations", "signal_failing",
                 "vdr_total", "vdr_blocking", "vdr_accepted", "vdr_kev")
SOURCES = ("deploy", "nightly", "sdr")


def _fail(msg):
    raise SystemExit(f"::error::KSI metrics: {msg} (fail-closed)")


# --- the evaluation -----------------------------------------------------------------

def verified_runtime(path, now):
    """The runtime signal only when its signature verifies against the pinned key
    and it is fresh (the VDR builder's check); otherwise None: no live credit."""
    spec = importlib.util.spec_from_file_location(
        "build_vdr_report", Path(__file__).resolve().parent / "build-vdr-report.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    check = mod.load_runtime_signal(path, now=now)
    if not check["verified"]:
        print(f"note: no live KSI credit: {check['reason']}")
        return None
    return json.loads(Path(path).read_text())


def evaluate(*, deploy_signal, vdr, beacon, runtime_signal, now, methods=None):
    """Each KSI's status, and the facts it was decided from."""
    facts = _ksi_methods.facts(deploy_signal=deploy_signal, vdr=vdr, beacon=beacon,
                               runtime_signal=runtime_signal, now=now, methods=methods)
    return _ksi_methods.decide(facts), facts


# --- one day's point -------------------------------------------------------------------

def system_metrics(ksi_in_scope, controls_in_scope, vdr, signal):
    vals = (signal or {}).get("validations") or []
    vsum = (vdr or {}).get("summary") or {}
    return {"ksi_in_scope": ksi_in_scope, "controls_in_scope": controls_in_scope,
            "signal_validations": len(vals),
            "signal_failing": sum(1 for v in vals if v.get("result") == "fail"),
            "vdr_total": vsum.get("total_findings", 0), "vdr_blocking": vsum.get("blocking", 0),
            "vdr_accepted": vsum.get("risk_accepted", 0), "vdr_kev": vsum.get("kev", 0)}


def persistent_validation(facts, beacon, runtime_signal):
    """Whether the persistent validation ran and passed: the nightly (its beacon)
    and the runtime check (its signal), each counted only while fresh."""
    inputs = facts["inputs"]
    results = (beacon or {}).get("gate_results") or []
    return {
        "nightly": {"fresh": inputs["beacon_fresh"],
                    "result": (beacon or {}).get("result") if inputs["beacon_fresh"] else None,
                    "failing_checks": sorted(r["check"] for r in results
                                             if isinstance(r, dict) and r.get("result") == "fail")
                    if inputs["beacon_fresh"] else []},
        "runtime": {"fresh": inputs["runtime_fresh"],
                    "divergence": ((runtime_signal or {}).get("divergence") or {}).get("status")
                    if inputs["runtime_fresh"] else None},
    }


def point(ksi_result, facts, beacon, runtime_signal, system, now, source):
    if source not in ("deploy", "nightly"):
        _fail(f"unknown source {source!r}")
    return {"date": now.date().isoformat(), "evaluated_at": now.isoformat(), "source": source,
            "ksis": {k: {"status": v["status"], "passing": v["passing"], "failing": list(v["failing"])}
                     for k, v in sorted(ksi_result["ksis"].items())},
            "persistent_validation": persistent_validation(facts, beacon, runtime_signal),
            **{f: system[f] for f in SYSTEM_FIELDS}}


# --- the history ----------------------------------------------------------------------

def load(path):
    """The published history (already signature-verified), or None when absent."""
    p = Path(path) if path else None
    if not p or not p.exists():
        return None
    try:
        doc = json.loads(p.read_text())
    except (OSError, ValueError) as e:
        _fail(f"{path} is unreadable ({e})")
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA or not isinstance(doc.get("daily_metric_data"), list):
        _fail(f"{path} is not a {SCHEMA} document")
    for h in doc["daily_metric_data"]:
        if not (isinstance(h, dict) and isinstance(h.get("date"), str) and h.get("source") in SOURCES):
            _fail(f"{path} holds a daily point without a date or source")
    return doc


def seed_from_sdr(sdr):
    """The system-level points a verified SDR carried before this history
    existed. They have no per-KSI data and no persistent-validation status."""
    old = ((sdr or {}).get("metrics") or {}).get("daily_metric_data") or []
    return [{"date": h["date"], "evaluated_at": None, "source": "sdr", "ksis": None,
             "persistent_validation": None, **{f: h.get(f) for f in SYSTEM_FIELDS}}
            for h in old if isinstance(h, dict) and isinstance(h.get("date"), str)]


def append(history, new):
    """The history with `new` as its day's point (a later evaluation of the same
    day replaces the earlier one), in date order, the past year only."""
    kept = [h for h in history if h["date"] != new["date"]]
    return sorted(kept + [new], key=lambda h: h["date"])[-HISTORY_DAYS:]


def _summary(window):
    if not window:
        return {}
    per_ksi = {}
    for h in window:
        for k, v in (h.get("ksis") or {}).items():
            s = per_ksi.setdefault(k, {"days": 0, "days_implemented": 0, "days_with_failing_method": 0,
                                       "status": None})
            s["days"] += 1
            s["days_implemented"] += v["status"] == "Implemented"
            s["days_with_failing_method"] += bool(v["failing"])
            s["status"] = v["status"]
    pv = [h["persistent_validation"] for h in window if h.get("persistent_validation")]
    return {
        "days": len(window), "from": window[0]["date"], "to": window[-1]["date"],
        "days_with_ksi_data": sum(1 for h in window if h.get("ksis")),
        "max_blocking": max(h.get("vdr_blocking") or 0 for h in window),
        "max_failing_validations": max(h.get("signal_failing") or 0 for h in window),
        "current_accepted": window[-1].get("vdr_accepted") or 0,
        "persistent_validation": {
            "days_recorded": len(pv),
            "nightly_days_passed": sum(1 for p in pv if p["nightly"]["result"] == "success"),
            "runtime_days_converged": sum(1 for p in pv if p["runtime"]["divergence"] == "converged"),
        },
        "ksis": dict(sorted(per_ksi.items())),
    }


def summaries(history):
    return {"summary_30d": _summary(history[-30:]), "summary_1y": _summary(history)}


def document(history, *, now, source, fedramp_id, signal_id, commit, run_url):
    return {
        "schema": SCHEMA,
        "fedramp_id": fedramp_id,
        "emitted_at": now.isoformat(),
        "ksi_signal_id": signal_id,
        "updated_by": {"source": source, "commit": commit, "run_url": run_url},
        "note": ("Daily metric data for each KSI (SDR-CSX-KMT): each KSI's status from "
                 "policies/compliance/ksi.rego and the status of persistent validation, one point per day "
                 "from the deploy or the nightly, up to a year. Points with source 'sdr' predate this "
                 "history and carry system-level metrics only."),
        **summaries(history),
        "daily_metric_data": history,
    }


def write(doc, path):
    """Compact: a year of per-KSI points is about 1.4 MB this way, about 5 MB indented."""
    Path(path).write_text(json.dumps(doc, separators=(",", ":")) + "\n")


def update(previous_doc, seed_sdr, new_point, **meta):
    """The new published document: the verified history (or, before the first
    one, the SDR's points) with today's point added."""
    history = previous_doc["daily_metric_data"] if previous_doc else seed_from_sdr(seed_sdr)
    return document(append(history, new_point), **meta)
