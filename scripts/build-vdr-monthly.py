#!/usr/bin/env python3
"""Monthly vulnerability detection and response activity report.

VER-TFR-MHR: report vulnerability detection and response activity, in a
consistent human-readable format, at least monthly. VER-RPT-HLO: include a
high-level overview of ALL detection and response activities in the period,
including vulnerability disclosure, bug bounty, penetration testing and
assessments. VER-RPT-PER: summarize all activity since the previous report,
including persistent verification and validation.

Writes vdr-monthly.json and vdr-monthly.md for the calendar month to date (UTC).
Every build adds the runs it can see to the month: the scans and feeds the VDR
build read, the runtime verification runs, the nightly non-machine
verification, and the activities the operator recorded outside the pipeline
(data/vdr-activities.json). The previous published vdr-monthly.json carries the
month's earlier runs forward; when the month turns, the finished month moves to
`previousMonths` (kept for twelve months) and a new month starts. Each activity
type is listed every time, with "none this period" when nothing happened.

    build-vdr-monthly.py --vdr vdr-report.json --history vdr-history.json \
        --decisions ../data/decisions.json --activities ../data/vdr-activities.json \
        --non-machine vdr-non-machine-vv.json [--runtime-runs FILE] [--previous vdr-monthly.json]

A missing or unreadable input stops the build: an absent input cannot read as
"no activity".
"""

import argparse
import importlib.util
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import _offering  # noqa: E402
import _decisions  # noqa: E402

_spec = importlib.util.spec_from_file_location("cr26_for_monthly", HERE / "build-cr26-vdr.py")
if _spec is None or _spec.loader is None:
    raise SystemExit("::error::monthly VDR report: cannot load build-cr26-vdr.py (fail-closed)")
cr26 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cr26)

JSON_OUT = "vdr-monthly.json"
MD_OUT = "vdr-monthly.md"
KEEP_MONTHS = 12
RUNTIME_URI = "https://samaydlette.com/.well-known/ksi-signal-runtime.json"

# Every activity type the report states, in order. `feeds` are the detection
# feed names (methodology.detection.feeds[].feed) whose runs count for it;
# `recorded` the data/vdr-activities.json kinds that count for it.
ACTIVITY_TYPES = [
    {"type": "sca", "title": "Software composition analysis (Grype over every dependency tree; Dependabot alerts)",
     "feeds": {"grype", "dependabot"}, "recorded": set()},
    {"type": "iac-sast", "title": "Infrastructure-as-code static analysis (Checkov, tfsec)",
     "feeds": {"checkov", "tfsec"}, "recorded": set()},
    {"type": "code-sast", "title": "Code static analysis (CodeQL)", "feeds": {"codeql"}, "recorded": set()},
    {"type": "dast-site", "title": "Dynamic scan of the public site (OWASP ZAP)", "feeds": {"zap"},
     "recorded": {"manual-scan"}},
    {"type": "dast-api", "title": "Authenticated dynamic scan of the Silk Reeling API",
     "feeds": {"zap-api", "dast-api"}, "recorded": set()},
    {"type": "threat-intel", "title": "Known-exploited and exploit-prediction feeds (CISA KEV, FIRST EPSS)",
     "feeds": {"kev", "epss"}, "recorded": set()},
    {"type": "runtime-vv", "title": "Runtime verification and validation of machine resources", "feeds": set(),
     "recorded": set()},
    {"type": "non-machine-vv", "title": "Verification and validation of non-machine resources (machine checks, nightly)",
     "feeds": set(), "recorded": set()},
    {"type": "vdp", "title": "Vulnerability disclosure program: reports received", "feeds": set(),
     "recorded": {"vdp-report"}},
    {"type": "bug-bounty", "title": "Bug bounty program", "feeds": set(), "recorded": {"bug-bounty"}},
    {"type": "pentest", "title": "Penetration testing", "feeds": set(), "recorded": {"penetration-test"}},
    {"type": "assessment", "title": "Assessments", "feeds": set(), "recorded": {"assessment"}},
]
TYPES = {t["type"] for t in ACTIVITY_TYPES}
FEED_TYPE = {f: t["type"] for t in ACTIVITY_TYPES for f in t["feeds"]}
KIND_TYPE = {k: t["type"] for t in ACTIVITY_TYPES for k in t["recorded"]}

ACT_TOP = {"$schema", "$comment", "schema", "programs", "activities"}
ACT_KEYS = {"id", "kind", "date", "end_date", "performed_by", "summary", "evidence", "recorded_by"}
ACT_REQUIRED = {"id", "kind", "date", "performed_by", "summary", "evidence", "recorded_by"}
PROGRAMS = {"vdp", "bug-bounty", "penetration-testing"}
ACT_ID_RE = re.compile(r"^ACT-\d{3}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _fail(msg):
    raise SystemExit(f"::error::monthly VDR report: {msg} (fail-closed)")


def _read(path, what):
    p = Path(path)
    if not p.is_file():
        _fail(f"{what} {path} not found")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _fail(f"{what} {path} is not valid JSON: {exc.__class__.__name__}")


# --- the operator's record of activity outside the pipeline -------------------------

def validate_activities(doc, where="data/vdr-activities.json"):
    if not isinstance(doc, dict) or doc.get("schema") != "vdr-activities/1":
        _fail(f"{where} is not a vdr-activities/1 document")
    if set(doc) - ACT_TOP:
        _fail(f"{where}: unknown field(s) {sorted(set(doc) - ACT_TOP)}")
    progs = doc.get("programs")
    if not isinstance(progs, dict) or set(progs) != PROGRAMS:
        _fail(f"{where}: programs must state exactly {sorted(PROGRAMS)}")
    for name, p in progs.items():
        if not isinstance(p, dict) or not isinstance(p.get("active"), bool) or not str(p.get("note") or "").strip():
            _fail(f"{where}: programs.{name} needs active (true/false) and a note")
    acts = doc.get("activities")
    if not isinstance(acts, list):
        _fail(f"{where}: activities must be a list")
    seen = set()
    for a in acts:
        aid = a.get("id") if isinstance(a, dict) else None
        if not isinstance(aid, str) or not ACT_ID_RE.match(aid) or aid in seen:
            _fail(f"{where}: activity id {aid!r} is not a unique ACT-NNN")
        seen.add(aid)
        if set(a) - ACT_KEYS or ACT_REQUIRED - set(a):
            _fail(f"{aid}: fields must be {sorted(ACT_REQUIRED)} plus optional end_date")
        if a["kind"] not in KIND_TYPE:
            _fail(f"{aid}: kind {a['kind']!r} is not one of {sorted(KIND_TYPE)}")
        for k in ("date", "end_date"):
            if k in a and not (isinstance(a[k], str) and DATE_RE.match(a[k])):
                _fail(f"{aid}: {k} must be YYYY-MM-DD")
        if a.get("end_date") and a["end_date"] < a["date"]:
            _fail(f"{aid}: end_date is before date")
        for k in ("performed_by", "summary", "evidence", "recorded_by"):
            if not isinstance(a[k], str) or not a[k].strip():
                _fail(f"{aid}: {k} must be a non-empty string")
    return doc


# --- runs ------------------------------------------------------------------------------

def _month_bounds(now):
    start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    return start, now


def _in(at, lo, hi):
    dt = cr26._maybe_dt(at)
    return bool(dt and lo <= dt <= hi)


def pipeline_runs(vdr):
    """The scan and feed runs one VDR build read, as [{type, source, at, status, count}]."""
    meth = vdr.get("methodology") or {}
    det = meth.get("detection") or {}
    runs = []
    for feed in det.get("feeds") or []:
        if not isinstance(feed, dict) or feed.get("feed") not in FEED_TYPE:
            continue
        # KEV and EPSS are dated by their publisher; a scan by the build that ran it.
        at = feed.get("source_date") if feed["feed"] in ("kev", "epss") else det.get("checked_at")
        runs.append({"type": FEED_TYPE[feed["feed"]], "source": f"{feed['feed']} ({feed.get('file')})",
                     "at": at, "status": feed.get("status"), "count": feed.get("count")})
    for key, typ in (("dast", "dast-site"), ("dast_api", "dast-api"), ("codeql", "code-sast")):
        d = meth.get(key)
        if isinstance(d, dict):
            runs.append({"type": typ, "source": d.get("scanner") or key, "at": d.get("generated_at"),
                         "status": d.get("status"), "count": d.get("alerts", d.get("count"))})
    return [r for r in runs if r["at"]]


def runtime_runs(vdr, retained):
    """Runtime V&V runs: every retained run when the emitter retains them, else
    the one run the VDR build read."""
    if retained is not None:
        rows = retained.get("runs") if isinstance(retained, dict) else retained
        if not isinstance(rows, list):
            _fail("runtime runs file has no runs list")
        out = []
        for r in rows:
            if not isinstance(r, dict) or not r.get("emitted_at"):
                _fail("a retained runtime run has no emitted_at")
            out.append({"type": "runtime-vv", "source": r.get("signal_id") or RUNTIME_URI, "at": r["emitted_at"],
                        "status": "failed" if r.get("failed") else "ok",
                        "count": r.get("validations") if not isinstance(r.get("validations"), list)
                        else len(r["validations"])})
        return out, "retained runs (every run the runtime emitter kept)"
    rt = (vdr.get("methodology") or {}).get("runtime_verification")
    if isinstance(rt, dict) and rt.get("verified") and rt.get("run_history"):
        # The emitter's signed run history, carried by the VDR build that verified it.
        return runtime_runs(vdr, {"runs": rt["run_history"]})[0], \
            "retained runs (the run history the runtime emitter signs into its signal)"
    note = ("latest run only: the runtime emitter publishes only its latest run, so a run replaced between "
            "two nightly builds is not counted")
    if isinstance(rt, dict) and rt.get("verified") and rt.get("emitted_at"):
        return [{"type": "runtime-vv", "source": rt.get("signal_id") or RUNTIME_URI, "at": rt["emitted_at"],
                 "status": "failed" if rt.get("failed") else "ok", "count": rt.get("validations")}], note
    return [], note + "; the VDR build recorded no verified runtime run"


def non_machine_runs(nmv):
    if not isinstance(nmv, dict) or nmv.get("schema") != "non-machine-vv/2":
        _fail("non-machine status is not a non-machine-vv/2 document")
    n = len(nmv.get("resources") or [])
    return [{"type": "non-machine-vv", "source": f"machine checks ({n} resources)",
             "at": nmv.get("generatedAt"), "status": nmv.get("status"), "count": n}]


def recorded_runs(acts):
    return [{"type": KIND_TYPE[a["kind"]], "source": f"{a['id']}: {a['summary']}",
             "at": f"{a.get('end_date') or a['date']}T00:00:00+00:00", "status": "recorded",
             "count": None, "performedBy": a["performed_by"], "evidence": a["evidence"]}
            for a in acts["activities"]]


def _key(r):
    return (r["type"], r["source"], r["at"])


def merge(*lists):
    out = {}
    for rows in lists:
        for r in rows:
            out.setdefault(_key(r), r)
    return sorted(out.values(), key=lambda r: (r["type"], r["at"], r["source"]))


# --- build -------------------------------------------------------------------------------

def overview(runs, programs):
    rows = []
    for t in ACTIVITY_TYPES:
        mine = [r for r in runs if r["type"] == t["type"]]
        row = {"type": t["type"], "title": t["title"], "runsInPeriod": len(mine),
               "lastRun": max((r["at"] for r in mine), default=None),
               "failedRuns": sum(1 for r in mine if r.get("status") not in ("ok", "recorded")),
               "summary": "none this period" if not mine else f"{len(mine)} in period"}
        prog = {"vdp": "vdp", "bug-bounty": "bug-bounty", "pentest": "penetration-testing"}.get(t["type"])
        if prog:
            row["program"] = programs[prog]
        rows.append(row)
    return rows


def build(vdr, mrh, register, acts, nmv, retained, previous, now):
    if not isinstance(vdr, dict) or not isinstance(vdr.get("findings"), list):
        _fail("vdr-report.json has no findings list")
    lo, hi = _month_bounds(now)
    month = lo.strftime("%Y-%m")
    rt_runs, rt_basis = runtime_runs(vdr, retained)
    seen = pipeline_runs(vdr) + rt_runs + non_machine_runs(nmv) + recorded_runs(acts)
    archive = []
    carried = []
    if isinstance(previous, dict):
        if previous.get("schema") != "vdr-monthly/1":
            _fail("previous vdr-monthly.json is not a vdr-monthly/1 document")
        archive = list(previous.get("previousMonths") or [])
        if previous.get("period", {}).get("month") == month:
            carried = previous.get("runs") or []
        elif previous.get("period", {}).get("month", "") < month:
            # The month turned: the previous report is that month's final report.
            archive.insert(0, {k: previous[k] for k in ("period", "overview", "response") if k in previous})
        else:
            _fail("previous vdr-monthly.json is for a later month")
    runs = [r for r in merge(carried, seen) if _in(r["at"], lo, hi)]
    response = cr26.activity_summary(vdr, mrh, register, lo.isoformat(), hi.isoformat())
    return {
        "schema": "vdr-monthly/1",
        "rules": ["VER-TFR-MHR", "VER-RPT-HLO", "VER-RPT-PER"],
        "generatedAt": now.isoformat(),
        "period": {"month": month, "from": lo.isoformat(), "to": hi.isoformat()},
        "source": {"vdrReportId": vdr.get("report_id"), "ksiSignalId": vdr.get("ksi_signal_id"),
                   "activities": "data/vdr-activities.json", "nonMachine": "vdr-non-machine-vv.json"},
        "runtimeRunsBasis": rt_basis,
        "overview": overview(runs, acts["programs"]),
        "response": {"counts": response["counts"], "remediations": response["remediations"],
                     "decisionsRecorded": response["decisionsRecorded"],
                     "decisionsClosed": response["decisionsClosed"]},
        "runs": runs,
        "previousMonths": archive[:KEEP_MONTHS],
    }


# --- render -----------------------------------------------------------------------------

def _cell(v):
    return cr26._cell("" if v is None else v)


def render(doc):
    p = doc["period"]
    c = doc["response"]["counts"]
    out = [f"# Vulnerability detection and response: {p['month']}", "",
           "_FedRAMP VER-TFR-MHR, VER-RPT-HLO, VER-RPT-PER. Month to date; rebuilt with every VDR report. "
           "Source of truth: the signed vdr-monthly.json beside this file._", "",
           f"Period: {p['from']} to {p['to']}", "",
           "## Overview of all activities", "",
           "| Activity | This period | Last run | Failed runs |", "|---|---|---|---|"]
    for o in doc["overview"]:
        what = o["summary"]
        if "program" in o:
            prog = o["program"]
            what += f" (program {'active' if prog['active'] else 'not active'}: {prog['note']})"
        out.append(f"| {_cell(o['title'])} | {_cell(what)} | {o['lastRun'] or 'none'} | {o['failedRuns']} |")
    out += ["", f"Runtime runs counted from: {doc['runtimeRunsBasis']}.", "",
            "## Response", "",
            f"- Detections: {c['detections']}; evaluations: {c['evaluations']}; rating changes: "
            f"{c['ratingChanges']}; reductions: {c['reductions']}",
            f"- No longer reported: {c['noLongerReported']}; remediations: {c['remediations']}; "
            f"decisions recorded: {c['decisionsRecorded']}; decisions closed: {c['decisionsClosed']}", "",
            "## Runs this period", ""]
    if doc["runs"]:
        out += ["| Activity | Source | Time | Status | Count |", "|---|---|---|---|---|"]
        for r in doc["runs"]:
            out.append(f"| {r['type']} | {_cell(r['source'])} | {r['at']} | {_cell(r.get('status'))} | "
                       f"{_cell(r.get('count'))} |")
    else:
        out.append("_None this period._")
    if doc["previousMonths"]:
        out += ["", "## Previous months", "", "| Month | Activities with runs | Detections | Remediations |",
                "|---|---|---|---|"]
        for m in doc["previousMonths"]:
            active = sum(1 for o in m.get("overview") or [] if o.get("runsInPeriod"))
            mc = (m.get("response") or {}).get("counts") or {}
            out.append(f"| {m['period']['month']} | {active} of {len(m.get('overview') or [])} | "
                       f"{mc.get('detections', '')} | {mc.get('remediations', '')} |")
    return "\n".join(out) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--vdr", default="vdr-report.json")
    ap.add_argument("--history", default="vdr-history.json")
    ap.add_argument("--decisions", default=None)
    ap.add_argument("--activities", default=str(HERE.parent / "data" / "vdr-activities.json"))
    ap.add_argument("--non-machine", default="vdr-non-machine-vv.json")
    ap.add_argument("--runtime-runs", default=None)
    ap.add_argument("--previous", default=None)
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--now", default=None, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    now = datetime.fromisoformat(a.now) if a.now else datetime.now(timezone.utc)
    doc = build(_read(a.vdr, "VDR report"), _read(a.history, "VDR history"), _decisions.load(a.decisions),
                validate_activities(_read(a.activities, "activity record"), a.activities),
                _read(a.non_machine, "non-machine status"),
                _read(a.runtime_runs, "runtime runs") if a.runtime_runs else None,
                _read(a.previous, "previous monthly report") if a.previous else None, now)
    doc = _offering.stamp_fedramp_id(doc)  # CDS-CSO-FID
    out = Path(a.out_dir)
    (out / JSON_OUT).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    (out / MD_OUT).write_text(render(doc), encoding="utf-8")
    quiet = [o["type"] for o in doc["overview"] if not o["runsInPeriod"]]
    print(f"Monthly VDR report {doc['period']['month']}: {len(doc['runs'])} runs; none this period: "
          f"{', '.join(quiet) or 'nothing'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
