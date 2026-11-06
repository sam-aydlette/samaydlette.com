#!/usr/bin/env python3
"""Monthly access summaries for the certification data (CDS-TRC-ACL).

Reads the CloudFront access records the deploy synced from the log bucket (JSON
lines, gzipped or plain, one object per request with the fields the delivery
keeps: see scripts/check-edge-access-logging.py ALLOWED_FIELDS) and writes
access-summary.json (+ .md): per month, how many requests reached each
certification artifact under /.well-known/ and the trust center under /trust/,
by response class and by country. Nothing else.

Privacy (operator's condition, 2026-11-05):
- Only /.well-known/ and /trust/ requests are counted; every other record is
  discarded unread beyond its path. CloudFront cannot limit logging by path, so
  this is where the limit is applied.
- A path is published by name only when it served an object (2xx or 304).
  Requests for anything else (probes for files that do not exist, errors) are
  counted under "other", so a requester cannot write a string into this file.
- No IP, user agent, referrer, cookie or query string exists in the records;
  the summary carries counts only.

Own-records lookup (DEC-160): `own_records()` finds the records of a party's
own requests from the times and paths it gives, since nothing identifies a
requester. It is exercised on every build against a simulated requester
(EXERCISE): first over fixed synthetic records with a known answer (the build
fails if the lookup gets it wrong), then over the real records, where only the
count is logged. Nothing is delivered to anyone, and no real request is
answered (DEC-194).

Retention: raw records expire after 90 days (infrastructure/logging.tf). Each
month's summary is carried forward from the previously published file, so
summaries are kept for MONTHS_KEPT months (FedRAMP asks for at least six). A
month is recomputed from the records only when they cover at least as much of it
as the published summary did, so a month whose early days have expired keeps its
fuller earlier count.
"""
import argparse
import gzip
import json
import re
import sys
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _engagement  # noqa: E402
import _offering  # noqa: E402

MONTHS_KEPT = 13
MIN_MONTHS_KEPT = 6
PREFIXES = ("/.well-known/", "/trust/")
SAFE_PATH = re.compile(r"^/[A-Za-z0-9._/-]{0,200}$")
SERVED = re.compile(r"^(2\d\d|304)$")
COUNTRY = re.compile(r"^[A-Z]{2}$")
OTHER = "other (not found, error, or not an object)"
SUPPLIED_FIELDS = ("date", "time", "x-edge-location", "c-country", "cs-method", "cs-uri-stem", "sc-status",
                   "sc-bytes", "x-edge-result-type")
REQUESTER = "A. Reader (simulated)"
# The simulated request: what it says about its own requests, and, over the
# synthetic records below, the answer the lookup must give.
EXERCISE = {"requester": REQUESTER,
            "asks": "Every record of my requests for the trust manifest on 2026-11-02 between 14:00 and 14:10 UTC. "
                    "I was definitely there. Probably.",
            "window": {"date": "2026-11-02", "from": "14:00:00", "to": "14:10:00",
                       "paths": ["/.well-known/trust-manifest.json"]},
            "synthetic_records": [
                {"date": "2026-11-02", "time": "14:03:11", "cs-uri-stem": "/.well-known/trust-manifest.json",
                 "sc-status": "200", "c-country": "US"},
                {"date": "2026-11-02", "time": "14:09:59", "cs-uri-stem": "/.well-known/trust-manifest.json",
                 "sc-status": "304", "c-country": "US"},
                {"date": "2026-11-02", "time": "14:11:00", "cs-uri-stem": "/.well-known/trust-manifest.json",
                 "sc-status": "200", "c-country": "US"},
                {"date": "2026-11-02", "time": "14:05:00", "cs-uri-stem": "/index.html",
                 "sc-status": "200", "c-country": "US"},
                {"date": "2026-11-03", "time": "14:05:00", "cs-uri-stem": "/.well-known/trust-manifest.json",
                 "sc-status": "200", "c-country": "US"}],
            "expected_matches": 2}


def _fail(msg):
    raise SystemExit(f"::error::access summary: {msg} (fail-closed)")


def read_records(root):
    """Yield one dict per access record under root (*.gz or plain JSON lines)."""
    for p in sorted(Path(root).rglob("*")) if Path(root).is_dir() else []:
        if not p.is_file():
            continue
        opener = gzip.open if p.suffix == ".gz" else open
        try:
            with opener(p, "rt", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        _fail(f"{p.name} holds a line that is not JSON")
                    if isinstance(rec, dict):
                        yield rec
        except (OSError, EOFError) as exc:
            _fail(f"{p.name} could not be read ({type(exc).__name__})")


def _artifact(stem, status):
    if not SERVED.match(str(status)) or not SAFE_PATH.match(stem or ""):
        return OTHER
    if stem.startswith("/trust/"):
        return "/trust/" if stem in ("/trust/", "/trust/index.html") else stem
    return stem


def summarize(records):
    """{month: {"requests", "artifacts", "countries", "status_classes", "first", "last"}}"""
    months = {}
    for r in records:
        stem = r.get("cs-uri-stem") or ""
        if not stem.startswith(PREFIXES):
            continue
        day = str(r.get("date") or "")
        try:
            d = date.fromisoformat(day)
        except ValueError:
            continue
        m = months.setdefault(d.strftime("%Y-%m"), {"requests": 0, "artifacts": Counter(), "countries": Counter(),
                                                   "status_classes": Counter(), "first": day, "last": day})
        status = str(r.get("sc-status") or "")
        m["requests"] += 1
        m["artifacts"][_artifact(stem, status)] += 1
        cc = str(r.get("c-country") or "")
        m["countries"][cc if COUNTRY.match(cc) else "unknown"] += 1
        m["status_classes"][(status[:1] + "xx") if status[:1].isdigit() else "unknown"] += 1
        m["first"], m["last"] = min(m["first"], day), max(m["last"], day)
    return months


def own_records(records, window):
    """The records matching a party's stated date, time range and paths, limited
    to /.well-known/ and /trust/ and to SUPPLIED_FIELDS."""
    paths = set(window["paths"])
    out = []
    for r in records:
        stem = r.get("cs-uri-stem") or ""
        if (stem in paths and stem.startswith(PREFIXES) and str(r.get("date")) == window["date"]
                and window["from"] <= str(r.get("time") or "") <= window["to"]):
            out.append({k: r[k] for k in SUPPLIED_FIELDS if k in r})
    return out


def exercise(records):
    """The own-records request path, run against the simulated requester. Fails
    closed when the lookup does not find exactly the synthetic answer."""
    found = own_records(EXERCISE["synthetic_records"], EXERCISE["window"])
    if len(found) != EXERCISE["expected_matches"]:
        _fail(f"own-records lookup found {len(found)} synthetic record(s), expected {EXERCISE['expected_matches']}")
    real = own_records(records, EXERCISE["window"])
    return {"simulated": True, "requester": REQUESTER, "engagement": _engagement.SHORT,
            "decision": "DEC-160", "asks": EXERCISE["asks"], "window": EXERCISE["window"],
            "syntheticCheck": {"expected": EXERCISE["expected_matches"], "found": len(found), "result": "pass"},
            "matchesInRealRecords": len(real),
            "wouldSupply": list(SUPPLIED_FIELDS),
            "deliveredTo": "nobody: the requester is simulated, and this log entry is the whole response"}


def _month_entry(month, m, now):
    return {"month": month, "coverage_from": m["first"], "coverage_to": m["last"],
            "requests": m["requests"],
            "artifacts": dict(sorted(m["artifacts"].items())),
            "countries": dict(sorted(m["countries"].items())),
            "status_classes": dict(sorted(m["status_classes"].items())),
            "computed_at": now.isoformat()}


def merge(previous, computed, now):
    """Carry earlier months forward; recompute a month only when the records cover
    at least as much of it as the published entry did."""
    by_month = {e["month"]: e for e in (previous or {}).get("months", []) if isinstance(e, dict) and "month" in e}
    for month, m in computed.items():
        old = by_month.get(month)
        if old is None or m["first"] <= old.get("coverage_from", "9999"):
            by_month[month] = _month_entry(month, m, now)
    kept = sorted(by_month.values(), key=lambda e: e["month"])[-MONTHS_KEPT:]
    return kept


def build(previous, records, now):
    records = list(records)
    months = merge(previous, summarize(records), now)
    started = (previous or {}).get("logging_records_since")
    firsts = [e["coverage_from"] for e in months]
    if firsts:
        started = min([started] + firsts) if started else min(firsts)
    return {
        "artifact": "access-summary",
        "rule": "CDS-TRC-ACL",
        "emitted_at": now.isoformat(),
        "scope": "Requests to the certification data under /.well-known/ and to the trust center under /trust/.",
        "logged_fields": "date, time, edge location, country, method, path, status, bytes, cache result. "
                         "No IP address, user agent, referrer, cookie or query string is logged.",
        "raw_record_retention_days": 90,
        "summary_retention_months": MONTHS_KEPT,
        "logging_records_since": started,
        "party_records": "The lookup of a requester's own records, by the times and paths it gives (no "
                         "requester identity is logged), is built and exercised on every build against a "
                         "simulated requester (ownRecordsExercise). There is no commitment and no deadline, "
                         "and no real request is answered (DEC-160, DEC-194).",
        "ownRecordsExercise": exercise(records),
        "months": months,
    }


def render_markdown(doc):
    out = ["# Trust center access summary", "",
           f"_{doc['scope']}_", "",
           f"- **Emitted:** {doc['emitted_at']}",
           f"- **Logged fields:** {doc['logged_fields']}",
           f"- **Raw records kept:** {doc['raw_record_retention_days']} days; "
           f"**summaries kept:** {doc['summary_retention_months']} months",
           f"- **Records since:** {doc['logging_records_since'] or 'none yet'}",
           f"- **Your own records:** {doc['party_records']}",
           f"- **Own-records exercise (simulated):** {doc['ownRecordsExercise']['requester']} asked: "
           f"\"{doc['ownRecordsExercise']['asks']}\" Synthetic check "
           f"{doc['ownRecordsExercise']['syntheticCheck']['result']}; "
           f"{doc['ownRecordsExercise']['matchesInRealRecords']} matching real record(s); delivered to "
           f"{doc['ownRecordsExercise']['deliveredTo']}.", ""]
    if not doc["months"]:
        out += ["No access records yet.", ""]
    for m in reversed(doc["months"]):
        out += [f"## {m['month']}", "",
                f"{m['requests']} requests, {m['coverage_from']} to {m['coverage_to']}. "
                f"By status: {', '.join(f'{k} {v}' for k, v in m['status_classes'].items())}. "
                f"By country: {', '.join(f'{k} {v}' for k, v in m['countries'].items())}.", "",
                "| Artifact | Requests |", "|---|---|"]
        for path, n in sorted(m["artifacts"].items(), key=lambda kv: (-kv[1], kv[0])):
            out.append(f"| `{path}` | {n} |")
        out.append("")
    out += ["---", "_Source of truth: the signed `access-summary.json` (CDS-TRC-ACL)._"]
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--records", required=True, help="directory of synced CloudFront access records")
    ap.add_argument("--previous", default=None, help="the previously published access-summary.json")
    ap.add_argument("--output", default="access-summary.json")
    ap.add_argument("--md-output", default="access-summary.md")
    a = ap.parse_args(argv)
    previous = {}
    if a.previous and Path(a.previous).exists():
        try:
            previous = json.loads(Path(a.previous).read_text())
        except json.JSONDecodeError:
            previous = {}
    if previous and previous.get("artifact") != "access-summary":
        previous = {}
    now = datetime.now(timezone.utc)
    doc = build(previous, read_records(a.records), now)
    prev_months = {e["month"] for e in previous.get("months", [])} if previous else set()
    # Never drop a month younger than the six FedRAMP requires.
    newest = sorted(prev_months | {e["month"] for e in doc["months"]})[-MIN_MONTHS_KEPT:]
    lost = sorted(set(newest) - {e["month"] for e in doc["months"]})
    if lost:
        _fail(f"would drop month(s) {lost} younger than {MIN_MONTHS_KEPT} months")
    doc = _offering.stamp_fedramp_id(doc)  # CDS-CSO-FID
    Path(a.output).write_text(json.dumps(doc, indent=2) + "\n")
    if a.md_output:
        Path(a.md_output).write_text(render_markdown(doc) + "\n")
    print(f"access-summary: {len(doc['months'])} month(s); records since {doc['logging_records_since']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
