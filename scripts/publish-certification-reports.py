#!/usr/bin/env python3
"""Publish FedRAMP Certification Reports unmodified, within two weeks (CDS-CSO-FRC).

FedRAMP is SIMULATED for this proof of concept. The simulated FedRAMP issues a
stand-in certification report only in response to a simulated package
submission (scripts/submit-package.py): for the first submission, after any
adaptive or transformative Significant Change Notification, and once a year.
Each report is logged verbatim, with the date received and its sha256, in
that submission's entry of the append-only package-submission-log.json. An
ordinary deploy issues none.

This reads this deploy's submission log and, for every logged report:

  - checks the report says, in its title and first line, that it is a
    simulated report NOT ISSUED BY FEDRAMP and that the system is not
    certified (a report that does not is never published);
  - checks its bytes against the sha256 logged when it was received (an
    edited report fails the deploy: the rule forbids inappropriate
    modification);
  - writes it byte-identical to --out/fedramp-certification-reports/<file>;

and writes the index --out/fedramp-certification-reports.json (signed by the
deploy). The index carries each report's first publication date over from the
previously published index, so the days from receipt to publication are a
matter of record, and a report first published more than 2 weeks after
receipt FAILS THE DEPLOY. Nothing is received from or sent to the real FedRAMP.

  publish-certification-reports.py --submission-log package-submission-log.json \
      --previous prev-index.json --out DIR
"""

import argparse
import hashlib
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fedramp_schema as fs  # noqa: E402
import _offering  # noqa: E402

BASE = "https://samaydlette.com/.well-known/fedramp-certification-reports/"
WINDOW_DAYS = 14
INDEX_SCHEMA = "fedramp-certification-reports-index/1"
NOT_ISSUED = "NOT ISSUED BY FEDRAMP"
NOT_CERTIFIED = "NOT FedRAMP certified"
SIMULATION = ("FedRAMP is simulated: this proof of concept has no FedRAMP counterpart. Every report listed was "
              "written by a Python function standing in for FedRAMP, in response to a simulated package "
              "submission, and says so in its title. The system is not certified. Nothing was received from or "
              "sent to FedRAMP.")


def _fail(msg):
    raise SystemExit(f"::error::FedRAMP certification reports: {msg} (fail-closed)")


def report_bytes(report):
    """The report exactly as received (scripts/submit-package.py logs its sha256)."""
    return (json.dumps(report, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def logged_reports(log):
    """Every certification report in the submission log, checked."""
    if not isinstance(log, dict) or log.get("schema") != "package-submission-log/1":
        _fail("the submission log is not a package-submission-log/1 document")
    out, files = [], set()
    for e in log.get("entries") or []:
        r = e.get("certificationReport") if isinstance(e, dict) else None
        if r is None:
            continue
        f = r.get("file")
        if not isinstance(f, str) or "/" in f or f.startswith(".") or not f.endswith(".json") or f in files:
            _fail(f"bad or repeated report file name {f!r}")
        files.add(f)
        try:
            date.fromisoformat(r.get("receivedOn", ""))
        except (TypeError, ValueError):
            _fail(f"{f}: receivedOn is not a date")
        report = r.get("report")
        if not isinstance(report, dict):
            _fail(f"{f}: the logged report is missing")
        raw = report_bytes(report)
        first = raw.decode("utf-8").splitlines()[1]  # the first line of content, after "{"
        title = str(report.get("title", ""))
        if not first.lstrip().startswith('"title"') or NOT_ISSUED not in title or NOT_CERTIFIED not in title:
            _fail(f"{f}: the report's title and first line must say it is a simulated report {NOT_ISSUED} and "
                  "that the system is not certified; it is never published otherwise")
        if hashlib.sha256(raw).hexdigest() != r.get("sha256"):
            _fail(f"{f} differs from the sha256 logged when it was received: reports are published unmodified")
        out.append((r, raw))
    return out


def build(log, previous, now, out):
    today = now.date()
    first = {e["file"]: e["firstPublished"] for e in (previous or {}).get("reports", [])
             if isinstance(e, dict) and e.get("file") and e.get("firstPublished")}
    (out / "fedramp-certification-reports").mkdir(parents=True, exist_ok=True)
    entries = []
    for r, raw in logged_reports(log):
        (out / "fedramp-certification-reports" / r["file"]).write_bytes(raw)
        published = first.get(r["file"], today.isoformat())
        days = (date.fromisoformat(published) - date.fromisoformat(r["receivedOn"])).days
        entries.append({"file": r["file"], "url": BASE + r["file"], "sha256": r["sha256"],
                        "receivedOn": r["receivedOn"], "from": r.get("from"), "trigger": r.get("trigger"),
                        "firstPublished": published, "daysToPublish": days, "withinTwoWeeks": days <= WINDOW_DAYS,
                        "simulated": True, "notIssuedByFedRAMP": True})
    return {"schema": INDEX_SCHEMA, "generated_at": now.isoformat(),
            "fedRampId": _offering.fedramp_id(), "certificationPackageOverviewUri": fs.CPO_URI,
            "certificationStatus": "not certified (proof of concept)",
            "simulated": {"counterparty": "fedramp", "how": SIMULATION},
            "rule": "CDS-CSO-FRC: FedRAMP Certification Reports are included unmodified and made available within "
                    "2 weeks of receipt.",
            "reports": entries}


def late(index):
    return [e for e in index["reports"] if not e["withinTwoWeeks"]]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--submission-log", required=True, help="this deploy's package-submission-log.json")
    ap.add_argument("--previous", default=None, help="the previously published index (absent: never published)")
    ap.add_argument("--out", default=".")
    a = ap.parse_args(argv)
    now = datetime.now(timezone.utc)
    try:
        log = json.loads(Path(a.submission_log).read_text())
    except (OSError, ValueError) as exc:
        _fail(f"cannot read the submission log ({type(exc).__name__})")
    prev = {}
    if a.previous and Path(a.previous).exists():
        try:
            prev = json.loads(Path(a.previous).read_text())
        except ValueError:
            _fail("the previously published index is not JSON; refusing to restart the publication record")
        if prev.get("schema") != INDEX_SCHEMA:
            _fail(f"the previously published index is not a {INDEX_SCHEMA} document")
    out = Path(a.out)
    idx = build(log, prev, now, out)
    overdue = late(idx)
    if overdue:
        _fail("; ".join(f"{e['file']} was first published {e['daysToPublish']} days after receipt, past the "
                        f"{WINDOW_DAYS}-day window" for e in overdue))
    (out / "fedramp-certification-reports.json").write_text(json.dumps(idx, indent=2) + "\n")
    print(f"fedramp-certification-reports: {len(idx['reports'])} report(s) published unmodified (simulated FedRAMP;"
          " not certified)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
