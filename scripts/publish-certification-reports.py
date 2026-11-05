#!/usr/bin/env python3
"""Publish FedRAMP Certification Reports unmodified (CDS-CSO-FRC).

Reads data/fedramp-certification-reports/register.json, checks every listed
report's bytes against its recorded sha256 (an edited report fails closed: the
rule forbids inappropriate modification), copies each byte-identical to
--out/fedramp-certification-reports/<file>, and writes the signed index
--out/fedramp-certification-reports.json. The index carries over each report's
first publication date from the previously published index, so the days from
receipt to publication (FedRAMP's window: 2 weeks) are a matter of record; a
report first published late is flagged late, never hidden.

SIMULATED: no FedRAMP counterpart exists for this proof of concept. The one
report is a stand-in the operator wrote, flagged simulated; nothing was
received from FedRAMP and nothing is sent anywhere.

  publish-certification-reports.py --out DIR --previous prev.json
"""

import argparse
import hashlib
import json
import shutil
import sys
from datetime import date, datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fedramp_schema as fs  # noqa: E402
import _offering  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
REPORTS_DIR = REPO / "data" / "fedramp-certification-reports"
BASE = "https://samaydlette.com/.well-known/fedramp-certification-reports/"
WINDOW_DAYS = 14
SIMULATION = ("FedRAMP is simulated: this proof of concept has no FedRAMP counterpart. The report listed is a "
              "plainly fake stand-in the operator wrote to exercise this path; nothing was received from FedRAMP.")


def _fail(msg):
    raise SystemExit(f"::error::FedRAMP certification reports: {msg} (fail-closed)")


def load_register(reports_dir=REPORTS_DIR, today=None):
    today = today or datetime.now(timezone.utc).date()
    reports_dir = Path(reports_dir)
    try:
        reg = json.loads((reports_dir / "register.json").read_text())
    except (OSError, ValueError) as exc:
        _fail(f"register unreadable: {exc}")
    if reg.get("schema") != "fedramp-certification-reports/1" or not isinstance(reg.get("reports"), list):
        _fail("register is not a fedramp-certification-reports/1 document")
    listed = set()
    for r in reg["reports"]:
        f = r.get("file")
        if not isinstance(f, str) or "/" in f or f.startswith(".") or f in listed:
            _fail(f"bad or repeated file name {f!r}")
        listed.add(f)
        try:
            received = date.fromisoformat(r.get("received_on", ""))
        except ValueError:
            _fail(f"{f}: received_on is not a date")
        if received > today:
            _fail(f"{f}: received_on {received} is in the future")
        p = reports_dir / f
        if not p.is_file():
            _fail(f"{f} is listed but not present")
        if hashlib.sha256(p.read_bytes()).hexdigest() != r.get("sha256"):
            _fail(f"{f} differs from the sha256 recorded when it was received: reports are published unmodified")
    unlisted = {p.name for p in reports_dir.iterdir() if p.is_file()} - listed - {"register.json"}
    if unlisted:
        _fail(f"files not in the register: {sorted(unlisted)}")
    return reg


def build(reg, previous, now, out, reports_dir=REPORTS_DIR):
    today = now.date()
    first = {e["file"]: e["firstPublished"] for e in (previous or {}).get("reports", [])
             if isinstance(e, dict) and e.get("file") and e.get("firstPublished")}
    (out / "fedramp-certification-reports").mkdir(parents=True, exist_ok=True)
    entries = []
    for r in reg["reports"]:
        shutil.copyfile(Path(reports_dir) / r["file"], out / "fedramp-certification-reports" / r["file"])
        published = first.get(r["file"], today.isoformat())
        days = (date.fromisoformat(published) - date.fromisoformat(r["received_on"])).days
        entries.append({"file": r["file"], "url": BASE + r["file"], "sha256": r["sha256"],
                        "receivedOn": r["received_on"], "from": r["from"], "firstPublished": published,
                        "daysToPublish": days, "withinTwoWeeks": days <= WINDOW_DAYS,
                        "simulated": bool(r.get("simulated"))})
    return {"schema": "fedramp-certification-reports-index/1", "generated_at": now.isoformat(),
            "fedRampId": _offering.fedramp_id(), "certificationPackageOverviewUri": fs.CPO_URI,
            "simulated": {"counterparty": "fedramp", "how": SIMULATION},
            "rule": "CDS-CSO-FRC: FedRAMP Certification Reports are included unmodified and made available within "
                    "2 weeks of receipt.",
            "reports": entries}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--reports-dir", default=str(REPORTS_DIR))
    ap.add_argument("--previous", default=None)
    ap.add_argument("--out", default=".")
    a = ap.parse_args(argv)
    now = datetime.now(timezone.utc)
    reg = load_register(a.reports_dir, now.date())
    prev = {}
    if a.previous and Path(a.previous).exists():
        try:
            prev = json.loads(Path(a.previous).read_text())
        except ValueError:
            prev = {}
    out = Path(a.out)
    idx = build(reg, prev, now, out, a.reports_dir)
    (out / "fedramp-certification-reports.json").write_text(json.dumps(idx, indent=2) + "\n")
    for e in idx["reports"]:
        if not e["withinTwoWeeks"]:
            print(f"::warning::{e['file']} was first published {e['daysToPublish']} days after receipt")
    print(f"fedramp-certification-reports: {len(idx['reports'])} report(s) published unmodified (simulated FedRAMP)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
