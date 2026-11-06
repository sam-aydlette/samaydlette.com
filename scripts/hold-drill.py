#!/usr/bin/env python3
"""Hold a drill when it is due, from the evidence nightly (DEC-195; simulated casts, DEC-194).

  board-meeting     The Board of Sam, quarterly (KSI-PIY-RES)
  cfo-review        The CFO's budget review, quarterly (KSI-PIY-RIS)
  tabletop          Choose-Your-Own-Disaster, monthly (KSI-INR-RIR, KSI-RPL-ARP, KSI-INR-AAR)
  disclosure-drill  Ima Finder's report through the intake, monthly (KSI-PIY-RVD)
  phishing-drill    The Prince of Compliance's lure, monthly (KSI-CED-RAT)

The logic is in scripts/_drills.py and scripts/_phishing.py; the calendar,
index and publication rules are scripts/_scheduled_review.py's. Each due drill
is built from the repository's data at this commit, its planted bad case fed
through the same check, and, if every check passes, written as
vdr-drill-<name>-<due date>.json and .view.md (never rewritten). A failing
drill is not written: the index is still written (carried forward), the run
fails, and the next run holds it again once the cause is fixed;
scripts/check-scheduled-review.py fails the nightly from the day after its due
date until then.

  hold-drill.py --review KEY [--previous-index INDEX.json] --out DIR --new-files FILE
  hold-drill.py --list      # the drill keys, one per line
"""

import argparse
import importlib.util
import json
import sys
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
import _decisions  # noqa: E402
import _drills  # noqa: E402
import _ksi_methods  # noqa: E402
import _offering  # noqa: E402
import _phishing  # noqa: E402
import _scheduled_review as sr  # noqa: E402

RULES = {
    "board-meeting": (["KSI-PIY-RES"], ["pm-2", "pm-9"]),
    "cfo-review": (["KSI-PIY-RIS"], ["pm-3", "sa-2"]),
    "tabletop": (["KSI-INR-RIR", "KSI-RPL-ARP", "KSI-INR-AAR"], ["ir-3", "cp-4", "ir-4"]),
    "disclosure-drill": (["KSI-PIY-RVD"], ["ra-5", "si-5"]),
    "phishing-drill": (["KSI-CED-RAT"], ["at-2", "at-3"]),
}
RECORD_KEY = {"board-meeting": "meeting", "cfo-review": "budget", "tabletop": "tabletop",
              "disclosure-drill": "disclosure", "phishing-drill": "phishing"}


def _fail(msg):
    raise SystemExit(f"::error::drill: {msg} (fail-closed)")


def _costs(repo):
    spec = importlib.util.spec_from_file_location("hold_security_review_costs", HERE / "hold-security-review.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m.validate_costs(json.loads((repo / "data" / "recurring-costs.json").read_text()), repo)


def _text(repo, rel):
    return (repo / rel).read_text(encoding="utf-8")


def build(key, due, now, fedramp_id, previous, repo=REPO, endorsements=None):
    """(document, index extra) for the drill due on `due`."""
    rv = sr.review(key)
    extra = {}
    if key == "board-meeting":
        reg = _decisions.load(repo / "data" / "decisions.json")
        have = sr.held(rv, previous)
        since = max((d for d in have if d < due.isoformat()), default=None)
        checks, record, every = _drills.board_meeting(due, _decisions.in_force(reg), reg["decisions"],
                                                      endorsements or [], date.fromisoformat(since) if since else None)
        extra = {"endorsements": every}
    elif key == "cfo-review":
        checks, record = _drills.cfo_review(_ksi_methods.load(), _costs(repo))
    elif key == "tabletop":
        ids = set(_decisions.by_any_id(_decisions.load(repo / "data" / "decisions.json")))
        checks, record = _drills.tabletop(due, _text(repo, _drills.IR_DOC), _text(repo, _drills.PLAN_DOC), ids, repo)
    elif key == "disclosure-drill":
        checks, record = _drills.disclosure_drill(now, _text(repo, "website/.well-known/security.txt"),
                                                  _text(repo, _drills.IR_DOC))
    elif key == "phishing-drill":
        checks, record = _phishing.drill(sr.due_dates(rv, due).index(due) + 1)
    else:
        _fail(f"{key} is not a drill")
    rules, controls = RULES[key]
    doc = sr.base_doc(rv, due, now, fedramp_id, f"{rv.title} due {due} (automated; simulated participants)")
    doc.update({"rules": rules, "controls": controls,
                "method": f"scripts/hold-drill.py --review {key}, run by evidence-nightly.yml on its due date "
                          "(logic: scripts/_drills.py, scripts/_phishing.py). Real checks over the repository's "
                          "data; the participants are simulated, and a planted bad case is fed through the same "
                          "check on every run and must be caught.",
                "checks": checks, "result": sr.result_of(checks), RECORD_KEY[key]: record})
    return sr.finish(doc, f"the {rv.title}"), extra


def run(key, previous, out, now, fedramp_id, repo=REPO):
    rv = sr.review(key)
    due = sr.due_now(rv, previous, now.date())
    endorsements = list((previous or {}).get("endorsements") or [])
    entries, files, failed = [], [], []
    for d in due:
        doc, extra = build(key, d, now, fedramp_id, previous, repo, endorsements)
        if doc["result"] != "pass":
            for c in doc["checks"]:
                if c["result"] != "pass":
                    print(f"::error::{rv.title} due {d}: {c['title']}: {c['detail']}")
            failed.append(d)
            continue
        endorsements = extra.get("endorsements", endorsements)
        entry, written = sr.write(out, rv, d, doc)
        entries.append(entry)
        files += written
    extra = {"endorsements": endorsements} if key == "board-meeting" else None
    index = sr.index_doc(rv, previous, entries, now, fedramp_id, extra)
    sr.write_json(out, rv.index, index)
    return index, entries, files, failed


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--list", action="store_true", help="print the drill keys and exit")
    ap.add_argument("--review", choices=sr.DRILLS)
    ap.add_argument("--previous-index", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--new-files", default=None)
    ap.add_argument("--now", default=None, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if a.list:
        print("\n".join(f"{k} {sr.REVIEWS[k].index[:-5]}" for k in sr.DRILLS))
        return 0
    if not a.review or not a.out:
        ap.error("--review and --out are required")
    now = sr.now_utc(a.now)
    prev = Path(a.previous_index) if a.previous_index else None
    previous = json.loads(prev.read_text()) if prev and prev.is_file() else {}
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    index, entries, files, failed = run(a.review, previous, out, now, _offering.fedramp_id())
    if a.new_files:
        Path(a.new_files).write_text("".join(f + "\n" for f in files))
    for e in entries:
        print(f"{a.review} due {e['dueDate']}: {e['result']}")
    print(f"{a.review}: {len(index['reviews'])} held; next due {index['nextDueDate']}")
    if failed:
        _fail(f"the {a.review} due {', '.join(map(str, failed))} did not pass; it is held again on the next run "
              "once fixed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
