#!/usr/bin/env python3
"""AFC-CSO-NOC: every change to the FedRAMP Security Inbox contact is notified
to FedRAMP (simulated) within one business day.

The inbox is simulated for this proof of concept (no mail is received), so what
is published is a contact statement rather than a mailbox. It lives in one
place, data/cds/offering.json (fedramp_security_inbox.contact), with an
append-only history. Each entry after the first is a change, dated by "since".
The first entry establishes the contact; it must say in "basis" why there was
no earlier contact to change from.

Two halves:

  check()         on every pull request and push (the unit-test job): the
                  contact is one non-empty line of printable text; the newest
                  history entry is the current contact; every later entry
                  changes the contact and is dated, not in the future; and
                  with --base (the same file at the merge base) the history is
                  append-only and a changed contact has a new entry.
  file_notices()  on every deploy (scripts/submit-package.py): files a notice
                  with the simulated FedRAMP for every change not yet filed,
                  keeps earlier notices unchanged, and reports any notice
                  dated more than one business day after its change, which
                  fails the deploy. NOTHING IS SENT: a notice is an entry in
                  the published package-submission-log.json, and the
                  simulated FedRAMP's receipt is a Python function's return
                  value. No real FedRAMP is notified (DEC-194).

Stdlib only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _bizdays  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
DEFAULT = REPO / "data" / "cds" / "offering.json"
CONTACT = re.compile(r"^[\x20-\x7e]{1,300}$")
DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
NOTICE_BUSINESS_DAYS = 1  # "immediately": filed no later than the next business day
NOTICE_KEYS = {"changedOn", "contact", "filedOn", "receipt"}


def _inbox(doc):
    return doc.get("fedramp_security_inbox") if isinstance(doc, dict) else None


def _date(value):
    if not isinstance(value, str) or not DAY.match(value):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def check(head: dict, base: dict | None = None, today: date | None = None) -> list[str]:
    """Violations of AFC-CSO-NOC in head (and in the step from base to head)."""
    today = today or date.today()
    out: list[str] = []
    fsi = _inbox(head)
    if not isinstance(fsi, dict):
        return ["fedramp_security_inbox is missing from data/cds/offering.json (AFC-CSO-INB)"]
    contact = fsi.get("contact")
    if not isinstance(contact, str) or not CONTACT.match(contact) or not contact.strip():
        out.append("fedramp_security_inbox.contact must be one non-empty line of printable text (at most 300 characters)")
    history = fsi.get("history")
    if not isinstance(history, list) or not history or not all(isinstance(h, dict) for h in history):
        return out + ["fedramp_security_inbox.history must list every contact the inbox has had"]
    if history[-1].get("contact") != contact:
        out.append("the contact changed without a history entry recording the change")
    first = history[0]
    if not (isinstance(first.get("basis"), str) and first["basis"].strip()):
        out.append("the first history entry has no basis saying why there was no earlier contact to change from")
    for i, h in enumerate(history):
        since = _date(h.get("since"))
        if since is None or since > today:
            out.append(f"history[{i}].since must be the date of the change, not in the future")
        if i == 0:
            continue
        if h.get("contact") == history[i - 1].get("contact"):
            out.append(f"history[{i}] repeats the previous contact")
        if "fedramp_notified" in h:
            out.append(f"history[{i}] hand-records a notice; the deploy files it (AFC-CSO-NOC), so remove "
                       "fedramp_notified")
    base_fsi = _inbox(base) if base is not None else None
    if isinstance(base_fsi, dict):
        base_hist = base_fsi.get("history") or []
        if history[:len(base_hist)] != base_hist:
            out.append("fedramp_security_inbox.history was rewritten; it is append-only")
        if base_fsi.get("contact") != contact and len(history) <= len(base_hist):
            out.append("the contact changed but no history entry was added for the change")
    return out


def file_notices(head: dict, previous, today: date, intake) -> tuple[list[dict], list[str]]:
    """(notices, problems). Carries over every earlier notice unchanged, files a
    notice through `intake` (the simulated FedRAMP) for each contact change in
    the history that has none, dated today, and reports every notice filed more
    than NOTICE_BUSINESS_DAYS business days after its change."""
    problems = check(head, today=today)
    if problems:
        return [], problems
    notices = list(previous or [])
    for i, n in enumerate(notices):
        if not isinstance(n, dict) or set(n) != NOTICE_KEYS or _date(n.get("changedOn")) is None \
                or _date(n.get("filedOn")) is None:
            return [], [f"the previously published change notice {i} is malformed; notices are carried over "
                        "unchanged"]
    filed = {(n["changedOn"], n["contact"]) for n in notices}
    for h in _inbox(head)["history"][1:]:
        if (h["since"], h["contact"]) in filed:
            continue
        notice = {"changedOn": h["since"], "contact": h["contact"], "filedOn": today.isoformat()}
        notice["receipt"] = intake(dict(notice))
        notices.append(notice)
        filed.add((h["since"], h["contact"]))
    for n in notices:
        deadline = _bizdays.add_business_days(_date(n["changedOn"]), NOTICE_BUSINESS_DAYS)
        if _date(n["filedOn"]) > deadline:
            problems.append(f"the notice of the change on {n['changedOn']} was filed {n['filedOn']}, after "
                            f"{deadline.isoformat()} (one business day)")
    return notices, problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--offering", type=Path, default=DEFAULT)
    ap.add_argument("--base", type=Path, help="offering.json at the merge base (optional)")
    a = ap.parse_args(argv)
    head = json.loads(a.offering.read_text())
    base = None
    if a.base and a.base.is_file() and a.base.stat().st_size:
        base = json.loads(a.base.read_text())
    problems = check(head, base)
    for p in problems:
        print(f"::error::FedRAMP Security Inbox (AFC-CSO-NOC): {p}")
    if not problems:
        fsi = _inbox(head)
        print(f"FedRAMP Security Inbox: {len(fsi['history'])} history entr{'y' if len(fsi['history']) == 1 else 'ies'}; "
              f"{'compared with the merge base' if base else 'no merge base given'}; ok")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
