#!/usr/bin/env python3
"""AFC-CSO-NOC: a change to the FedRAMP Security Inbox contact must record that
FedRAMP was notified.

The inbox is simulated for this proof of concept (no mail is received), so what
is published is a contact statement rather than a mailbox. It lives in one
place, data/cds/offering.json (fedramp_security_inbox.contact), with an
append-only history. Each entry after the first is a change, and a change must
carry the notification marker:

    "fedramp_notified": {"on": "YYYY-MM-DD", "channel": "<how FedRAMP was told>"}

FedRAMP's channel for this is the "[CSP] Notification of Changes" form on
help.fedramp.gov (the rule's notification target). The first entry establishes
the contact and needs no marker only when there was no earlier contact to
change from; it must say why in "basis".

Checks (each failure names itself; exit 1 on any):
  - the contact is one non-empty line of printable text
  - the newest history entry is the current contact
  - every later entry changes the contact and carries a dated, non-future
    fedramp_notified marker with a channel
  - with --base (the same file at the merge base): the history is append-only,
    and if the contact changed, the new entries are the ones that say so

Stdlib only; runs in the unit-test job on every pull request and push.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT = REPO / "data" / "cds" / "offering.json"
CONTACT = re.compile(r"^[\x20-\x7e]{1,300}$")
DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")


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
        out.append("the contact changed without a history entry recording the change and notifying FedRAMP")
    first = history[0]
    if first.get("fedramp_notified") is None and not (isinstance(first.get("basis"), str) and first["basis"].strip()):
        out.append("the first history entry has no fedramp_notified and no basis saying why none was needed")
    for i, h in enumerate(history):
        since = _date(h.get("since"))
        if since is None or since > today:
            out.append(f"history[{i}].since must be a date, not in the future")
        if i == 0:
            continue
        if h.get("contact") == history[i - 1].get("contact"):
            out.append(f"history[{i}] repeats the previous contact")
        marker = h.get("fedramp_notified")
        if not isinstance(marker, dict):
            out.append(f"history[{i}] changes the contact without a fedramp_notified marker (AFC-CSO-NOC)")
            continue
        on = _date(marker.get("on"))
        if on is None or on > today:
            out.append(f"history[{i}].fedramp_notified.on must be the date FedRAMP was notified, not in the future")
        channel = marker.get("channel")
        if not isinstance(channel, str) or not channel.strip():
            out.append(f"history[{i}].fedramp_notified.channel must say how FedRAMP was notified")
    base_fsi = _inbox(base) if base is not None else None
    if isinstance(base_fsi, dict):
        base_hist = base_fsi.get("history") or []
        if history[:len(base_hist)] != base_hist:
            out.append("fedramp_security_inbox.history was rewritten; it is append-only")
        if base_fsi.get("contact") != contact and len(history) <= len(base_hist):
            out.append("the contact changed but no history entry was added for the change")
    return out


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
