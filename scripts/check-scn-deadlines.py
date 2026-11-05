#!/usr/bin/env python3
"""Scheduled SCN deadline check (SCN-ADP-NTF, SCN-TRF-NAF/NAV/UPD, SCN-CSO-EMG).

Reads the published evaluation log and notification index and the register in
this checkout, and fails (exit 1) on anything late and still outstanding:

- an adaptive, transformative or emergency change whose named record is not in
  the register by its deadline (adaptive: 10 business days after merge, the
  earliest it can have finished; emergency: 5; transformative: at merge);
- a notice a register record owes that is not yet published after its
  deadline (a record merged but never deployed is not a notification);
- a transformative change whose service documentation is not updated within
  30 business days of finishing.

A notice published late is not an open item: the index records it (onTime
false) for good. Exit 0 nothing overdue, 1 overdue, 2 cannot read an input.

    check-scn-deadlines.py                         # the published copies
    check-scn-deadlines.py --index-file i.json --log-file l.json --today 2026-11-05
"""

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _scn  # noqa: E402


def _read(path, url):
    if path:
        return json.loads(Path(path).read_text())
    try:
        with urllib.request.urlopen(url, timeout=30) as r:  # noqa: S310 (fixed https URL)
            return json.loads(r.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {}
        raise


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--register", default=str(_scn.REGISTER))
    ap.add_argument("--index-file")
    ap.add_argument("--log-file")
    ap.add_argument("--today", help="ISO date (tests)")
    a = ap.parse_args(argv)
    today = date.fromisoformat(a.today) if a.today else datetime.now(timezone.utc).date()
    try:
        index = _read(a.index_file, _scn.BASE + _scn.INDEX_NAME + ".json")
        log = _read(a.log_file, _scn.BASE + _scn.LOG_NAME + ".json")
        header, rows = _scn.read_register(a.register)
    except (OSError, ValueError, urllib.error.URLError) as exc:
        print(f"::error::SCN deadline check cannot read its inputs: {exc}")
        return 2
    errors = _scn.validate_register(header, rows)
    if errors:
        for e in errors:
            print(f"::error::scn-register: {e}")
        return 2
    late = _scn.overdue(rows, index, log.get("entries", []), today)
    for item in late:
        print(f"::error::SCN overdue: {item}")
    if late:
        return 1
    print(f"SCN deadlines: nothing overdue on {today} ({len(rows)} records, "
          f"{len(log.get('entries', []))} evaluations)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
