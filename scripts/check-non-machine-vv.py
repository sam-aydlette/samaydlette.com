#!/usr/bin/env python3
"""VDR-TFR-NMV: check that every non-machine information resource was verified
and validated within the last 3 months, under an in-force decision record.

    check-non-machine-vv.py [--register data/non-machine-resources.json]
                            [--decisions data/decisions.json] [--out vdr-non-machine-vv.json]
                            [--enforce] [--today YYYY-MM-DD]

--out writes the status the nightly and the deploy publish. --enforce exits 1
when anything is out of date (the deploy); without it the status is written
with status "lapsed" and the published freshness window (92 days on
verifiedAt) turns the watchdog red instead (the nightly).
"""

import argparse
import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _decisions  # noqa: E402
import _nonmachine  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--register", default=None)
    ap.add_argument("--decisions", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--enforce", action="store_true")
    ap.add_argument("--today", default=None)
    a = ap.parse_args(argv)
    doc = _nonmachine.load(a.register)
    reg = _decisions.load(a.decisions)
    today = date.fromisoformat(a.today) if a.today else date.today()
    st = _nonmachine.status(doc, reg, today)
    if a.out:
        Path(a.out).write_text(json.dumps(st, indent=2) + "\n", encoding="utf-8")
    print(f"Non-machine V&V (VDR-TFR-NMV): {len(st['resources'])} resources, oldest verification "
          f"{st['verifiedAt'][:10]}, next due by {st['nextDueBy']}: {st['status']}")
    for p in st["problems"]:
        print(f"::{'error' if a.enforce else 'warning'}::non-machine V&V: {p}", file=sys.stderr)
    return 1 if (a.enforce and st["problems"]) else 0


if __name__ == "__main__":
    sys.exit(main())
