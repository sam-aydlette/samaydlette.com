#!/usr/bin/env python3
"""Fail when a Quarterly Review date has passed with no review published (CCM-QTR-MTG).

The deploy and the evidence nightly run this against the published
/.well-known/quarterly-reviews.json. A review is held by package-maintenance.yml
on its date; from the day after, a review date with no review in the index
fails the run, so a missed review cannot pass quietly.

  check-quarterly-review.py --index quarterly-reviews.json   # the published index
  check-quarterly-review.py --no-index                       # nothing published yet (HTTP 404)
"""

import argparse
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ccm  # noqa: E402
import _quarterly_review as qr  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--calendar", default=str(_ccm.CALENDAR_PATH))
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--index", help="the published quarterly-reviews.json")
    src.add_argument("--no-index", action="store_true", help="the index is not published yet")
    ap.add_argument("--today", default=None, help="YYYY-MM-DD (default: today, UTC)")
    a = ap.parse_args(argv)
    today = date.fromisoformat(a.today) if a.today else datetime.now(timezone.utc).date()
    cal = _ccm.load(a.calendar, today)
    index = {} if a.no_index else json.loads(Path(a.index).read_text())
    late = qr.missing(cal, index, today)
    for issue, review in late:
        print(f"::error::Quarterly Review of the report issued {issue} was due {review} and is not published")
    if late:
        return 1
    print(f"Quarterly Reviews: {len(qr.held(index))} held, none overdue; next {cal.next_review(today)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
