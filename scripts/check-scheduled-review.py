#!/usr/bin/env python3
"""Fail when a scheduled review's due date has passed with no review published (DEC-195).

The evidence nightly and the package maintainer (called by every deploy) run
this against the published, signature-verified index. From the day after a
due date with no review in the index, the run fails, so a missed review cannot
pass quietly. With --rules-of-behavior it also fails when the current rules of
behavior have no acknowledgement in the security-review index (PL-4).

  check-scheduled-review.py --review security-review --index security-reviews.json \
      [--rules-of-behavior docs/rules-of-behavior.md]
  check-scheduled-review.py --review recovery-exercise --no-index   # nothing published yet (HTTP 404)
"""

import argparse
import hashlib
import importlib.util
import json
import sys
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import _scheduled_review as sr  # noqa: E402


def _security_review():
    spec = importlib.util.spec_from_file_location("hold_security_review_check", HERE / "hold-security-review.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def problems(key, index, today, rob_path=None):
    rv = sr.review(key)
    out = [f"{rv.title} due {d} is not published" for d in sr.missing(rv, index, today)]
    if rob_path is not None:
        sha = hashlib.sha256(Path(rob_path).read_bytes()).hexdigest()
        if not _security_review().rob_acknowledged(index, sha):
            out.append(f"the current rules of behavior ({sha[:12]}) have no acknowledgement in {rv.index}")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--review", required=True, choices=sorted(sr.REVIEWS))
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--index", help="the published index")
    src.add_argument("--no-index", action="store_true", help="the index is not published yet")
    ap.add_argument("--rules-of-behavior", default=None, help="also require this document's acknowledgement")
    ap.add_argument("--today", default=None, help="YYYY-MM-DD (default: today, UTC)")
    a = ap.parse_args(argv)
    today = date.fromisoformat(a.today) if a.today else sr.now_utc().date()
    index = {} if a.no_index else json.loads(Path(a.index).read_text())
    found = problems(a.review, index, today, a.rules_of_behavior)
    for p in found:
        print(f"::error::{p}")
    if found:
        return 1
    rv = sr.review(a.review)
    print(f"{rv.title}: {len(sr.held(rv, index))} held, none overdue; next due {sr.next_due(rv, today)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
