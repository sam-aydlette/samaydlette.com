#!/usr/bin/env python3
"""Hold each Quarterly Review on its date, with simulated attendees (CCM-QTR-MTG, CCM-QTR-RTR).

Run by package-maintenance.yml after it issues the quarterly report. For every
calendar issue whose review date has come and that the published index
(quarterly-reviews.json) does not list yet, it reads the frozen report
(ocr-issue-<date>.json, whose sha256 must equal the one the verified OCR issue
index records), builds the review with scripts/_quarterly_review.py and writes:

  quarterly-review-<date>.json and .md   the review, never rewritten
  quarterly-reviews.json                 the index of every review held, plus the next date

A malformed previous index fails (each earlier review is carried forward
unchanged, by date and sha256), as does a due review whose report cannot be
found or does not match its recorded sha256. The list of
new files to publish goes to --new-files (one per line).

  hold-quarterly-review.py --ocr-index out/ocr-issues.json --issues-dir DIR [--issues-dir DIR] \
      --previous-index work/quarterly-reviews.json --out out --new-files out/reviews.txt
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ccm  # noqa: E402
import _engagement  # noqa: E402
import _offering  # noqa: E402
import _quarterly_review as qr  # noqa: E402


_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")


def _fail(msg):
    raise SystemExit(f"::error::Quarterly Review: {msg} (fail-closed)")


def _find(name, dirs):
    for d in dirs:
        p = Path(d) / name
        if p.is_file():
            return p
    return None


def run(cal, ocr_index, issues_dirs, previous, out, now, fedramp_id):
    today = now.date()
    issued = {i["issueDate"]: i for i in (ocr_index or {}).get("issues", [])}
    reviews = list((previous or {}).get("reviews", []))
    for r in reviews:
        if (not isinstance(r, dict) or not _DATE.match(str(r.get("ocrIssue")))
                or not _SHA.match(str(r.get("reviewSha256")))):
            _fail("the previous review index holds a malformed entry")
    have = qr.held(previous)
    new = []
    for d in cal.issues:
        iso = d.isoformat()
        if cal.review_date(d) > today or iso in have:
            continue
        entry = issued.get(iso)
        if entry is None:
            _fail(f"the review of {iso} is due but no report was issued on {iso}")
        p = _find(f"ocr-issue-{iso}.json", issues_dirs)
        if p is None:
            _fail(f"the review of {iso} is due but ocr-issue-{iso}.json is not available")
        sha = hashlib.sha256(p.read_bytes()).hexdigest()
        if sha != entry.get("reportSha256"):
            _fail(f"ocr-issue-{iso}.json does not match the sha256 the issue index records")
        doc = qr.build(cal, d, json.loads(p.read_text()), sha, now, fedramp_id)
        name = f"quarterly-review-{iso}"
        (out / f"{name}.json").write_text(json.dumps(doc, indent=2) + "\n")
        (out / f"{name}.md").write_text(qr.render_markdown(doc) + "\n")
        reviews.append({"ocrIssue": iso, "reviewDate": doc["reviewDate"], "heldAt": doc["heldAt"],
                        "late": doc["late"], "review": f"{qr.BASE}{name}.json", "reviewMarkdown": f"{qr.BASE}{name}.md",
                        "reviewSha256": hashlib.sha256((out / f"{name}.json").read_bytes()).hexdigest()})
        new += [f"{name}.json", f"{name}.md"]
    reviews.sort(key=lambda r: r["ocrIssue"])
    index = {"schema": qr.INDEX_SCHEMA, "fedRampId": fedramp_id, "generated_at": now.isoformat(),
             "simulated": True, "engagement": _engagement.STATEMENT,
             "nextQuarterlyReviewDate": cal.next_review(today).isoformat(),
             "calendar": _ccm.ICS_URL,
             "access": "Each review is at /.well-known/quarterly-review-<issue date>.json (and .md), signed (.bundle) "
                       "and never rewritten; this index records each one's sha256.",
             "reviews": reviews}
    late = qr.missing(cal, index, today)
    if late:
        _fail(f"review(s) past their date and not held: {', '.join(str(r) for _, r in late)}")
    (out / "quarterly-reviews.json").write_text(json.dumps(index, indent=2) + "\n")
    return index, new


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--calendar", default=str(_ccm.CALENDAR_PATH))
    ap.add_argument("--offering", default=str(_offering.OFFERING_PATH))
    ap.add_argument("--ocr-index", required=True, help="ocr-issues.json as published after this run's issue step")
    ap.add_argument("--issues-dir", action="append", required=True, help="where the frozen reports are")
    ap.add_argument("--previous-index", default=None)
    ap.add_argument("--out", required=True)
    ap.add_argument("--new-files", default=None)
    a = ap.parse_args(argv)
    now = datetime.now(timezone.utc)
    cal = _ccm.load(a.calendar, now.date())
    prev_path = Path(a.previous_index) if a.previous_index else None
    previous = json.loads(prev_path.read_text()) if prev_path and prev_path.is_file() else {}
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    index, new = run(cal, json.loads(Path(a.ocr_index).read_text()), a.issues_dir, previous, out, now,
                     _offering.fedramp_id(a.offering))
    if a.new_files:
        Path(a.new_files).write_text("".join(f + "\n" for f in new))
    print(f"quarterly-reviews: {len(index['reviews'])} held; {len(new) // 2} new this run; next "
          f"{index['nextQuarterlyReviewDate']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
