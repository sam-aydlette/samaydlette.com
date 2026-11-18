"""The Ongoing Certification Report calendar: data/ocr-calendar.json.

One place computes the dates the OCR, the CPO and the quarterly issue publish:

- the due dates: the 15th of the middle month of each quarter (CCM-OCR-SOR);
- the next report's target date (CCM-OCR-NRD): the earliest due date that has
  no issue yet, which is in the past when a report is overdue;
- the next Quarterly Review's target date (CCM-QTR-NRD, CCM-QTR-SAR):
  review_business_days business days after a report's release;
- the current reporting period: from the last issue (or the first period
  start) to today.

`issued` is the list of reports already issued, each {"id", "due", "issued_on",
"period_from", "period_to"} (ISO dates), from the published index of issues;
empty until the first issue.

Stdlib only, fail-closed.
"""

import json
from datetime import date, timedelta
from pathlib import Path

PATH = Path(__file__).resolve().parent.parent / "data" / "ocr-calendar.json"


def _fail(msg):
    raise SystemExit(f"::error::OCR calendar: {msg} (fail-closed)")


def load(path=PATH):
    try:
        cal = json.loads(Path(path).read_text())
    except (OSError, ValueError) as e:
        _fail(f"{path} unreadable ({e})")
    if cal.get("schema") != "ocr-calendar/1":
        _fail(f"{path} is not an ocr-calendar/1 document")
    months = (cal.get("issue_dates") or {}).get("months")
    day = (cal.get("issue_dates") or {}).get("day")
    if not (isinstance(months, list) and len(months) == 4 and all(isinstance(m, int) and 1 <= m <= 12 for m in months)
            and len({(m - 1) // 3 for m in months}) == 4):
        _fail("issue_dates.months must name one month in each quarter")
    if not (isinstance(day, int) and 1 <= day <= 28):
        _fail("issue_dates.day must be 1 to 28")
    if not (isinstance(cal.get("review_business_days"), int) and 3 <= cal["review_business_days"] <= 10):
        _fail("review_business_days must be 3 to 10 (CCM-QTR-SAR)")
    try:
        date.fromisoformat(cal["first_period_start"])
    except (KeyError, TypeError, ValueError):
        _fail("first_period_start must be an ISO date")
    if not (cal.get("decided_by") and cal.get("decided_on")):
        _fail("the calendar needs decided_by and decided_on")
    return cal


def due_dates(cal, through):
    """Every due date from the first period start through `through`, in order."""
    start = date.fromisoformat(cal["first_period_start"])
    day = cal["issue_dates"]["day"]
    out = []
    for year in range(start.year, through.year + 2):
        for m in sorted(cal["issue_dates"]["months"]):
            d = date(year, m, day)
            if start < d <= through:
                out.append(d)
    return out


def issue_id(due):
    return f"{due.year}-Q{(due.month - 1) // 3 + 1}"


def _issued_dues(issued):
    return {date.fromisoformat(i["due"]) for i in issued or []}


def next_report(cal, issued, today):
    """(target date, overdue): the earliest due date with no issue yet."""
    done = _issued_dues(issued)
    for d in due_dates(cal, today + timedelta(days=200)):
        if d not in done:
            return d, d < today
    _fail("no due date in the next 200 days")


def add_business_days(d, n):
    while n:
        d += timedelta(days=1)
        if d.weekday() < 5:
            n -= 1
    return d


def next_review(cal, issued, today):
    """The next Quarterly Review: after the latest issued report's release, if that
    review is still ahead; otherwise after the next report's target date."""
    n = cal["review_business_days"]
    if issued:
        last = max(issued, key=lambda i: i["issued_on"])
        r = add_business_days(date.fromisoformat(last["issued_on"]), n)
        if r >= today:
            return r
    target, _ = next_report(cal, issued, today)
    return add_business_days(max(target, today), n)


def period_start(cal, issued, today):
    """The current reporting period starts the day after the last report closed
    before today, or on the first period start. On the day a report is issued,
    that report's own period is the current one."""
    closed = [i["period_to"] for i in issued or [] if date.fromisoformat(i["period_to"]) < today]
    if closed:
        return date.fromisoformat(max(closed)) + timedelta(days=1)
    return date.fromisoformat(cal["first_period_start"])


def load_issued(path):
    """The issued reports from an index of issues (scripts/issue-ocr.py), or []
    when no path is given or no index exists yet."""
    if not path or not Path(path).exists():
        return []
    try:
        doc = json.loads(Path(path).read_text())
    except ValueError as e:
        _fail(f"{path} is not JSON ({e})")
    if not isinstance(doc, dict) or doc.get("schema") != "ocr-issues/1" or not isinstance(doc.get("issues"), list):
        _fail(f"{path} is not an ocr-issues/1 index")
    issues = doc["issues"]
    for i in issues:
        try:
            for k in ("due", "issued_on", "period_from", "period_to"):
                date.fromisoformat(i[k])
        except (KeyError, TypeError, ValueError):
            _fail(f"{path}: issue {i.get('id') if isinstance(i, dict) else i!r} lacks valid dates")
    return issues

