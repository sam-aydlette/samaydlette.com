"""The quarterly Collaborative Continuous Monitoring calendar (CCM-OCR-SOR, CCM-QTR-SAR).

infrastructure/schemas/ccm-calendar.json fixes the Ongoing Certification Report
issue dates and how many business days after each issue the Quarterly Review
falls. Everything that publishes a next-report or next-review date (the OCR, the
CPO, the review calendar file) reads it here, so the dates are the same
everywhere and stay put between issues (CCM-OCR-NRD, CCM-QTR-NRD).

Fails closed, stdlib only. The calendar must:
- list issue dates in order, each a business day, 84 to 98 days after the one
  before (a regular 3-month cycle);
- place every issue date away from the beginning, middle and end of its quarter
  (more than 14 days from either end, more than 7 from the middle);
- put each review 3 to 10 business days after its issue;
- cover every date it computes with its holiday list;
- keep at least two issue dates ahead of `today`, so it cannot quietly run out.
"""

import json
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CALENDAR_PATH = REPO / "infrastructure" / "schemas" / "ccm-calendar.json"
SITE = "https://samaydlette.com"
REPO_URL = "https://github.com/sam-aydlette/samaydlette.com"
ICS_URL = f"{SITE}/.well-known/quarterly-review.ics"
ISSUES_INDEX_URL = f"{SITE}/.well-known/ocr-issues.json"
FEEDBACK_FORM = "ocr-feedback.yml"
REGISTRATION_FORM = "quarterly-review-registration.yml"
REGISTRATION_URL = f"{REPO_URL}/issues/new?template={REGISTRATION_FORM}"
MIN_GAP_DAYS, MAX_GAP_DAYS = 84, 98
EDGE_DAYS, MID_DAYS = 14, 7
MIN_FUTURE_ISSUES = 2
_HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def _fail(msg):
    raise SystemExit(f"::error::CCM calendar: {msg} (fail-closed)")


def _date(v, what):
    try:
        return date.fromisoformat(v)
    except (TypeError, ValueError):
        _fail(f"{what} {v!r} is not a YYYY-MM-DD date")


def quarter_bounds(d):
    q0 = (d.month - 1) // 3 * 3 + 1
    start = date(d.year, q0, 1)
    end = date(d.year + (q0 + 3 > 12), (q0 + 2) % 12 + 1, 1) - timedelta(days=1)
    return start, end


class Calendar:
    def __init__(self, doc):
        self.doc = doc
        self.issues = [_date(d, "issue date") for d in doc["ocr_issue_dates"]]
        self.holidays = {_date(d, "holiday") for d in doc["holidays"]["dates"]}
        self.covers_through = _date(doc["holidays"]["covers_through"], "holidays.covers_through")
        self.offset = doc["review_business_days_after_issue"]
        self.start_utc = doc["review_start_utc"]
        self.duration = doc["review_duration_minutes"]

    def is_business_day(self, d):
        if d > self.covers_through:
            _fail(f"{d} is past the holiday list (covers through {self.covers_through})")
        return d.weekday() < 5 and d not in self.holidays

    def add_business_days(self, d, n):
        while n > 0:
            d += timedelta(days=1)
            if self.is_business_day(d):
                n -= 1
        return d

    def review_date(self, issue):
        return self.add_business_days(issue, self.offset)

    def issued(self, today):
        """Issue dates on or before `today`."""
        return [d for d in self.issues if d <= today]

    def next_issue(self, today):
        """The next issue date strictly after `today`: stable from one issue to the next."""
        return next(d for d in self.issues if d > today)

    def next_review(self, today):
        """The next review on or after `today` (the one following the latest
        issue, until it has happened)."""
        return next(r for r in (self.review_date(d) for d in self.issues) if r >= today)

    def period(self, issue):
        """(from, to) an issue covers: the previous issue to this one. The first
        issue covers the 3 months before it."""
        i = self.issues.index(issue)
        start = self.issues[i - 1] if i else issue - timedelta(days=91)
        return start, issue

    def current_period(self, today):
        """(from, to) of the report as it stands today: since the latest issue."""
        done = self.issued(today)
        return (done[-1] if done else self.issues[0] - timedelta(days=91)), today

    def review_start(self, issue):
        h, m = (int(x) for x in self.start_utc.split(":"))
        r = self.review_date(issue)
        return datetime(r.year, r.month, r.day, h, m, tzinfo=timezone.utc)


def validate(doc, today):
    if not isinstance(doc, dict) or doc.get("schema") != "ccm-calendar/1":
        _fail("not a ccm-calendar/1 document")
    for k in ("decided_by", "decided_on", "review_by", "rationale"):
        if not isinstance(doc.get(k), str) or not doc[k].strip():
            _fail(f"{k} is missing")
    if _date(doc["review_by"], "review_by") < today:
        _fail(f"review_by {doc['review_by']} has passed: the calendar needs a fresh decision")
    off = doc.get("review_business_days_after_issue")
    if not isinstance(off, int) or isinstance(off, bool) or not 3 <= off <= 10:
        _fail("review_business_days_after_issue must be 3 to 10 (CCM-QTR-SAR)")
    if not _HHMM.match(str(doc.get("review_start_utc", ""))):
        _fail("review_start_utc must be HH:MM")
    dur = doc.get("review_duration_minutes")
    if not isinstance(dur, int) or isinstance(dur, bool) or not 15 <= dur <= 240:
        _fail("review_duration_minutes must be 15 to 240")
    if not isinstance(doc.get("ocr_issue_dates"), list) or len(doc["ocr_issue_dates"]) < 2:
        _fail("ocr_issue_dates must list at least two dates")
    if not isinstance(doc.get("holidays"), dict) or not isinstance(doc["holidays"].get("dates"), list):
        _fail("holidays.dates must be a list")
    cal = Calendar(doc)
    prev = None
    for d in cal.issues:
        if prev is not None and not MIN_GAP_DAYS <= (d - prev).days <= MAX_GAP_DAYS:
            _fail(f"{d} is {(d - prev).days} days after {prev}: not a regular 3-month cycle")
        if not cal.is_business_day(d):
            _fail(f"issue date {d} is not a business day")
        qs, qe = quarter_bounds(d)
        mid = qs + (qe - qs) / 2
        if (d - qs).days < EDGE_DAYS or (qe - d).days < EDGE_DAYS or abs((d - mid).days) <= MID_DAYS:
            _fail(f"issue date {d} is at the beginning, middle or end of its quarter (CCM-OCR-SOR)")
        cal.review_date(d)  # inside the holiday coverage
        prev = d
    if sum(1 for d in cal.issues if d > today) < MIN_FUTURE_ISSUES:
        _fail(f"fewer than {MIN_FUTURE_ISSUES} issue dates after {today}: extend the calendar")
    return cal


def load(path=CALENDAR_PATH, today=None):
    today = today or datetime.now(timezone.utc).date()
    try:
        doc = json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        _fail(f"cannot read {path}: {exc}")
    return validate(doc, today)


def feedback_url(issue):
    """The asynchronous feedback channel for one OCR issue (CCM-OCR-FBM): a
    GitHub issue form, prefilled with the issue's date."""
    return f"{REPO_URL}/issues/new?template={FEEDBACK_FORM}&ocr={issue.isoformat()}"


# --- the review calendar file (CCM-QTR-REG) -----------------------------------------

def _ics_escape(s):
    return s.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\n", "\\n")


def _fold(line):
    """RFC 5545 3.1: lines longer than 75 octets continue with a leading space."""
    raw = line.encode("utf-8")
    if len(raw) <= 75:
        return line
    out, cur = [], b""
    for ch in line:
        b = ch.encode("utf-8")
        if len(cur) + len(b) > (75 if not out else 74):
            out.append(cur.decode("utf-8"))
            cur = b""
        cur += b
    out.append(cur.decode("utf-8"))
    return "\r\n ".join(out)


def ics(cal, today):
    """One VEVENT per Quarterly Review from the latest issued report on.
    Deterministic: DTSTAMP is the calendar's decision date."""
    stamp = cal.doc["decided_on"].replace("-", "") + "T000000Z"
    done = cal.issued(today)
    first = done[-1] if done else cal.issues[0]
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//samaydlette.com//CCM quarterly review//EN",
             "CALSCALE:GREGORIAN", "METHOD:PUBLISH", "X-WR-CALNAME:samaydlette.com Quarterly Review"]
    for issue in cal.issues:
        if issue < first:
            continue
        start = cal.review_start(issue)
        end = start + timedelta(minutes=cal.duration)
        desc = (f"Quarterly Review (CCM-QTR-MTG) of the Ongoing Certification Report issued {issue}. "
                f"Report: {SITE}/.well-known/ocr-issue-{issue}.json (published on the issue date). "
                f"Register: {REGISTRATION_URL} . The operator hosts the review by video call and sends "
                f"the join link to registered parties. Questions about the report: {feedback_url(issue)}")
        lines += ["BEGIN:VEVENT", f"UID:qtr-review-{issue}@samaydlette.com", f"DTSTAMP:{stamp}",
                  f"DTSTART:{start.strftime('%Y%m%dT%H%M%SZ')}", f"DTEND:{end.strftime('%Y%m%dT%H%M%SZ')}",
                  f"SUMMARY:{_ics_escape(f'samaydlette.com Quarterly Review (OCR {issue})')}",
                  f"DESCRIPTION:{_ics_escape(desc)}", f"URL:{REGISTRATION_URL}",
                  "LOCATION:Video call (link sent on registration)", "END:VEVENT"]
    lines.append("END:VCALENDAR")
    return "\r\n".join(_fold(x) for x in lines) + "\r\n"


def dates_summary(cal, today):
    """What the CPO and the OCR publish about the cycle."""
    nxt = cal.next_issue(today)
    return {"nextOngoingCertificationReportDate": nxt.isoformat(),
            "nextQuarterlyReviewDate": cal.next_review(today).isoformat(),
            "quarterlyReviewCalendar": ICS_URL,
            "quarterlyReviewRegistration": REGISTRATION_URL,
            "ongoingCertificationReportIssues": ISSUES_INDEX_URL,
            "issueDates": [d.isoformat() for d in cal.issues],
            "reviewBusinessDaysAfterIssue": cal.offset}


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Validate the CCM calendar and write the review .ics.")
    ap.add_argument("--calendar", default=str(CALENDAR_PATH))
    ap.add_argument("--ics", default=None, help="write the Quarterly Review calendar file here")
    a = ap.parse_args(argv)
    today = datetime.now(timezone.utc).date()
    cal = load(a.calendar, today)
    if a.ics:
        Path(a.ics).write_text(ics(cal, today), newline="")
    s = dates_summary(cal, today)
    print(f"CCM calendar: next report {s['nextOngoingCertificationReportDate']}, "
          f"next review {s['nextQuarterlyReviewDate']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
