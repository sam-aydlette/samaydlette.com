"""Scheduled reviews, run by machines on their dates, with simulated people where a person is needed.

The operator does not hold recurring reviews by hand (DEC-195 names the only
three human acts left). Every review a policy, plan or KSI used to ask a person
for is built here as an automated mechanism that would work with real people,
and it runs on its calendar against a small, plainly simulated cast:

  calendar    REVIEWS: each review's cadence (monthly or annual) and first due
              date, fixed in code and changed only by a reviewed pull request.
              `due_dates`, `missing` and `next_due` compute from it alone.
  held        the published, signed index of every review held, by due date;
              `held()` refuses a malformed one (fail-closed).
  build       each review's own script builds its document (the checks it ran,
              each with its result); `finish()` adds the engagement statement
              (DEC-194), refuses wording that offers engagement with a real
              party, and runs the sensitivity screen before anything is written.
  write       `write()` writes <review>-<due date>.json and its complete
              human-readable .view.md (scripts/build-human-views.py), never
              rewritten, and returns its index entry with its sha256.
  overdue     scripts/check-scheduled-review.py fails the deploy and the evidence
              nightly from the day after a due date with no review published.

The reviews:
  security-review     annual, package-maintenance.yml (scripts/hold-security-review.py),
                      published as security-review-<date>.json and security-reviews.json,
                      which also carries the rules-of-behavior acknowledgements.
  recovery-exercise   monthly, evidence-nightly.yml (scripts/hold-recovery-exercise.py),
                      published as vdr-recovery-exercise-<date>.json and
                      vdr-recovery-exercises.json; each November's carries the tabletop.
The audit-log review runs on every nightly instead (scripts/audit-log-review.py,
vdr-audit-log-review.json); its window is its freshness entry.
"""

import hashlib
import importlib.util
import json
import sys
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _engagement  # noqa: E402
import _sensitivity  # noqa: E402
import _training  # noqa: E402

BASE = "https://samaydlette.com/.well-known/"
SIMULATED_MARK = "(simulated)"
SCHEMA = "scheduled-review/1"
INDEX_SCHEMA = "scheduled-reviews/1"
# DEC-195: the only recurring human acts. Everything here runs without them.
HUMAN_ACTS_DECISION = "DEC-195"

# The cast. Everyone is simulated, and says so in their name (DEC-194).
CAST = {
    "reviewer": "Rev Yewer (simulated)",             # signs off the annual security review
    "personnel": _training.TRAINEE,                  # Pat Placeholder: acknowledges the rules of behavior
    "intruder": "Mallory McHypothetical (simulated)",  # the audit-log review's planted event, caught every run
    "incident-commander": "Bea Kupp (simulated)",    # runs the recovery tabletop
    "scenario-injector": "Dee Saster (simulated)",   # reads out the tabletop's scenarios
    # The intern handed log reads "just to look around": the OPA gate's planted
    # bad grant (log_read_grant_unexpected; tests/fixtures/plans/log-read-grant-curious-carl.json).
    "log-snooper": "Curious Carl (simulated)",
}


@dataclass(frozen=True)
class Review:
    key: str
    title: str
    cadence: str          # "monthly" (on the 1st) or "annual" (on first_due's month and day)
    first_due: date
    prefix: str           # published file name before "<due date>.json"
    index: str            # the published index's file name
    publisher: str        # the _signers.py identity key of the workflow that holds it


REVIEWS = {
    "security-review": Review("security-review", "Annual Security Review", "annual", date(2026, 11, 6),
                              "security-review-", "security-reviews.json", "maintenance"),
    "recovery-exercise": Review("recovery-exercise", "Recovery exercise", "monthly", date(2026, 11, 1),
                                "vdr-recovery-exercise-", "vdr-recovery-exercises.json", "nightly"),
}


def _fail(msg):
    raise SystemExit(f"::error::scheduled review: {msg} (fail-closed)")


def review(key):
    if key not in REVIEWS:
        _fail(f"unknown review {key!r}")
    return REVIEWS[key]


def _add_months(d, n):
    m = d.month - 1 + n
    return date(d.year + m // 12, m % 12 + 1, 1)


def due_dates(rv, until):
    """Every due date from the first one up to and including `until`."""
    out, d, n = [], rv.first_due, 0
    while d <= until:
        out.append(d)
        n += 1
        d = _add_months(rv.first_due, n) if rv.cadence == "monthly" else rv.first_due.replace(
            year=rv.first_due.year + n)
    return out


def next_due(rv, today):
    """The first due date strictly after `today`."""
    return due_dates(rv, today + timedelta(days=400))[len(due_dates(rv, today))]


def held(rv, index):
    """{due date (ISO): entry} from a published index (or {}). Fails on one that
    is not this review's index."""
    if not index:
        return {}
    if (not isinstance(index, dict) or index.get("schema") != INDEX_SCHEMA or index.get("review") != rv.key
            or not isinstance(index.get("reviews"), list)):
        _fail(f"the published {rv.index} is not a {INDEX_SCHEMA} index of {rv.key}")
    out = {}
    for r in index["reviews"]:
        if not isinstance(r, dict) or not isinstance(r.get("dueDate"), str) or len(str(r.get("sha256"))) != 64:
            _fail(f"the published {rv.index} holds a malformed entry")
        out[r["dueDate"]] = r
    return out


def missing(rv, index, today):
    """Due dates strictly before `today` with no review published."""
    have = held(rv, index)
    return [d for d in due_dates(rv, today - timedelta(days=1)) if d.isoformat() not in have]


def due_now(rv, index, today):
    """Due dates on or before `today` that the index does not hold yet."""
    have = held(rv, index)
    return [d for d in due_dates(rv, today) if d.isoformat() not in have]


def sha_json(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def result_of(checks):
    """'pass' when every check passed; each check is {id, title, result, detail}."""
    for c in checks:
        if c.get("result") not in ("pass", "fail") or not c.get("id") or not c.get("title"):
            _fail(f"a malformed check: {c!r}"[:200])
    return "pass" if all(c["result"] == "pass" for c in checks) else "fail"


def finish(doc, what):
    """The document as published: the engagement statement, the screen against
    wording that invites a real party (DEC-194), and the sensitivity screen."""
    doc = {**doc, "engagement": _engagement.STATEMENT, "humanActs": HUMAN_ACTS_DECISION}
    _engagement.require_none(doc, what)
    doc["sensitivityScreen"] = _sensitivity.require_clean(doc, what)
    return doc


def _views():
    spec = importlib.util.spec_from_file_location("human_views_for_reviews",
                                                  Path(__file__).resolve().parent / "build-human-views.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def write_json(out, name, doc):
    """Write `name` and its complete .view.md; return the files written."""
    p = Path(out) / name
    p.write_text(json.dumps(doc, indent=2) + "\n")
    view = _views().build(p)
    return [p.name, view.name]


def write(out, rv, due, doc):
    """Write one held review and its view; returns (index entry, [its JSON file name]).
    The workflow publishes the view beside each JSON it is given."""
    name = f"{rv.prefix}{due.isoformat()}.json"
    files = write_json(out, name, doc)[:1]
    entry = {"dueDate": due.isoformat(), "heldAt": doc["heldAt"], "late": doc["late"], "result": doc["result"],
             "review": f"{BASE}{name}", "view": f"{BASE}{name[:-5]}.view.md",
             "sha256": hashlib.sha256((Path(out) / name).read_bytes()).hexdigest()}
    return entry, files


def index_doc(rv, previous, entries, now, fedramp_id, extra=None):
    """The index: every earlier entry carried forward unchanged, plus this run's."""
    have = held(rv, previous)
    rows = list(have.values()) + [e for e in entries if e["dueDate"] not in have]
    rows.sort(key=lambda r: r["dueDate"])
    doc = {"schema": INDEX_SCHEMA, "fedRampId": fedramp_id, "review": rv.key, "title": rv.title,
           "cadence": rv.cadence, "generated_at": now.isoformat(), "simulated": True,
           "nextDueDate": next_due(rv, now.date()).isoformat(),
           "access": f"Each review is at /.well-known/{rv.prefix}<due date>.json (and .view.md), signed (.bundle) "
                     "and never rewritten; this index records each one's sha256.",
           "overdueCheck": "scripts/check-scheduled-review.py fails the deploy and the evidence nightly from the "
                           "day after a due date with no review here.",
           "reviews": rows, **(extra or {})}
    return finish(doc, f"the {rv.title} index")


def base_doc(rv, due, now, fedramp_id, title):
    return {"schema": SCHEMA, "fedRampId": fedramp_id, "review": rv.key, "title": title, "cadence": rv.cadence,
            "dueDate": due.isoformat(), "heldAt": now.isoformat(), "late": now.date() > due,
            "generated_at": now.isoformat(), "simulated": True}


def now_utc(value=None):
    """`value` (an ISO timestamp, for tests) or the current UTC time."""
    if value:
        t = datetime.fromisoformat(value)
        return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc)


# --- the SDR's automated methods (FRC-CSX-VVK) ------------------------------------------
# How a scheduled mechanism's published record is judged current and passing.
# Which KSIs each mechanism verifies is in infrastructure/schemas/ksi-methods.json
# (scripts/_ksi_methods.py), which calls method_status for the published records
# of the audit-log review and the recovery exercise after checking their
# signatures.

AUDIT_LOG_MAX_AGE_HOURS = 26


def _ts(v):
    try:
        t = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def method_status(key, doc, now):
    """(ok, reason) for one scheduled mechanism's published record."""
    if not isinstance(doc, dict):
        return False, "its record is not published yet"
    if key == "audit-log-review":
        at = _ts(doc.get("generated_at"))
        if doc.get("schema") != "audit-log-review/1" or at is None:
            return False, "its record is not an audit-log-review/1 document"
        if not 0 <= (now - at).total_seconds() <= AUDIT_LOG_MAX_AGE_HOURS * 3600:
            return False, f"its record is older than {AUDIT_LOG_MAX_AGE_HOURS} hours"
        if not (doc.get("exercise") or {}).get("caught"):
            return False, "the planted simulated intruder was not caught"
        if doc.get("result") != "pass":
            return False, "the last review did not pass"
        return True, None
    rv = review(key)
    try:
        late = missing(rv, doc, now.date())
        have = held(rv, doc)
    except SystemExit as exc:
        return False, str(exc)[:160]
    if late:
        return False, f"the review due {late[0]} is not published"
    if not have:
        return False, "no review has been held yet"
    last = have[max(have)]
    if last.get("result") != "pass":
        return False, f"the review due {last['dueDate']} did not pass"
    return True, None
