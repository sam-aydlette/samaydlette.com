"""The Quarterly Review, automated and held with simulated attendees (CCM-QTR-*, CCM-OCR-AFS/FBM).

The operator does not host meetings with FedRAMP or agencies (DEC-194), and no
person runs this process. What a real review needs is built here as code that
would work with real people, and it is exercised every quarter against a cast
of plainly simulated ones:

  roster        who attends, checked against the attendee policy in code
                (CCM-QTR-RTP): simulated agencies, the simulated FedRAMP and the
                simulated assessor; any other party only with its relevance
                recorded; nobody who is not marked simulated.
  agenda        the standing agenda (CCM-QTR-ACT), filled from the issued
                Ongoing Certification Report it reviews.
  feedback      the asynchronous feedback intake (CCM-OCR-FBM): submissions
                about an issued report, each validated and screened, answered
                by rule. Simulated parties submit through it; nobody else is
                invited to. The anonymized summary of the questions and answers
                (CCM-OCR-AFS) goes into the next report (scripts/build-ocr.py
                calls qa_summary(), the same function the review publishes).
  transcript    a scripted transcript that walks the agenda (CCM-QTR-RTR). The
                full transcript is "supplied" to the attendees as a log entry
                (its sha256); the published one has every agency line removed
                (CCM-QTR-SRR), and everything passes the sensitivity screen
                (CCM-QTR-NID).

The feedback depends only on the issue date, so the review and the next report
always carry the same summary. scripts/hold-quarterly-review.py writes the
review on its date (package-maintenance.yml); scripts/check-quarterly-review.py
fails the deploy and the nightly when a review date has passed with no review
published.
"""

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _engagement  # noqa: E402
import _sensitivity  # noqa: E402

SCHEMA = "quarterly-review/1"
INDEX_SCHEMA = "quarterly-reviews/1"
BASE = "https://samaydlette.com/.well-known/"
SIMULATED_MARK = "(simulated)"
ROLES = ("agency", "fedramp", "assessor")      # who is invited by default (CCM-QTR-RTP)
HOST = {"seat": "Host", "org": "The operator, played by package-maintenance.yml (simulated)", "role": "host"}
ROSTER = [
    {"seat": "Authorizing Official", "org": "Department of Hypothetical Affairs (simulated)", "role": "agency"},
    {"seat": "Information System Security Officer", "org": "Bureau of Made-Up Statistics (simulated)",
     "role": "agency"},
    {"seat": "Package reviewer", "org": "FedRAMP (simulated)", "role": "fedramp"},
    {"seat": "Lead assessor", "org": "Totally Real Assessment Services, LLC (simulated)", "role": "assessor"},
]
ATTENDEE_POLICY = ("Simulated agencies, the simulated FedRAMP and the simulated assessor attend by default. Any other "
                   "party attends only with its specific relevance recorded on the roster (CCM-QTR-RTP). Everyone "
                   "on the roster is simulated: the operator invites no real party (DEC-194).")
AGENCY_LINE_REMOVED = "[Comment from a simulated agency attendee removed before publication (CCM-QTR-SRR).]"
INTAKE = ("Asynchronous feedback intake (CCM-OCR-FBM): a submission names the report's issue date and a question; "
          "scripts/_quarterly_review.py validates and screens it, answers it by rule and adds it, anonymized, to the "
          "next report. Each quarter simulated parties submit through it. No real party is invited to (DEC-194).")
# The feedback the simulated parties submit, rotated by quarter: (from role, question, answer).
FEEDBACK_POOL = [
    ("agency", "Is this system FedRAMP authorized?",
     "No. It is not FedRAMP certified or authorized, it holds no federal data, and nobody has asked it to be. It is "
     "a proof of concept that shows the evidence a 20x Class C system would produce."),
    ("agency", "How do we get access to the certification package?",
     "You already have it: everything is public, and the trust manifest lists every file with its signature. No "
     "form, no request, no fax."),
    ("fedramp", "Why is every attendee at this review simulated?",
     "Because the operator does not engage FedRAMP or any agency about this system (DEC-194). The review runs anyway, "
     "on its date, so the mechanism is shown working."),
    ("assessor", "What happens if a Quarterly Review is missed?",
     "The deploy and the evidence nightly both fail from the day after a review date with no review published."),
    ("agency", "Will the accepted findings ever be revisited?",
     "Each one is a decision record with a review date; a record past its date lapses and stops covering anything."),
    ("assessor", "Can the assessor attend in person?",
     "The assessor is a GitHub Actions workflow wearing a lanyard. It attends in YAML."),
    ("agency", "Is there coffee?",
     "Simulated coffee only. It is excellent, and its software bill of materials has no known vulnerabilities."),
    ("fedramp", "How do we know the evidence shown here is current?",
     "Every published artifact has a governed freshness window and a signature; the watchdog pages the operator when "
     "one lapses."),
]
PER_QUARTER = 3


def _fail(msg):
    raise SystemExit(f"::error::Quarterly Review: {msg} (fail-closed)")


# --- the attendee policy (CCM-QTR-RTP) ------------------------------------------------

def check_roster(roster):
    """The roster, if it meets the attendee policy; fails closed otherwise."""
    if not roster:
        _fail("the roster is empty")
    for a in roster:
        org, role = str(a.get("org") or ""), a.get("role")
        if not org.endswith(SIMULATED_MARK):
            _fail(f"attendee {org!r} is not marked {SIMULATED_MARK}: no real party is invited (DEC-194)")
        if role not in ROLES:
            if role != "other" or not str(a.get("relevance") or "").strip():
                _fail(f"attendee {org!r} ({role}) is a third party with no specific relevance recorded")
    return roster


# --- feedback intake (CCM-OCR-FBM) and the anonymized summary (CCM-OCR-AFS) -----------

def simulated_submissions(issue, quarter_index):
    """What the simulated parties submit about the report issued on `issue`."""
    n = len(FEEDBACK_POOL)
    picks = [FEEDBACK_POOL[(quarter_index * PER_QUARTER + i) % n] for i in range(PER_QUARTER)]
    by_role = {r["role"]: r["org"] for r in ROSTER}
    return [{"ocr": issue, "from": by_role[role], "question": q, "_answer": a} for role, q, a in picks]


def intake(submissions, issue):
    """Validate, screen and answer each submission; refuses one about another
    report, one from a party not marked simulated, or one that would publish an
    identifier."""
    out = []
    for s in submissions:
        if s.get("ocr") != issue:
            _fail(f"a submission about {s.get('ocr')!r} arrived in the intake for {issue}")
        if not str(s.get("from") or "").endswith(SIMULATED_MARK):
            _fail("a submission from a party not marked simulated: no real feedback is solicited (DEC-194)")
        q = str(s.get("question") or "").strip()
        if not q:
            _fail("a submission with no question")
        out.append({"from": s["from"], "question": q, "answer": s["_answer"]})
    _sensitivity.require_clean(out, f"the feedback on the report issued {issue}")
    return out


def qa_summary(issue, quarter_index):
    """The anonymized, desensitized summary of the questions and answers on one
    issued report: no party, name or agency. The review publishes it and the
    next report carries it (CCM-OCR-AFS)."""
    items = intake(simulated_submissions(issue, quarter_index), issue)
    return {"ocr": issue, "received": len(items), "summarizedBy": "scripts/_quarterly_review.py (automated)",
            "simulated": True,
            "items": [{"question": i["question"], "answer": i["answer"]} for i in items]}


# --- agenda (CCM-QTR-ACT) and transcript (CCM-QTR-RTR) ---------------------------------

def agenda(ocr):
    """The standing agenda, filled from the issued report."""
    changes = len(ocr.get("certificationDataChanges") or [])
    planned = len((ocr.get("plannedCertificationDataChanges") or {}).get("changes") or [])
    incidents = len((ocr.get("reportableIncidents") or {}).get("incidents") or [])
    period = ocr.get("reportPeriod") or {}
    return [
        f"The report for {period.get('from')} to {period.get('to')}: {changes} change(s) to certification data, "
        f"{len(ocr.get('transformativeChanges') or [])} transformative, {incidents} reportable incident(s).",
        "Standing item (CCM-QTR-ACT): Key Security Indicator results and their trend, from the Security Decision "
        "Record's metric summaries.",
        f"Standing item (CCM-QTR-ACT): accepted vulnerabilities and their trend. {ocr.get('acceptedVulnerabilities')}",
        f"Standing item (CCM-QTR-ACT): the plan for the next quarter: {planned} planned change(s) to certification "
        "data.",
        "Questions submitted through the feedback intake, and questions from the attendees.",
    ]


def transcript(issue, review_date, items, qa, next_review):
    """The full scripted transcript: [{speaker, org, role, line}]."""
    host = HOST
    att = {a["role"]: a for a in ROSTER}
    agency2 = ROSTER[1]

    def say(who, line):
        return {"speaker": who["seat"], "org": who["org"], "role": who["role"], "line": line}

    lines = [
        say(host, f"Welcome to the Quarterly Review of the Ongoing Certification Report issued {issue}. Everyone "
                  "here is simulated, including, for the purposes of this meeting, me."),
        say(att["fedramp"], "Noted for the record: nothing was submitted to us. We are also simulated, so the "
                            "record is also simulated."),
        say(att["agency"], "Happy to be here. Purely hypothetically."),
    ]
    for n, item in enumerate(items, 1):
        lines.append(say(host, f"Agenda item {n}. {item}"))
    lines.append(say(agency2, "Could we get the trend as a pie chart?"))
    lines.append(say(host, "No."))
    lines.append(say(att["assessor"], "Totally Real Assessment Services has re-checked every rule and every KSI and "
                                      "would like it minuted that our lanyard is real."))
    lines.append(say(host, "So minuted."))
    for i in qa["items"]:
        lines.append(say(host, f"A question from the feedback intake: {i['question']}"))
        lines.append(say(host, i["answer"]))
    lines.append(say(host, f"The next review is on {next_review}. Meeting adjourned. Nobody needs to stay for the "
                           "hot wash; there is no hot wash."))
    return lines


AGENCY_NAME_REMOVED = "A simulated agency (name removed, CCM-QTR-SRR) (simulated)"


def public_transcript(lines):
    """The transcript as published (CCM-QTR-SRR): every agency comment, question
    and name removed."""
    return [dict(x, speaker="Agency attendee", org=AGENCY_NAME_REMOVED, line=AGENCY_LINE_REMOVED)
            if x["role"] == "agency" else x for x in lines]


def public_roster(roster):
    """The roster as published: agency names removed (CCM-QTR-SRR)."""
    return [dict(a, org=AGENCY_NAME_REMOVED) if a["role"] == "agency" else a for a in roster]


def _sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# --- the review ---------------------------------------------------------------------

def build(cal, issue, ocr, ocr_sha256, now, fedramp_id):
    """The review of the report issued on `issue` (a date in the calendar)."""
    if issue not in cal.issues:
        _fail(f"{issue} is not a calendar issue date")
    review = cal.review_date(issue)
    if review > now.date():
        _fail(f"the review of {issue} is on {review}: not before its date")
    roster = check_roster([dict(a) for a in ROSTER])
    qi = cal.issues.index(issue)
    qa = qa_summary(issue.isoformat(), qi)
    items = agenda(ocr)
    nxt = cal.issues[qi + 1] if qi + 1 < len(cal.issues) else None
    next_review = cal.review_date(nxt).isoformat() if nxt else "not yet scheduled"
    full = transcript(issue.isoformat(), review, items, qa, next_review)
    doc = {
        "schema": SCHEMA,
        "fedRampId": fedramp_id,
        "simulated": True,
        "engagement": _engagement.STATEMENT,
        "title": f"Quarterly Review of the Ongoing Certification Report issued {issue} (simulated)",
        "rules": ["CCM-QTR-MTG", "CCM-QTR-ACT", "CCM-QTR-RTP", "CCM-QTR-RTR", "CCM-QTR-SRR", "CCM-QTR-NID",
                  "CCM-OCR-FBM", "CCM-OCR-AFS"],
        "reviewDate": review.isoformat(),
        "start": cal.review_start(issue).isoformat(),
        "durationMinutes": cal.duration,
        "heldAt": now.isoformat(),
        "late": now.date() > review,
        "generated_at": now.isoformat(),
        "ocrIssue": {"issueDate": issue.isoformat(), "report": f"{BASE}ocr-issue-{issue}.json",
                     "reportSha256": ocr_sha256},
        "host": HOST,
        "attendeePolicy": ATTENDEE_POLICY,
        "roster": public_roster(roster),
        "agenda": items,
        "feedback": {"intake": INTAKE, **qa},
        "transcript": public_transcript(full),
        "transcriptSupplied": {
            "to": [a["org"] for a in public_roster(roster)],
            "fullTranscriptSha256": _sha(full),
            "how": "Log entry only: the full transcript is supplied to the simulated attendees by recording its "
                   "sha256 here. Nothing is sent to anyone (DEC-194)."},
        "publicRelease": {"decision": _engagement.DECISION,
                          "statement": "Published with every agency comment, question and name removed (CCM-QTR-SRR), "
                                       "after the sensitivity screen below (CCM-QTR-NID)."},
    }
    _engagement.require_none(doc, "the Quarterly Review")
    doc["sensitivityScreen"] = _sensitivity.require_clean(doc, "the Quarterly Review")
    return doc


def render_markdown(doc):
    out = [f"# {doc['title']}", "", f"> {doc['engagement']}", "",
           f"- **Review date:** {doc['reviewDate']} (held {doc['heldAt']}{', late' if doc['late'] else ''}) | "
           f"**Report reviewed:** {doc['ocrIssue']['report']}",
           f"- **Attendee policy:** {doc['attendeePolicy']}", "", "## Roster", ""]
    out += [f"- {a['seat']}, {a['org']}" for a in [doc["host"], *doc["roster"]]]
    out += ["", "## Agenda", ""] + [f"{n}. {x}" for n, x in enumerate(doc["agenda"], 1)]
    out += ["", "## Transcript (agency lines removed)", ""]
    out += [f"**{x['speaker']} ({x['org']}):** {x['line']}  " for x in doc["transcript"]]
    out += ["", "## Feedback received through the intake (anonymized)", "", doc["feedback"]["intake"], ""]
    out += [f"- **Q:** {i['question']}  \n  **A:** {i['answer']}" for i in doc["feedback"]["items"]]
    out += ["", f"_Full transcript supplied to the simulated attendees: sha256 "
                f"`{doc['transcriptSupplied']['fullTranscriptSha256']}`. {doc['transcriptSupplied']['how']}_", "",
            "---", "_Source of truth: the signed JSON._"]
    return "\n".join(out)


def held(index):
    """{issue date: entry} from a published quarterly-reviews.json (or {})."""
    if not index:
        return {}
    if index.get("schema") != INDEX_SCHEMA or not isinstance(index.get("reviews"), list):
        _fail("the published quarterly-reviews.json is not a quarterly-reviews/1 index")
    return {r["ocrIssue"]: r for r in index["reviews"]}


def missing(cal, index, today):
    """Review dates that have passed (strictly before today) with no review published."""
    have = held(index)
    return [(d, cal.review_date(d)) for d in cal.issues
            if cal.review_date(d) < today and d.isoformat() not in have]
