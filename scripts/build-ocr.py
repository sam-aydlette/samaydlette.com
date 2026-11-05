#!/usr/bin/env python3
# =============================================================================
# ONGOING CERTIFICATION REPORT BUILDER  (CR26 CCM, FedRAMP's 2026-06-24 schema)
# =============================================================================
# CCM-OCR-AVL: a human-readable report every 3 months covering the period since
# the previous one, with the eight summaries, in FedRAMP's OCR schema. Dates
# come from the fixed calendar (infrastructure/schemas/ccm-calendar.json via
# scripts/_ccm.py), never from "now plus 91 days":
#
#   rolling (default)   the report as it stands today, from the latest issue to
#                       today; rebuilt on every deploy and maintenance run
#   --issue YYYY-MM-DD  the frozen report for one calendar issue date, covering
#                       the previous issue to that one (scripts/issue-ocr.py)
#
# Sources: the SCN register (changes), the decision register (planned changes),
# the VDR report (accepted vulnerabilities), the incident register when present
# (reportable incidents and lessons learned), and the feedback register
# (data/ocr-feedback.json: the operator's anonymized summary of the questions
# and answers on the previous report, CCM-OCR-AFS).
#
# Before it is written, every string is screened (scripts/_sensitivity.py,
# CCM-OCR-LSI) and the whole document validated against the vendored schema;
# either failing writes nothing. The public-release determination (CCM-OCR-RPS)
# is a decision record the report cites.
#
#   build-ocr.py --vdr vdr-report.json --decisions ../data/decisions.json \
#       --scn-register ../docs/scn/scn-register.csv --ksi-signal ksi-signal.json
# =============================================================================

import argparse
import csv
import json
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ccm  # noqa: E402
import _decisions  # noqa: E402
import _fedramp_schema as fs  # noqa: E402
import _incidents  # noqa: E402
import _offering  # noqa: E402
import _sensitivity  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
FEEDBACK_PATH = REPO / "data" / "ocr-feedback.json"
INCIDENTS_PATH = REPO / "data" / "incidents.json"
SITE = "https://samaydlette.com"
PLANNING_DAYS = 92  # at least 3 months past the report's end
SUMMARY_MAX = 300
# The decision records the report cites (data/decisions.json).
PUBLIC_RELEASE_DECISION = "DEC-101"   # CCM-OCR-RPS / CCM-QTR-SCR: published in full
FEEDBACK_DECISION = "DEC-102"         # CCM-OCR-AFS: the operator summarizes feedback, anonymized
REVIEW_DECISION = "DEC-103"           # CCM-QTR-MTG: the operator hosts each review
STANDING_AGENDA = [
    "Walk through the report's eight summaries and anything changed since it was issued.",
    "Standing item (CCM-QTR-ACT): Key Security Indicator results and their trend over the quarter, from the "
    "Security Decision Record's 30-day and one-year metric summaries.",
    "Standing item (CCM-QTR-ACT): open and accepted vulnerabilities and their trend, from the vulnerability "
    "history (VER-TFR-MRH).",
    "Standing item (CCM-QTR-ACT): the plan for the next quarter, including planned changes to certification data.",
    "Questions from attendees, and those received through the report's feedback channel.",
]


def _fail(msg):
    raise SystemExit(f"::error::OCR: {msg} (fail-closed)")


def _load_json(path, required=False):
    p = Path(path) if path else None
    if not p or not p.exists():
        if required:
            _fail(f"{path} not found")
        return None
    return json.loads(p.read_text())


def _scn_rows(path):
    p = Path(path)
    if not p.exists():
        return []
    with p.open(newline="") as f:
        return list(csv.DictReader(f))


def _day(v):
    try:
        return date.fromisoformat(str(v)[:10])
    except ValueError:
        return None


def incident_summary(incidents, period_start):
    """CCM-OCR-AVL item 7, from the incident register: the FedRAMP Reportable
    Incidents detected this period, or an attestation of none. Exercises are
    not incidents and are never counted."""
    log = "The incident log, /.well-known/incident-reports.json, records every incident evaluated, exercises included."
    real = [i for i in (incidents or {}).get("incidents", [])
            if not i.get("exercise") and (i.get("evaluation") or {}).get("reportable")
            and str(i.get("detected_at") or i.get("started_at") or "")[:10] >= period_start]
    if real:
        return (f"{len(real)} FedRAMP Reportable Incident(s) this period: "
                + "; ".join(f"{i['id']} ({_incidents.status(i)})" for i in real) + f". {log}")
    return ("No FedRAMP Reportable Incidents occurred during this reporting period. The system holds "
            "no federal customer data, so the IEC-CSO-EFR trigger does not apply; this is an "
            f"attestation of none, not an omission. {log}")


def _in(d, period):
    return d is not None and period[0] < d <= period[1]


def _short(text, n=SUMMARY_MAX):
    text = " ".join(str(text or "").split())
    return text if len(text) <= n else text[: n - 1].rstrip() + "…"


# --- the eight summaries -------------------------------------------------------------

def scn_changes(rows, period):
    out, transformative = [], []
    for r in rows:
        when = _day(r.get("date_finished")) or _day(r.get("date_initiated"))
        if not _in(when, period):
            continue
        line = f"{r.get('scn_id')} ({r.get('scn_type')}, {when}): {_short(r.get('short_description'))}"
        out.append(line)
        if (r.get("scn_type") or "").lower() == "transformative":
            transformative.append(line)
    return out, transformative


def planned_changes(decisions, period):
    horizon = period[1] + timedelta(days=PLANNING_DAYS)
    changes = [f"{r['id']}: {_short(r.get('title'), 160)}"
               + (f" (planned completion {r['planned_completion']})" if r.get("planned_completion") else "")
               for r in _decisions.in_force(decisions or {"decisions": []})
               if r.get("remediation_plan") or r.get("planned_completion")]
    return {"planningHorizonThrough": horizon.isoformat(), "changes": changes}


def accepted_summary(vdr, period):
    acc = (vdr or {}).get("risk_accepted") or []
    if not acc:
        return (f"No accepted vulnerabilities as of {period[1]}. Full records: "
                f"{SITE}/.well-known/vdr-accepted-vulnerabilities.json (VER-RPT-AVI).")
    ids = ", ".join(sorted(str(a.get("decision_id") or a.get("tracking_id")) for a in acc)[:20])
    return (f"{len(acc)} accepted vulnerabilities as of {period[1]}, each with a decision record ({ids}). "
            f"Full records: {SITE}/.well-known/vdr-accepted-vulnerabilities.json (VER-RPT-AVI).")


def reportable_incidents(register, period):
    out = []
    for inc in (register or {}).get("incidents", []):
        if not (inc.get("evaluation") or {}).get("reportable"):
            continue
        if not _in(_day(inc.get("started_at")), period):
            continue
        title = str(inc.get("title") or "")
        if inc.get("exercise"):
            title = "Exercise, not a real incident: " + title.removeprefix("Exercise: ")
        rec = {"summary": f"{inc['id']}: {_short(title)}", "occurredAt": inc["started_at"]}
        if inc.get("resolved_at"):
            rec["resolvedAt"] = inc["resolved_at"]
        lessons = list(inc.get("lessons_learned") or [])
        for rep in inc.get("reports", []):
            lessons += list((rep.get("set") or {}).get("lessons_learned") or [])
        if lessons:
            rec["incidentLessonsLearned"] = [_short(x) for x in lessons]
        out.append(rec)
    return out


# --- feedback (CCM-OCR-FBM / AFS) ----------------------------------------------------

def load_feedback(path=FEEDBACK_PATH):
    doc = _load_json(path) or {"schema": "ocr-feedback/1", "summaries": []}
    if doc.get("schema") != "ocr-feedback/1" or not isinstance(doc.get("summaries"), list):
        _fail(f"{path} is not an ocr-feedback/1 document")
    for s in doc["summaries"]:
        for k in ("ocr", "received", "summarized_by", "summarized_on", "items"):
            if k not in s:
                _fail(f"feedback summary for {s.get('ocr')} has no {k}")
        if not isinstance(s["items"], list) or len(s["items"]) > s["received"]:
            _fail(f"feedback summary for {s['ocr']}: more summarized items than received")
    return doc


def feedback_summary(feedback, previous_issue):
    """The anonymized summary of feedback on the previous issued report."""
    if previous_issue is None:
        return {"ocr": None, "statement": "No report has been issued before this one, so there is no feedback "
                "to summarize yet."}
    entry = next((s for s in feedback["summaries"] if s["ocr"] == previous_issue.isoformat()), None)
    if entry is None or entry["received"] == 0:
        return {"ocr": previous_issue.isoformat(), "received": 0,
                "statement": f"No feedback or questions were received on the report issued {previous_issue}."}
    return {"ocr": entry["ocr"], "received": entry["received"],
            "summarizedOn": entry["summarized_on"],
            "statement": f"{entry['received']} item(s) received on the report issued {entry['ocr']}, "
                         "summarized without names, agencies or identifying detail.",
            "items": [{"question": _short(i["question"]), "answer": _short(i["answer"])} for i in entry["items"]]}


# --- build ---------------------------------------------------------------------------

def build(cal, today, vdr, decisions, scn_rows, incidents, feedback, signal, prof, off, prev, now, issue=None):
    if issue is None:
        period = cal.current_period(today)
        done = cal.issued(today)
        prev_issue = done[-1] if done else None
        kind = {"kind": "rolling", "statement": "The report as it stands since the latest issue; rebuilt on every "
                "deploy and maintenance run. Issued reports are frozen: see ongoingCertificationReportIssues."}
    else:
        if issue not in cal.issues:
            _fail(f"{issue} is not a calendar issue date")
        if issue > today:
            _fail(f"{issue} is in the future: a report is issued on or after its date")
        period = cal.period(issue)
        i = cal.issues.index(issue)
        prev_issue = cal.issues[i - 1] if i else None
        kind = {"kind": "issued", "issueDate": issue.isoformat(), "issuedAt": now.isoformat(),
                "late": today > issue,
                "statement": "Frozen at issue: this file is never rewritten. Its sha256 is in ocr-issues.json."}
    ref = issue or today
    review_issue = issue or (cal.issued(today)[-1] if cal.issued(today) else cal.issues[0])
    changes, transformative = scn_changes(scn_rows, period)
    feedback_on = feedback_summary(feedback, prev_issue)
    doc = {
        "$schema": fs.stamp("ocr"),
        "certificationPackageOverviewUri": fs.CPO_URI,
        "reportPeriod": {"from": period[0].isoformat(), "to": period[1].isoformat()},
        "certificationDataChanges": changes,
        "plannedCertificationDataChanges": planned_changes(decisions, period),
        "acceptedVulnerabilities": accepted_summary(vdr, period),
        "transformativeChanges": transformative,
        "updatedRecommendations": [
            "No new recommendations this period. The secure configuration guidance remains current: "
            f"{off.get('secure_configuration_guidance_url')}"],
        "activeAgencies": [],
        "reportableIncidents": {"incidents": reportable_incidents(incidents, period)},
        "metadata": {},
        "providerExtensions": {
            "fedRampId": off["fedramp_id"],
            "class": prof.get("fedramp_class"),
            "impact_level": prof.get("impact_level"),
            "ksi_signal_id": (signal or {}).get("signal_id"),
            "report": kind,
            "continuousMonitoring": _ccm.dates_summary(cal, ref),
            "activeAgenciesStatement": "No agency uses this offering: it is an unsponsored proof of concept.",
            "incidentAttestation": incident_summary(incidents, period[0].isoformat()),
            "incidentRegister": ("data/incidents.json" if incidents is not None else
                                 "No incident register in this build; the list above is empty because no "
                                 "FedRAMP Reportable Incident has been recorded."),
            "feedback": {"channel": _ccm.feedback_url(ref if issue else review_issue),
                         "howDelivered": "A public GitHub issue form per report. The operator answers there and "
                                         "publishes an anonymized summary of the questions and answers in the next "
                                         f"report ({FEEDBACK_DECISION}). Sensitive questions go to the security "
                                         "contact in /.well-known/security.txt.",
                         "summaryOfPreviousReport": feedback_on},
            "quarterlyReview": {"date": cal.review_date(review_issue).isoformat(),
                                "start": cal.review_start(review_issue).isoformat(),
                                "durationMinutes": cal.duration,
                                "calendar": _ccm.ICS_URL, "registration": _ccm.REGISTRATION_URL,
                                "hostedBy": f"The operator hosts it by video call ({REVIEW_DECISION}).",
                                "agenda": STANDING_AGENDA},
            "publicRelease": {"decision": PUBLIC_RELEASE_DECISION,
                              "statement": "Published in full: it carries no federal customer or agency data and "
                                           "passed the sensitivity screen below, so releasing it will not likely "
                                           "have an adverse effect on the offering (CCM-OCR-RPS)."},
        },
    }
    doc["providerExtensions"]["sensitivityScreen"] = _sensitivity.require_clean(doc, "the Ongoing Certification Report")
    return _offering.stamp_version(doc, prev, now, "Automated: scripts/build-ocr.py, from the CCM calendar, the "
                                   "SCN, decision, incident and feedback registers and the VDR report")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--vdr", default="vdr-report.json")
    ap.add_argument("--decisions", default="../data/decisions.json")
    ap.add_argument("--scn-register", default="../docs/scn/scn-register.csv")
    ap.add_argument("--incidents", default="../data/incidents.json")
    ap.add_argument("--ksi-signal", default="ksi-signal.json")
    ap.add_argument("--profile", default=str(REPO / "data" / "system-profile.json"))
    ap.add_argument("--offering", default=str(_offering.OFFERING_PATH))
    ap.add_argument("--calendar", default=str(_ccm.CALENDAR_PATH))
    ap.add_argument("--incidents", default=str(INCIDENTS_PATH))
    ap.add_argument("--feedback", default=str(FEEDBACK_PATH))
    ap.add_argument("--previous", default=None, help="the previously published rolling report (for its version)")
    ap.add_argument("--issue", default=None, help="build the frozen report for this calendar issue date")
    ap.add_argument("--output", default="ongoing-certification-report.json")
    ap.add_argument("--md-output", default="ongoing-certification-report.md")
    a = ap.parse_args(argv)

    now = datetime.now(timezone.utc)
    today = now.date()
    cal = _ccm.load(a.calendar, today)
    prev = _load_json(a.previous) or {}
    issue = date.fromisoformat(a.issue) if a.issue else None
    doc = build(cal, today, _load_json(a.vdr), _decisions.load(a.decisions), _scn_rows(a.scn_register),
                _incidents.load(a.incidents) if Path(a.incidents).is_file() else None, load_feedback(a.feedback), _load_json(a.ksi_signal),
                json.loads(Path(a.profile).read_text()), _offering.load(a.offering), prev, now, issue)
    fs.write_validated(doc, "ocr", a.output)
    if a.md_output:
        Path(a.md_output).write_text(render_markdown(doc) + "\n")
    cm = doc["providerExtensions"]["continuousMonitoring"]
    print(f"ongoing-certification-report ({doc['providerExtensions']['report']['kind']}) "
          f"{doc['reportPeriod']['from']}..{doc['reportPeriod']['to']}: "
          f"{len(doc['certificationDataChanges'])} changes, "
          f"{len(doc['reportableIncidents']['incidents'])} incidents; next report "
          f"{cm['nextOngoingCertificationReportDate']}, next review {cm['nextQuarterlyReviewDate']}")
    return 0


# --- human-readable view (same data as the JSON) --------------------------------------

def render_markdown(r):
    pe, m = r["providerExtensions"], r["metadata"]
    cm, qr, fb = pe["continuousMonitoring"], pe["quarterlyReview"], pe["feedback"]
    rep = pe["report"]
    title = (f"Ongoing Certification Report, issued {rep['issueDate']}" if rep["kind"] == "issued"
             else "Ongoing Certification Report (since the latest issue)")
    out = [f"# {title}", "",
           f"- **FedRAMP ID:** {pe['fedRampId']} (simulated)",
           f"- **Class:** {pe['class']} | **Reporting period:** {r['reportPeriod']['from']} to {r['reportPeriod']['to']}",
           f"- **Version:** {m['version']} | **Last updated:** {m['lastUpdated']}",
           f"- **Bound to inventory signal:** `{pe['ksi_signal_id']}`",
           f"- **Next Ongoing Certification Report (CCM-OCR-NRD):** {cm['nextOngoingCertificationReportDate']}",
           f"- **Next Quarterly Review (CCM-QTR-NRD):** {cm['nextQuarterlyReviewDate']}",
           f"- **Questions or feedback on this report:** {fb['channel']}", "",
           f"> {rep['statement']}", ""]

    def section(n, t, lines):
        out.extend([f"## {n}. {t}", "", *(lines or ["_None this period._"]), ""])

    section(1, "Changes to certification data", [f"- {c}" for c in r["certificationDataChanges"]])
    pc = r["plannedCertificationDataChanges"]
    section(2, f"Planned changes through {pc['planningHorizonThrough']}", [f"- {c}" for c in pc["changes"]])
    section(3, "Accepted vulnerabilities", [r["acceptedVulnerabilities"]])
    section(4, "Transformative changes", [f"- {c}" for c in r["transformativeChanges"]])
    section(5, "Updated recommendations", [f"- {c}" for c in r["updatedRecommendations"]])
    section(6, "Agencies using the offering", [f"- {a}" for a in r["activeAgencies"]] or
            [pe["activeAgenciesStatement"]])
    inc = r["reportableIncidents"]["incidents"]
    section(7, "FedRAMP Reportable Incidents",
            [f"- {i['summary']} (occurred {i['occurredAt']}"
             + (f", resolved {i['resolvedAt']})" if i.get("resolvedAt") else ")") for i in inc]
            or ["No FedRAMP Reportable Incident occurred in this period."]
            + ([pe["incidentAttestation"]] if pe.get("incidentAttestation") else []))
    lessons = [f"- {x}" for i in inc for x in i.get("incidentLessonsLearned", [])]
    section(8, "Lessons learned from incidents", lessons)
    s = fb["summaryOfPreviousReport"]
    out += ["## Feedback on the previous report (anonymized)", "", s["statement"], ""]
    out += [f"- **Q:** {i['question']}  \n  **A:** {i['answer']}" for i in s.get("items", [])]
    out += ["", f"## Quarterly Review: {qr['date']}", "",
            f"{qr['hostedBy']} Starts {qr['start']}, {qr['durationMinutes']} minutes. Calendar file: "
            f"{qr['calendar']}. Registration: {qr['registration']}.", "", "Agenda:", ""]
    out += [f"{n}. {x}" for n, x in enumerate(qr["agenda"], 1)]
    out += ["", "## Public release", "", f"{pe['publicRelease']['statement']} ({pe['publicRelease']['decision']}). "
            f"Sensitivity screen: {', '.join(pe['sensitivityScreen']['checks'])}; "
            f"{pe['sensitivityScreen']['findings']} findings.", "",
            "---", "_Source of truth: the signed JSON. Rules: CCM-OCR-AVL, CCM-OCR-NRD, CCM-QTR-NRD._"]
    return "\n".join(out)


if __name__ == "__main__":
    sys.exit(main())
