#!/usr/bin/env python3
# =============================================================================
# ONGOING CERTIFICATION REPORT BUILDER  (CR26 CCM)
# =============================================================================
# CR26 Collaborative Continuous Monitoring is a quarterly cycle, not a stream.
# CCM-OCR-AVL requires a human-readable Ongoing Certification Report (OCR) every
# 3 months covering the period since the previous summary, carrying eight
# high-level summaries; CCM-OCR-NRD requires publishing the target date of the
# next OCR, and CCM-QTR-NRD the target date of the next Quarterly Review. This
# generator derives the OCR from the system's own published artifacts (the SCN
# register, the decision register, the VDR report) and emits it as both JSON (Certification
# Data, bound to the canonical inventory's signal_id) and human-readable
# markdown. It is the same report for the Rev5 and 20x certification types.
#
# What it cannot manufacture is the *relationship*: the synchronous Quarterly
# Review (CCM-QTR-MTG) and the agency feedback loop (CCM-OCR-FBM/AFS) need a
# consuming party. With no agency sponsor those are recorded as N/A, and the OCR
# says so rather than implying a closed loop that does not exist.
#
#   build-ocr.py --vdr vdr-report.json --decisions ../data/decisions.json \
#                --scn-register ../docs/scn/scn-register.csv --ksi-signal ksi-signal.json
# =============================================================================

import argparse
import csv
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _decisions  # noqa: E402
import _fedramp_schema as fs  # noqa: E402
import _ocr_calendar  # noqa: E402
from _common import fedramp_id  # noqa: E402

QUARTER_DAYS = 91


def _load_json(path):
    p = Path(path)
    if not p.exists():
        print(f"::warning::OCR input not found: {path}", file=sys.stderr)
        return None
    return json.loads(p.read_text())


def _scn_rows(path):
    p = Path(path)
    if not p.exists():
        return []
    with p.open(newline="") as f:
        return list(csv.DictReader(f))


RELATIONSHIP = ("N/A absent a consuming agency. The synchronous Quarterly Review (CCM-QTR-MTG), the feedback "
                "channel (CCM-OCR-FBM) and the anonymized feedback summary (CCM-OCR-AFS) need a counterparty; "
                "with no agency sponsor there is none. The next review's target date is published regardless "
                "(CCM-QTR-NRD).")
NO_INCIDENTS = ("No FedRAMP Reportable Incidents occurred during this reporting period. The system holds no federal "
                "customer data, so the IEC-CSO-EFR trigger does not apply; the empty list is an attestation of none.")
RECOMMENDATIONS = ["No new customer recommendations this period; the Secure Configuration Guidance at /.well-known/ "
                   "remains current."]


def _in_period(row, start, end):
    """An SCN belongs to the period when it started or finished in it, or is still open."""
    days = [row.get("date_initiated") or "", row.get("date_finished") or ""]
    if not days[1]:
        return True
    return any(start.isoformat() <= d[:10] <= end.isoformat() for d in days if d)


def build_ocr(vdr, decisions, scn_rows, signal_id, now, cal, issued=()):
    """The OCR in FedRAMP's schema (CCM-OCR-AVL), for the period since the last
    issued report, with the next report and review dates from the calendar."""
    today = now.date()
    start = _ocr_calendar.period_start(cal, issued)
    target, overdue = _ocr_calendar.next_report(cal, issued, today)
    review = _ocr_calendar.next_review(cal, issued, today)

    # 1 and 4. Changes to Certification Data: the SCN register is the change record.
    rows = [r for r in scn_rows if _in_period(r, start, today)]
    changes = [f"{r.get('scn_id')} ({r.get('scn_type')}): {(r.get('short_description') or '')[:240]}" for r in rows]
    transformative = [c for c, r in zip(changes, rows, strict=True)
                      if (r.get("scn_type") or "").lower() == "transformative"]
    # 2. Planned changes: in-force decision records with a remediation plan or a
    # planned completion. A false positive or an accepted risk plans no change.
    planned = [f"{r['id']}: {r.get('title', '')[:160]}"
               + (f" (planned completion {r['planned_completion']})" if r.get("planned_completion") else "")
               for r in (decisions or {}).get("decisions", [])
               if r.get("status") == "in-force" and (r.get("remediation_plan") or r.get("planned_completion"))]
    # 3. Accepted vulnerabilities: a summary; the records are in the VDR (VER-RPT-AVI).
    accepted = (vdr or {}).get("risk_accepted", []) or []
    accepted_text = (f"{len(accepted)} accepted vulnerabilit{'y' if len(accepted) == 1 else 'ies'}, each with its "
                     "decision record; the full records are in /.well-known/vdr-accepted-vulnerabilities.json."
                     if accepted else "None.")
    return {
        "$schema": fs.stamp("ocr"),
        "certificationPackageOverviewUri": fs.CPO_URI,
        "reportPeriod": {"from": start.isoformat(), "to": today.isoformat()},
        "certificationDataChanges": changes,
        "plannedCertificationDataChanges": {
            "planningHorizonThrough": (today + timedelta(days=QUARTER_DAYS)).isoformat(), "changes": planned},
        "acceptedVulnerabilities": accepted_text,
        "transformativeChanges": transformative,
        "updatedRecommendations": RECOMMENDATIONS,
        "activeAgencies": [],
        "reportableIncidents": {"incidents": []},
        # This repository's fields, beside the schema's.
        "fedramp_id": fedramp_id(),  # CDS-CSO-FID
        "class": "C",
        "emitted_at": now.isoformat(),
        "ksi_signal_id": signal_id,
        "next_ongoing_certification_report_date": target.isoformat(),          # CCM-OCR-NRD
        "next_ongoing_certification_report_overdue": overdue,
        "next_quarterly_review_date": review.isoformat(),                      # CCM-QTR-NRD
        "reportable_incidents_attestation": NO_INCIDENTS,
        "lessons_learned_from_incidents": [],
        "relationship_obligations_status": RELATIONSHIP,
    }


def render_markdown(r):
    out = ["# Ongoing Certification Report", "",
           f"- **FedRAMP ID:** {r['fedramp_id']} | **Class:** {r['class']}",
           f"- **Reporting period:** {r['reportPeriod']['from']} to {r['reportPeriod']['to']}",
           f"- **Emitted:** {r['emitted_at']}",
           f"- **Bound to inventory signal:** `{r['ksi_signal_id']}`",
           f"- **Next Ongoing Certification Report (CCM-OCR-NRD):** {r['next_ongoing_certification_report_date']}"
           + (" (overdue)" if r["next_ongoing_certification_report_overdue"] else ""),
           f"- **Next Quarterly Review (CCM-QTR-NRD):** {r['next_quarterly_review_date']}", "",
           "> " + r["relationship_obligations_status"], ""]

    def section(n, title, items, empty):
        out.extend([f"## {n}. {title}", ""] + ([f"- {x}" for x in items] if items else [f"_{empty}_"]) + [""])

    section(1, "Changes to Certification Data", r["certificationDataChanges"], "No changes recorded this period.")
    p = r["plannedCertificationDataChanges"]
    section(2, f"Planned changes through {p['planningHorizonThrough']}", p["changes"], "None planned.")
    out.extend(["## 3. Accepted vulnerabilities", "", r["acceptedVulnerabilities"], ""])
    section(4, "Transformative changes", r["transformativeChanges"], "None this period.")
    section(5, "Updated recommendations", r["updatedRecommendations"], "None.")
    section(6, "Agencies using the product", r["activeAgencies"], "None: unsponsored proof of concept.")
    out.extend(["## 7. FedRAMP Reportable Incidents", "", r["reportable_incidents_attestation"], ""])
    section(8, "Lessons learned from incidents", r["lessons_learned_from_incidents"], "None; no incidents to date.")
    out += ["---", "_Source of truth: the signed `ongoing-certification-report.json`, in FedRAMP's OCR schema. "
            "Rules: CCM-OCR-AVL (report), CCM-OCR-NRD and CCM-QTR-NRD (next dates)._"]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vdr", default="vdr-report.json")
    ap.add_argument("--decisions", default="../data/decisions.json")
    ap.add_argument("--scn-register", default="../docs/scn/scn-register.csv")
    ap.add_argument("--ksi-signal", default="ksi-signal.json")
    ap.add_argument("--output", default="ongoing-certification-report.json")
    ap.add_argument("--md-output", default="ongoing-certification-report.md")
    a = ap.parse_args()

    now = datetime.now(timezone.utc)
    vdr = _load_json(a.vdr)
    decisions = _decisions.load(a.decisions)
    sig = _load_json(a.ksi_signal)
    signal_id = sig.get("signal_id") if sig else None
    scn_rows = _scn_rows(a.scn_register)

    report = build_ocr(vdr, decisions, scn_rows, signal_id, now, _ocr_calendar.load())
    fs.write_validated(report, "ocr", a.output)
    if a.md_output:
        Path(a.md_output).write_text(render_markdown(report) + "\n")
    print(f"ongoing-certification-report: {report['reportPeriod']['from']} to {report['reportPeriod']['to']}; "
          f"{len(report['certificationDataChanges'])} changes, "
          f"{len(report['plannedCertificationDataChanges']['changes'])} planned; "
          f"next report {report['next_ongoing_certification_report_date']}, "
          f"next review {report['next_quarterly_review_date']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
