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
# register, the POA&M, the VDR report) and emits it as both JSON (Certification
# Data, bound to the canonical inventory's signal_id) and human-readable
# markdown. It is the same report for the Rev5 and 20x certification types.
#
# What it cannot manufacture is the *relationship*: the synchronous Quarterly
# Review (CCM-QTR-MTG) and the agency feedback loop (CCM-OCR-FBM/AFS) need a
# consuming party. With no agency sponsor those are recorded as N/A, and the OCR
# says so rather than implying a closed loop that does not exist.
#
#   build-ocr.py --vdr vdr-report.json --poam oscal-poam.json \
#                --scn-register ../docs/scn/scn-register.csv --ksi-signal ksi-signal.json
# =============================================================================

import argparse
import csv
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

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


def build_ocr(vdr, poam, scn_rows, signal_id, now):
    period_start = (now - timedelta(days=QUARTER_DAYS)).date().isoformat()
    period_end = now.date().isoformat()

    # 1. Changes to Certification Data — the SCN register is the change record.
    cert_changes = [{"scn_id": r.get("scn_id"), "type": r.get("scn_type"),
                     "summary": (r.get("short_description") or "")[:240],
                     "status": r.get("status", "")[:80]} for r in scn_rows]
    # 4. Transformative changes (a subset of the above).
    transformative = [c for c in cert_changes if (c.get("type") or "").lower() == "transformative"]

    # 2. Planned changes over the next 3 months — open POA&M items.
    planned = []
    if poam:
        for it in poam.get("plan-of-action-and-milestones", {}).get("poam-items", []) or []:
            status = next((p.get("value") for p in it.get("props", []) or []
                           if p.get("name") == "status"), None)
            if status == "open":
                planned.append({"title": it.get("title", "")[:160]})

    # 3. Accepted vulnerabilities.
    accepted = []
    if vdr:
        for a in vdr.get("risk_accepted", []) or []:
            accepted.append({"tracking_id": a.get("tracking_id"), "pain": a.get("pain"),
                             "poam_ref": a.get("poam_ref"),
                             "explanation": (a.get("explanation") or "")[:200]})

    report = {
        "report_type": "ongoing-certification-report",
        "schema": "fedramp-ongoing-certification-report-schema-2026-06-24.json",
        "fedramp_id": "<not assigned — unsponsored self-attested PoC>",
        "class": "C",
        "emitted_at": now.isoformat(),
        "reporting_period": {"start": period_start, "end": period_end},
        "ksi_signal_id": signal_id,
        "next_ongoing_certification_report_date": (now + timedelta(days=QUARTER_DAYS)).date().isoformat(),
        "next_quarterly_review_date": (now + timedelta(days=QUARTER_DAYS)).date().isoformat(),
        # The eight CCM-OCR-AVL summaries:
        "summaries": {
            "changes_to_certification_data": cert_changes,                 # 1
            "planned_changes_next_quarter": planned,                       # 2
            "accepted_vulnerabilities": accepted,                          # 3
            "transformative_changes": transformative,                      # 4
            "updated_recommendations": [                                   # 5
                "No new customer recommendations this period; the Secure Configuration "
                "Guidance at /.well-known/ remains current."],
            "agencies_using_product": [],                                  # 6 (none)
            "reportable_incidents_or_attestation":                         # 7
                "No FedRAMP Reportable Incidents occurred during this reporting period. "
                "The system holds no federal customer data, so the IEC-CSO-EFR trigger "
                "does not apply; this is an attestation of none, not an omission.",
            "lessons_learned_from_incidents": [],                          # 8 (none)
        },
        "relationship_obligations_status": (
            "N/A absent a consuming agency. The synchronous Quarterly Review (CCM-QTR-MTG), "
            "the feedback channel (CCM-OCR-FBM), and the anonymized feedback summary "
            "(CCM-OCR-AFS) require a counterparty; with no agency sponsor there is none to "
            "exercise them. The next-review date above is published per CCM-QTR-NRD regardless."),
    }
    return report


def render_markdown(r):
    s = r["summaries"]
    out = ["# Ongoing Certification Report", ""]
    out.append(f"- **Class:** {r['class']} | **Reporting period:** {r['reporting_period']['start']} to {r['reporting_period']['end']}")
    out.append(f"- **Emitted:** {r['emitted_at']}")
    out.append(f"- **Bound to inventory signal:** `{r['ksi_signal_id']}`")
    out.append(f"- **Next Ongoing Certification Report (CCM-OCR-NRD):** {r['next_ongoing_certification_report_date']}")
    out.append(f"- **Next Quarterly Review (CCM-QTR-NRD):** {r['next_quarterly_review_date']}")
    out.append("")
    out.append("> " + r["relationship_obligations_status"])
    out.append("")

    def section(n, title, body):
        out.append(f"## {n}. {title}\n")
        out.extend(body)
        out.append("")

    cc = s["changes_to_certification_data"]
    section(1, "Changes to Certification Data",
            ([f"- `{c['scn_id']}` ({c['type']}): {c['summary']} — _{c['status']}_" for c in cc]
             if cc else ["_No changes recorded this period._"]))
    pc = s["planned_changes_next_quarter"]
    section(2, "Planned changes over the next 3 months",
            ([f"- {p['title']}" for p in pc] if pc else ["_None planned._"]))
    av = s["accepted_vulnerabilities"]
    section(3, "Accepted vulnerabilities",
            ([f"- `{a['tracking_id']}` (PAIN {a['pain']}, {a['poam_ref'] or 'no POA&M'}): {a['explanation']}" for a in av]
             if av else ["_None._"]))
    tf = s["transformative_changes"]
    section(4, "Transformative changes",
            ([f"- `{c['scn_id']}`: {c['summary']}" for c in tf] if tf else ["_None this period._"]))
    section(5, "Updated recommendations", [f"- {x}" for x in s["updated_recommendations"]])
    ag = s["agencies_using_product"]
    section(6, "Agencies using the product",
            ([f"- {a}" for a in ag] if ag else ["_None — unsponsored proof of concept._"]))
    section(7, "FedRAMP Reportable Incidents", [s["reportable_incidents_or_attestation"]])
    ll = s["lessons_learned_from_incidents"]
    section(8, "Lessons learned from incidents",
            ([f"- {x}" for x in ll] if ll else ["_None; no incidents to date._"]))
    out.append("---")
    out.append("_Source of truth: the signed `ongoing-certification-report.json`. Rules: "
               "CCM-OCR-AVL (report), CCM-OCR-NRD / CCM-QTR-NRD (next dates)._")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vdr", default="vdr-report.json")
    ap.add_argument("--poam", default="oscal-poam.json")
    ap.add_argument("--scn-register", default="../docs/scn/scn-register.csv")
    ap.add_argument("--ksi-signal", default="ksi-signal.json")
    ap.add_argument("--output", default="ongoing-certification-report.json")
    ap.add_argument("--md-output", default="ongoing-certification-report.md")
    a = ap.parse_args()

    now = datetime.now(timezone.utc)
    vdr = _load_json(a.vdr)
    poam = _load_json(a.poam)
    sig = _load_json(a.ksi_signal)
    signal_id = sig.get("signal_id") if sig else None
    scn_rows = _scn_rows(a.scn_register)

    report = build_ocr(vdr, poam, scn_rows, signal_id, now)
    Path(a.output).write_text(json.dumps(report, indent=2) + "\n")
    if a.md_output:
        Path(a.md_output).write_text(render_markdown(report) + "\n")
    print(f"ongoing-certification-report: {len(report['summaries']['changes_to_certification_data'])} cert changes, "
          f"{len(report['summaries']['planned_changes_next_quarter'])} planned, "
          f"{len(report['summaries']['accepted_vulnerabilities'])} accepted vulns; "
          f"next report {report['next_ongoing_certification_report_date']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
