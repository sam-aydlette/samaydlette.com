#!/usr/bin/env python3
# =============================================================================
# INCIDENT REPORTS: IIR, OIR and FIR from the incident register
# =============================================================================
# The incident register (data/incidents.json, read through scripts/_incidents.py)
# records each incident's FedRAMP reportability evaluation (IEC-CSO-EFR), its
# Incident Rating (IEC-CSO-EFI, or the IEC-CSO-DPR default) and the reports
# issued. This renders, for every FedRAMP Reportable Incident, each report in
# FedRAMP's 2026-06-24 incident report schema:
#
#   incident-<ID>-<NN>-initial.json   IEC-CSO-IIR
#   incident-<ID>-<NN>-ongoing.json   IEC-CSO-OIR  (restates every earlier item)
#   incident-<ID>-<NN>-final.json     IEC-CSO-FIR  (final values for every item)
#
# each validated before it is written (scripts/_fedramp_schema.py), plus the
# incident log:
#
#   incident-reports.json   every incident, its evaluation and reason, its rating
#                           history, each report (file, sha256, what changed) and
#                           each report clock (due, issued, on time)
#   incident-reports.md     the same, human-readable, with every report's content
#
# The clocks are FedRAMP's Class C timeframes, read through scripts/_rules.py.
#
# Vulnerabilities as incidents (VER-TFR-IRI, VER-TFR-NRI). Given the VDR report,
# policies/triage.rego names each finding a rule makes a FedRAMP Reportable
# Incident. One the operator has adopted that rule for and that no unresolved
# incident names is published as a trigger with no incident, its Initial
# report due from the finding's first evaluation at the default rating; the
# clock check fails, and the evidence watchdog pages, once that time passes.
#
# Notification. Nothing is sent to FedRAMP or to agencies: the register's
# policy says "published-only" and every report says so. After this builder,
# scripts/deliver-incident-reports.py "delivers" each report to SIMULATED
# FedRAMP and agency recipients and writes the delivery log.
#
#   build-incident-report.py --incidents ../data/incidents.json --vdr vdr-report.json --out-dir .
#   build-incident-report.py --check incident-reports.json     # exit 1 if a report is overdue
# =============================================================================

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fedramp_schema as fs  # noqa: E402
import _incidents  # noqa: E402
import _rules  # noqa: E402

INDEX = "incident-reports.json"
INDEX_MD = "incident-reports.md"
EXERCISE_PREFIX = "EXERCISE: a simulated incident; no real system, data or agency was affected. "

# The items an Initial report carries (IEC-CSO-IIR) and the further items an
# Ongoing report adds (IEC-CSO-OIR), in the rules' order, by register field.
IIR_ITEMS = [("coordinator", "Federal incident response coordinator"),
             ("tracking_id", "Provider tracking identifier"),
             ("description", "Description of the incident"),
             ("timeline", "Timeline"),
             ("rating", "Potential Agency Impact N-rating (historical and current)"),
             ("functional_impact", "Functional impact to federal agency customers"),
             ("recovery_plan", "Estimated recovery plan, milestones and timelines"),
             ("affected_agencies", "Likely affected customer agencies")]
OIR_ITEMS = [("observed_activity", "Observed incident activity"),
             ("indicators_of_compromise", "Indicators of compromise"),
             ("related_cves", "Related CVE identifiers"),
             ("root_cause", "Root cause"),
             ("response_and_recovery_activities", "Response and recovery activities")]


def _fail(msg):
    raise SystemExit(f"::error::incident reports: {msg} (fail-closed)")


def _iso(dt):
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def vulnerability_triggers(vdr):
    """The VDR findings policies/triage.rego treats as FedRAMP Reportable Incidents."""
    import _triage
    findings = [{k: f.get(k) for k in ("tracking_id", "cve", "pain", "internet_reachable", "likely_exploitable",
                                       "fully_mitigated", "final_disposition", "first_evaluated")}
                for f in vdr.get("findings", [])]
    out = _triage.evaluate('{"triggers": data.vdr.triage.incident_triggers, '
                           '"errors": data.vdr.triage.incident_errors}', {"findings": findings})
    if out.get("errors"):
        _fail("; ".join(sorted(out["errors"])))
    if not isinstance(out.get("triggers"), list):
        _fail("the triage policy returned no incident triggers")
    return out["triggers"]


def _milestones(inc, upto, default):
    """Every milestone known at `upto`: the register's, plus the ones the
    register's own fields mark (evaluation, each rating, resolution, recovery)."""
    ms = []
    for r in inc["reports"]:
        if _incidents.parse_ts(r["at"], "") > upto:
            break
        ms += [(m["at"], m["description"]) for m in r.get("set", {}).get("milestones", [])]
    ev = inc["evaluation"]
    ms.append((ev["evaluated_at"], f"FedRAMP reportability evaluated ({ev['basis']}): reportable; "
                                   f"rated N{default} by default (IEC-CSO-DPR)"))
    for e in inc["estimates"]:
        ms.append((e["estimated_at"], f"Incident Rating estimated N{e['rating']} (IEC-CSO-EFI)"))
    for k, text in (("resolved_at", "Incident resolved"), ("recovery_complete_at", "Recovery complete")):
        if k in inc:
            ms.append((inc[k], text))
    known = [(at, d) for at, d in ms if _incidents.parse_ts(at, "") <= upto]
    return [{"occurredAt": at, "milestoneDescription": d}
            for at, d in sorted(known, key=lambda x: _incidents.parse_ts(x[0], ""))]


def _state(inc, k):
    """The register fields as known after report k, and which report last set each."""
    state, set_by = {}, {}
    for i, r in enumerate(inc["reports"][:k + 1]):
        for key, val in r.get("set", {}).items():
            if key != "milestones":
                state[key], set_by[key] = val, i
    return state, set_by


def _rating_notes(inc, at, default):
    rating, basis = _incidents.rating_at(inc, at, default)
    hist = [f"N{r} from {when} ({b})" for when, r, b in _incidents.rating_history(inc, default, at)]
    if basis.startswith("default"):
        lead = (f"No Incident Rating estimate had been made; rated N{rating} by default as IEC-CSO-DPR requires.")
    else:
        e = [x for x in inc["estimates"] if _incidents.parse_ts(x["estimated_at"], "") <= at][-1]
        scope = "one agency" if e["agencies"] == "single" else "more than one agency"
        lead = (f"Estimated N{rating} under IEC-CSO-EFI: a likely {e['customer_effect']} customer effect on "
                f"{scope}. {e['reason']}")
    return rating, f"{lead} History: {'; '.join(hist)}."


def report_document(inc, k, policy, default):
    """Report k of incident `inc` in the FedRAMP incident report schema. Every
    item set by report k or earlier is restated with its latest value."""
    r = inc["reports"][k]
    at = _incidents.parse_ts(r["at"], "")
    state, _ = _state(inc, k)
    rating, notes = _rating_notes(inc, at, default)
    doc = {
        "$schema": fs.stamp("incident"),
        "certificationPackageOverviewUri": fs.CPO_URI,
        "reportType": r["type"],
        "providerTrackingId": inc["id"],
        "federalIncidentCoordinator": policy["federal_incident_coordinator"],
        "incidentDescription": (EXERCISE_PREFIX if inc["exercise"] else "") + state["description"],
        "timeline": {
            "startedAt": inc["started_at"],
            "detectedAt": inc["detected_at"],
            "detectionSource": inc["detection_source"],
            "evaluationCompletedAt": inc["evaluation"]["evaluated_at"],
            "milestones": _milestones(inc, at, default),
        },
        "potentialImpact": {
            "historicalRating": [n for _, n, _ in _incidents.rating_history(inc, default, at)],
            "currentRating": rating,
            "evaluationNotes": notes,
        },
    }
    for key, field in _incidents.TEXT_FIELDS.items():
        if key in state and key != "description":
            doc[field] = state[key]
    for key, field in _incidents.LIST_FIELDS.items():
        if key in state:
            doc[field] = state[key]
    if r["type"] == "Final":
        doc["resolvedAt"] = inc["recovery_complete_at"]
    return doc


def _changes(inc, k):
    """{item: "updated" | "no update" | "not yet available"} for report k."""
    state, set_by = _state(inc, k)
    out = {}
    for key, _ in IIR_ITEMS + OIR_ITEMS:
        if key in ("coordinator", "tracking_id"):
            out[key] = "updated" if k == 0 else "no update"
        elif key == "timeline":
            out[key] = "updated" if k == 0 or inc["reports"][k].get("set", {}).get("milestones") else "no update"
        elif key == "rating":
            prev = _incidents.parse_ts(inc["reports"][k - 1]["at"], "") if k else None
            now = _incidents.parse_ts(inc["reports"][k]["at"], "")
            moved = k == 0 or any(prev < _incidents.parse_ts(e["estimated_at"], "") <= now for e in inc["estimates"])
            out[key] = "updated" if moved else "no update"
        elif key not in state:
            out[key] = "not yet available"
        else:
            out[key] = "updated" if set_by[key] == k else "no update"
    return out


def build(reg, vdr, now, out_dir, rules_dir=_rules.RULES_DIR):
    """Write every report and the incident log; return the log."""
    out_dir = Path(out_dir)
    timeframes = _rules.incident_report_timeframes(rules_dir)
    default = _rules.default_incident_rating(rules_dir)
    policy = reg["policy"]
    registry = fs.load_registry()
    incidents, due = [], []
    for inc in reg["incidents"]:
        reports = []
        for k, r in enumerate(inc["reports"]):
            name = f"incident-{inc['id']}-{k + 1:02d}-{r['type'].lower()}.json"
            fs.write_validated(report_document(inc, k, policy, default), "incident", out_dir / name, registry)
            reports.append({"type": r["type"], "issued_at": r["at"], "file": name,
                            "sha256": hashlib.sha256((out_dir / name).read_bytes()).hexdigest(),
                            "changes": _changes(inc, k)})
        obligations = _incidents.obligations(inc, timeframes, default, now)
        pending = [o for o in obligations if o["report_index"] is None]
        for o in pending:
            due.append({"incident": inc["id"], "finding": None, "report": o["report"], "due_at": o["due_at"],
                        "overdue": o["overdue"]})
        last = inc["reports"][-1]["at"] if inc["reports"] else inc["evaluation"]["evaluated_at"]
        rating, basis = _incidents.rating_at(inc, _incidents.parse_ts(last, ""), default)
        incidents.append({
            "id": inc["id"], "title": inc["title"], "exercise": inc["exercise"],
            "status": _incidents.status(inc),
            "detected_at": inc["detected_at"], "detection_source": inc["detection_source"],
            "evaluation": inc["evaluation"], "findings": inc.get("findings", []),
            "rating": ({"current": rating, "basis": basis,
                        "history": [{"from": w, "rating": n, "basis": b}
                                    for w, n, b in _incidents.rating_history(inc, default)]}
                       if inc["evaluation"]["reportable"] else None),
            "resolved_at": inc.get("resolved_at"), "recovery_complete_at": inc.get("recovery_complete_at"),
            "reports": reports, "obligations": obligations,
            "next_report_due_at": pending[0]["due_at"] if pending else None,
        })

    triggers = []
    covered = _incidents.open_findings(reg)
    if vdr is not None:
        for t in vulnerability_triggers(vdr):
            adopted = t["rule"] in policy["adopted_vulnerability_rules"]
            inc_id = covered.get(t["tracking_id"]) or (covered.get(t["cve"]) if t["cve"] else None)
            entry = {**t, "adopted": adopted, "incident": inc_id}
            triggers.append(entry)
            if adopted and inc_id is None:
                start = _incidents.parse_ts(t["first_evaluated"], "") if t["first_evaluated"] else now
                unit, n = timeframes["iir"][default]
                at = _incidents.add_clock(start, unit, n)
                due.append({"incident": None, "finding": t["tracking_id"], "report": "Initial",
                            "due_at": at.isoformat(), "overdue": now > at})
    overdue = [d for d in due if d["overdue"]]
    log = {
        "schema": "incident-reports/1",
        "emitted_at": _iso(now),
        "generator": "scripts/build-incident-report.py",
        "description": ("The incident log: every incident recorded in data/incidents.json, its FedRAMP "
                        "reportability evaluation and reason (IEC-CSO-EFR), its Incident Rating (IEC-CSO-EFI, "
                        "or the IEC-CSO-DPR default), each Initial, Ongoing and Final report issued, and each "
                        "Class C report clock. Exercises are marked exercise: true."),
        "rules": _rules.pin(rules_dir),
        "notification": {"mode": policy["notification"], "text": policy["notification_text"]},
        "policy": {k: policy[k] for k in ("federal_incident_coordinator", "adopted_vulnerability_rules",
                                          "federal_customer_data", "decided_by", "decided_on", "review_by")},
        "vdr": ({"emitted_at": vdr.get("emitted_at"), "report_id": vdr.get("report_id")} if vdr is not None
                else None),
        "vulnerability_triggers": triggers,
        "obligations_due": due,
        "clock_status": "overdue" if overdue else "ok",
        "summary": {
            "incidents": len(incidents),
            "reportable": sum(1 for i in incidents if i["evaluation"]["reportable"]),
            "open": sum(1 for i in incidents if i["status"] in ("open", "resolved")),
            "exercises": sum(1 for i in incidents if i["exercise"]),
            "reports": sum(len(i["reports"]) for i in incidents),
            "triggers_without_incident": sum(1 for t in triggers if t["adopted"] and t["incident"] is None),
            "overdue": len(overdue),
        },
        "incidents": incidents,
    }
    (out_dir / INDEX).write_text(json.dumps(log, indent=2) + "\n")
    (out_dir / INDEX_MD).write_text(render_markdown(log, out_dir) + "\n")
    return log


def _item_text(key, doc):
    if key == "coordinator":
        return doc["federalIncidentCoordinator"]
    if key == "tracking_id":
        return doc["providerTrackingId"]
    if key == "description":
        return doc["incidentDescription"]
    if key == "timeline":
        t = doc["timeline"]
        lines = [f"started {t['startedAt']}; detected {t['detectedAt']} by {t['detectionSource']}; "
                 f"reportability evaluated {t['evaluationCompletedAt']}"]
        lines += [f"{m['occurredAt']}: {m['milestoneDescription']}" for m in t["milestones"]]
        return "\n".join(f"  - {x}" for x in lines)
    if key == "rating":
        p = doc["potentialImpact"]
        return f"N{p['currentRating']} (history {', '.join(f'N{n}' for n in p['historicalRating'])}). " \
               f"{p['evaluationNotes']}"
    field = _incidents.TEXT_FIELDS.get(key) or _incidents.LIST_FIELDS.get(key)
    val = doc.get(field)
    if isinstance(val, list):
        return ", ".join(val) if val else "none"
    return val or "not yet available"


def render_markdown(log, out_dir):
    s = log["summary"]
    out = ["# Incident log and reports", "",
           "_Generated by scripts/build-incident-report.py from data/incidents.json. The JSON beside this file "
           "(incident-reports.json, signed) is the record; this is a rendering of it._", "",
           f"- **Emitted:** {log['emitted_at']}",
           f"- **Incidents:** {s['incidents']} ({s['reportable']} FedRAMP Reportable; {s['exercises']} exercises); "
           f"**reports issued:** {s['reports']}; **overdue:** {s['overdue']}",
           f"- **Notification:** {log['notification']['mode']}. {log['notification']['text']}",
           f"- **Federal incident response coordinator:** {log['policy']['federal_incident_coordinator']}",
           f"- **Vulnerabilities treated as incidents:** {', '.join(log['policy']['adopted_vulnerability_rules'])}",
           ""]
    out += ["## Vulnerabilities that are FedRAMP Reportable Incidents (VER-TFR-IRI / VER-TFR-NRI)", ""]
    if log["vdr"] is None:
        out += ["No VDR report was supplied to this build.", ""]
    elif not log["vulnerability_triggers"]:
        out += [f"None in the VDR report emitted {log['vdr']['emitted_at']}.", ""]
    else:
        out += ["| Finding | Rule | PAIN | Adopted | Incident |", "|---|---|---|---|---|"]
        out += [f"| `{t['tracking_id']}` | {t['rule']} | {t['pain']} | {t['adopted']} | {t['incident'] or 'NONE'} |"
                for t in log["vulnerability_triggers"]]
        out.append("")
    if log["obligations_due"]:
        out += ["## Reports due", "", "| Incident / finding | Report | Due | Overdue |", "|---|---|---|---|"]
        out += [f"| {d['incident'] or d['finding']} | {d['report']} | {d['due_at']} | {d['overdue']} |"
                for d in log["obligations_due"]]
        out.append("")
    for entry in log["incidents"]:
        ev = entry["evaluation"]
        out += [f"## {entry['id']}: {entry['title']}" + (" (EXERCISE)" if entry["exercise"] else ""), "",
                f"- **Status:** {entry['status']}",
                f"- **Detected:** {entry['detected_at']} by {entry['detection_source']}",
                f"- **Reportability (IEC-CSO-EFR, evaluated {ev['evaluated_at']}, basis {ev['basis']}):** "
                f"{'FedRAMP Reportable Incident' if ev['reportable'] else 'not a FedRAMP Reportable Incident'}. "
                f"{ev['reason']}",
                f"- **Federal customer data considered:** {ev['federal_customer_data_considered']}"]
        if entry["findings"]:
            out.append(f"- **Findings named:** {', '.join(f'`{f}`' for f in entry['findings'])}")
        if entry["rating"]:
            out.append(f"- **Rating:** N{entry['rating']['current']} ({entry['rating']['basis']})")
        if entry["obligations"]:
            out += ["", "| Report | Due | Issued | On time |", "|---|---|---|---|"]
            out += [f"| {o['report']} | {o['due_at']} | {o['issued_at'] or 'not yet'} | "
                    f"{'yes' if o['on_time'] else 'no' if o['on_time'] is False else ('OVERDUE' if o['overdue'] else 'pending')} |"
                    for o in entry["obligations"]]
        out.append("")
        for k, rep in enumerate(entry["reports"]):
            doc = json.loads((Path(out_dir) / rep["file"]).read_text())
            out += [f"### {rep['type']} report, issued {rep['issued_at']} ({rep['file']})", "",
                    f"_Notification: {log['notification']['mode']}; see above._", ""]
            items = IIR_ITEMS + (OIR_ITEMS if k else
                                 [x for x in OIR_ITEMS if rep["changes"][x[0]] != "not yet available"])
            for key, label in items:
                change = rep["changes"][key]
                text = _item_text(key, doc)
                sep = "\n" if text.startswith("  - ") else " "
                out.append(f"- **{label}** ({change}):{sep}{text}")
            if rep["type"] == "Final":
                out.append(f"- **Resolved and recovered:** {doc['resolvedAt']}")
            out.append("")
    return "\n".join(out).rstrip()


def check(index_path, now):
    """Exit status for the clock check: 1 when a report is due and missing."""
    log = json.loads(Path(index_path).read_text())
    late = [d for d in log.get("obligations_due", [])
            if _incidents.parse_ts(d["due_at"], "obligations_due.due_at") < now]
    for d in late:
        who = d["incident"] or f"finding {d['finding']} (no incident opened)"
        print(f"::error::{who}: the {d['report']} incident report was due at {d['due_at']} and has not been issued")
    if not late:
        print(f"incident report clocks: ok ({len(log.get('obligations_due', []))} report(s) pending, none overdue)")
    return 1 if late else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--incidents", default=str(_incidents.DEFAULT_PATH))
    ap.add_argument("--vdr", default=None, help="the built VDR report, for VER-TFR-IRI/NRI triggers")
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--now", default=None, help="ISO 8601 time to evaluate the clocks at (default: now)")
    ap.add_argument("--check", default=None, metavar="INDEX",
                    help="check a built incident-reports.json and exit 1 if a report is overdue")
    a = ap.parse_args(argv)
    now = _incidents.parse_ts(a.now, "--now") if a.now else datetime.now(timezone.utc)
    if a.check:
        return check(a.check, now)
    reg = _incidents.load(a.incidents, now=now)
    vdr = None
    if a.vdr:
        try:
            vdr = json.loads(Path(a.vdr).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            _fail(f"cannot read the VDR report {a.vdr}: {exc}")
        if not isinstance(vdr, dict) or not isinstance(vdr.get("findings"), list):
            _fail(f"{a.vdr} is not a VDR report")
    log = build(reg, vdr, now, a.out_dir)
    s = log["summary"]
    print(f"incident reports: {s['incidents']} incident(s), {s['reports']} report(s), "
          f"{s['triggers_without_incident']} trigger(s) without an incident, clocks {log['clock_status']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
