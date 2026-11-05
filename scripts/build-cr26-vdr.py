#!/usr/bin/env python3
# =============================================================================
# CR26 VULNERABILITY REPORTS: VDT, AVI and MRH from the VDR report
# =============================================================================
# The VDR report (vdr-report.json) is this pipeline's own record of every
# finding: its clock, its ratings and its decision. CR26 asks for the same facts
# in three FedRAMP shapes (2026-06-24 schemas):
#
#   vdr-detail-report.json             VER-RPT-VDT  findings not accepted
#   vdr-accepted-vulnerabilities.json  VER-RPT-AVI  accepted findings + rationale
#   vdr-history.json                   VER-TFR-MRH  all recent activity, both kinds
#
# The names share the vdr- prefix because the nightly refresh may write only
# .well-known/vdr-* (its IAM grant); they are rebuilt with every VDR report.
#
# Each is validated against its vendored schema before it is written
# (scripts/_fedramp_schema.py); one that fails is never written.
#
# Which findings are accepted follows FRD-ACV: a vulnerability the provider does
# not intend to fully mitigate or remediate, or one past the VER-TFR-MAV period.
# Here that is a decision of kind accepted / risk-accepted / operational-
# requirement, or a finding the VDR builder marked accepted (past 192 days). The
# rationale is the decision record's justification, never invented: an accepted
# finding with no justification stops the build.
#
# The schemas carry no field for the component, the CVE, the scanner check or the
# decision. Those are the joins a reader needs to trace a finding to the system,
# so each record carries them under `providerExtensions` (the schemas allow
# additional properties).
#
# Report periods (VER-RPT-PER: summarize ALL activity since the previous report):
# each VDT/AVI runs from the previous published report's end to now. The MRH
# accumulates: a finding that leaves the VDR stays in the history, marked
# Remediated with the time it stopped being reported, for HISTORY_DAYS.
#
#   build-cr26-vdr.py --vdr vdr-report.json --decisions ../data/decisions.json \
#       --previous-vdt prev-vdt.json --previous-avi prev-avi.json --previous-mrh prev-mrh.json
# =============================================================================

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _decisions  # noqa: E402
import _fedramp_schema as fs  # noqa: E402

HISTORY_DAYS = 366
ACCEPTED_KINDS = {"risk-accepted", "accepted", "operational-requirement"}
FINAL = {"false-positive": "False Positive", "remediated": "Remediated"}
SOURCES = {
    "checkov": "Checkov (infrastructure-as-code static analysis)",
    "checkov-suppression": "Checkov (infrastructure-as-code static analysis; suppressed check)",
    "tfsec": "tfsec (infrastructure-as-code static analysis)",
    "zap": "OWASP ZAP (dynamic application scan)",
    "grype": "Grype (software composition analysis)",
    "dependabot": "GitHub Dependabot (software composition analysis)",
    "opa": "OPA policy evaluation of the deployed configuration",
}

VDT_OUT = "vdr-detail-report.json"
AVI_OUT = "vdr-accepted-vulnerabilities.json"
MRH_OUT = "vdr-history.json"


def _fail(msg):
    raise SystemExit(f"::error::CR26 vulnerability reports: {msg} (fail-closed)")


def _rating(pain):
    """'N3' -> 3. A missing or malformed rating stops the build."""
    if isinstance(pain, str) and len(pain) == 2 and pain[0] == "N" and pain[1] in "012345":
        return int(pain[1])
    _fail(f"PAIN rating {pain!r} is not N0-N5")


def _ts(value, where):
    if not isinstance(value, str):
        _fail(f"{where}: missing timestamp")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail(f"{where}: {value!r} is not an ISO 8601 timestamp")
    if dt.tzinfo is None:
        _fail(f"{where}: {value!r} has no time zone")
    return dt.astimezone(timezone.utc).isoformat()


def _justifications(register):
    return {r["id"]: (r.get("justification") or "").strip() for r in register.get("decisions", [])}


def _description(f):
    title, desc = (f.get("title") or "").strip(), (f.get("description") or "").strip()
    if title and desc and desc != title:
        return f"{title}: {desc}"
    return title or desc


def is_accepted(f):
    disp = f.get("final_disposition") or f.get("current_disposition")
    return disp in ACCEPTED_KINDS or bool(f.get("accepted"))


def detail(f):
    """A VDR finding as a FedRAMP vulnerabilityDetail record."""
    tid = f.get("tracking_id")
    if not tid:
        _fail("a finding has no tracking_id")
    pain = f.get("current_pain") or f.get("pain")
    rec = {
        "providerTrackingId": tid,
        "detection": {
            "detectedAt": _ts(f.get("first_detected"), f"{tid}.first_detected"),
            "detectionSource": SOURCES.get(f.get("source"), f.get("source") or "unknown"),
        },
        "vulnerabilityDescription": _description(f) or tid,
        "potentialAgencyImpact": (f"Potential Agency Impact {pain} "
                                  f"(technical impact {f.get('technical_impact') or 'not rated'}; "
                                  "see VER-EVA-EPA for the N-rating scale)."),
        "evaluationCompletedAt": _ts(f.get("first_evaluated") or f.get("completed_evaluation"),
                                     f"{tid}.first_evaluated"),
        "isInternetReachable": bool(f.get("internet_reachable")),
        "isLikelyExploitable": bool(f.get("likely_exploitable")),
        "currentRating": _rating(pain),
    }
    over = {"isOverdue": bool(f.get("is_overdue"))}
    if f.get("overdue_explanation"):
        over["explanation"] = f["overdue_explanation"]
    elif over["isOverdue"]:
        _fail(f"{tid}: overdue with no explanation")
    rec["overdueStatus"] = over
    if f.get("supplementary_info"):
        rec["supplementaryRiskInformation"] = f["supplementary_info"]
    reductions = [{"reducedAt": _ts(r.get("at"), f"{tid}.completed_reductions"), "rating": _rating(r.get("to"))}
                  for r in f.get("completed_reductions") or []]
    if reductions:
        rec["painReductionEvents"] = reductions
    disp = f.get("final_disposition") or f.get("current_disposition") or "open"
    if disp in FINAL:
        rec["finalDisposition"] = FINAL[disp]
    elif disp == "mitigated":
        rec["finalDisposition"] = "Fully Mitigated" if f.get("fully_mitigated") else "Partially Mitigated"
    nxt = f.get("next_reduction")
    if "finalDisposition" not in rec and not is_accepted(f) and nxt and nxt.get("estimated_time"):
        target = nxt.get("target_pain")
        # "remediated" removes the vulnerability: no impact remains (N0).
        rec["projectedNextReduction"] = {
            "estimatedAt": _ts(nxt["estimated_time"], f"{tid}.next_reduction"),
            "targetRating": 0 if target == "remediated" else _rating(target),
        }
    rec["providerExtensions"] = {
        "componentId": f.get("component_id"),
        "resource": f.get("resource") or None,
        "cve": f.get("cve"),
        "scannerCheck": f.get("tool_id"),
        "decisionId": f.get("decision_id"),
        "disposition": disp,
        "isKev": bool(f.get("is_kev")),
        "remediationDueAt": f.get("remediation_due_at"),
    }
    return rec


def accepted_info(f, justifications):
    did = f.get("decision_id")
    why = justifications.get(did, "") if did else ""
    if not why and f.get("accepted") and f.get("acceptance_explanation"):
        why = f["acceptance_explanation"]
    if not why:
        _fail(f"accepted finding {f.get('tracking_id')} has no decision justification ({did or 'no decision_id'})")
    return {"vulnerabilityDetail": detail(f), "acceptanceRationale": why}


def _period_start(previous, fallback):
    """The previous report's end, if it is a valid past time; else `fallback`."""
    try:
        end = (previous or {}).get("reportPeriod", {}).get("to")
        dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).isoformat()
    except (AttributeError, TypeError, ValueError):
        return fallback


def _load_previous(path):
    """The previous published report, already signature-verified by the caller.
    Not passed: none was published (first run). Passed but unreadable: stop,
    because treating it as absent would silently drop the carried history."""
    if not path:
        return None
    try:
        doc = json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        _fail(f"previous report {path} unreadable: {exc}")
    if not isinstance(doc, dict):
        _fail(f"previous report {path} is not a JSON object")
    return doc


def build(vdr, register, previous_vdt, previous_avi, previous_mrh, now):
    if not isinstance(vdr, dict) or not isinstance(vdr.get("findings"), list):
        _fail("vdr-report.json has no findings list")
    just = _justifications(register)
    scanner = list(vdr["findings"])
    # Suppressed checks the VDR lists as risk-accepted are accepted vulnerabilities too.
    suppressed = [dict(r, final_disposition="risk-accepted") for r in vdr.get("risk_accepted") or []]
    active = [detail(f) for f in scanner if not is_accepted(f)]
    accepted = [accepted_info(f, just) for f in scanner + suppressed if is_accepted(f)]
    times = [r["detection"]["detectedAt"] for r in active] + \
            [a["vulnerabilityDetail"]["detection"]["detectedAt"] for a in accepted]
    earliest = min(times) if times else now.isoformat()
    to = now.isoformat()
    cpo = {"certificationPackageOverviewUri": fs.CPO_URI}
    # REQ-GOV-2: like every VDR-family output, each names the method profile and
    # conformance results of the VDR report it came from.
    ext = {"source": "vdr-report.json", "vdrReportId": vdr.get("report_id"),
           "ksiSignalId": vdr.get("ksi_signal_id"), "profile": (vdr.get("methodology") or {}).get("profile")}
    vdt = {"$schema": fs.stamp("vdt"), **cpo,
           "reportPeriod": {"from": _period_start(previous_vdt, earliest), "to": to},
           "vulnerabilities": active, "providerExtensions": dict(ext)}
    avi = {"$schema": fs.stamp("avi"), **cpo,
           "reportPeriod": {"from": _period_start(previous_avi, earliest), "to": to},
           "acceptedVulnerabilities": accepted, "providerExtensions": dict(ext)}
    mrh = build_history(active, accepted, previous_mrh, now)
    mrh["providerExtensions"] = {**ext, **mrh["providerExtensions"]}
    for doc, period in ((vdt, "VDT"), (avi, "AVI")):
        if doc["reportPeriod"]["from"] > doc["reportPeriod"]["to"]:
            _fail(f"{period} period starts after it ends")
    return vdt, avi, mrh


def build_history(active, accepted, previous, now):
    """VER-TFR-MRH: every current record, plus records that left the VDR within
    HISTORY_DAYS, closed as Remediated with the time they stopped being reported."""
    cutoff = (now - timedelta(days=HISTORY_DAYS)).isoformat()
    current = {r["providerTrackingId"] for r in active} | \
              {a["vulnerabilityDetail"]["providerTrackingId"] for a in accepted}
    carried = []
    prev = previous or {}
    for rec in (prev.get("activeVulnerabilities") or []) + \
               [a.get("vulnerabilityDetail") for a in prev.get("acceptedVulnerabilities") or []]:
        if not isinstance(rec, dict) or rec.get("providerTrackingId") in current:
            continue
        ext = dict(rec.get("providerExtensions") or {})
        gone = ext.get("noLongerReportedAt") or now.isoformat()
        if gone < cutoff:
            continue
        closed = dict(rec)
        closed.pop("projectedNextReduction", None)
        closed.setdefault("finalDisposition", "Remediated")
        closed["overdueStatus"] = {"isOverdue": False}
        ext["noLongerReportedAt"] = gone
        closed["providerExtensions"] = ext
        carried.append(closed)
    return {"$schema": fs.stamp("mrh"), "certificationPackageOverviewUri": fs.CPO_URI,
            "generatedAt": now.isoformat(),
            "activeVulnerabilities": active + sorted(carried, key=lambda r: r["providerTrackingId"]),
            "acceptedVulnerabilities": accepted,
            "providerExtensions": {
                "retention": f"Records that leave the VDR stay {HISTORY_DAYS} days, closed as Remediated "
                             "with the time they stopped being reported (noLongerReportedAt)."}}


def render_markdown(title, rule, records, accepted=False):
    out = [f"# {title}", "", f"_FedRAMP {rule}. Source of truth: the signed JSON beside this file._", ""]
    if not records:
        return "\n".join(out + ["_None._"])
    out += ["| Tracking ID | Detected | Internet-reachable | Likely exploitable | Rating | Overdue | "
            + ("Rationale |" if accepted else "Disposition |"),
            "|---|---|---|---|---|---|---|"]
    for r in records:
        d = r["vulnerabilityDetail"] if accepted else r
        last = (r["acceptanceRationale"] if accepted else d.get("finalDisposition", "active"))
        out.append("| `{t}` | {at} | {irv} | {lev} | N{n} | {od} | {last} |".format(
            t=d["providerTrackingId"], at=d["detection"]["detectedAt"][:10],
            irv="yes" if d["isInternetReachable"] else "no", lev="yes" if d["isLikelyExploitable"] else "no",
            n=d["currentRating"], od="yes" if d["overdueStatus"]["isOverdue"] else "no",
            last=last.replace("|", "\\|").replace("\n", " ")))
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vdr", default="vdr-report.json")
    ap.add_argument("--decisions", default="../data/decisions.json")
    ap.add_argument("--previous-vdt", default=None)
    ap.add_argument("--previous-avi", default=None)
    ap.add_argument("--previous-mrh", default=None)
    ap.add_argument("--out-dir", default=".")
    a = ap.parse_args()

    try:
        vdr = json.loads(Path(a.vdr).read_text())
    except (OSError, ValueError) as exc:
        _fail(f"cannot read {a.vdr}: {exc}")
    register = _decisions.load(a.decisions)
    now = datetime.now(timezone.utc)
    vdt, avi, mrh = build(vdr, register, _load_previous(a.previous_vdt), _load_previous(a.previous_avi),
                          _load_previous(a.previous_mrh), now)
    out = Path(a.out_dir)
    registry = fs.load_registry()
    # Validate all three before writing any, so a failure leaves none half-written.
    for doc, kind in ((vdt, "vdt"), (avi, "avi"), (mrh, "mrh")):
        errors = fs.validate(doc, kind, registry)
        if errors:
            for e in errors[:25]:
                print(f"::error::{kind}: {e}", file=sys.stderr)
            _fail(f"{kind} does not validate against {fs.SCHEMAS[kind]}; nothing written")
    fs.write_validated(vdt, "vdt", out / VDT_OUT, registry)
    fs.write_validated(avi, "avi", out / AVI_OUT, registry)
    fs.write_validated(mrh, "mrh", out / MRH_OUT, registry)
    (out / VDT_OUT.replace(".json", ".md")).write_text(
        render_markdown("Vulnerability Detail Report", "VER-RPT-VDT", vdt["vulnerabilities"]) + "\n")
    (out / AVI_OUT.replace(".json", ".md")).write_text(
        render_markdown("Accepted Vulnerability Info", "VER-RPT-AVI", avi["acceptedVulnerabilities"],
                        accepted=True) + "\n")
    print(f"CR26 vulnerability reports: VDT {len(vdt['vulnerabilities'])}, "
          f"AVI {len(avi['acceptedVulnerabilities'])}, history {len(mrh['activeVulnerabilities'])} active + "
          f"{len(mrh['acceptedVulnerabilities'])} accepted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
