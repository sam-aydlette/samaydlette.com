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
# What each record says, and where it comes from:
#   detection time   the earliest evidence: the scanner's first report, or the
#                    original_detection_date of a decision naming this exact
#                    record, when the weakness was found before the pipeline's
#                    scanner saw it (e.g. a manual scan). A .checkov.yaml
#                    suppression, which no scanner ever reports, falls back to
#                    the decision date when the decision records no detection
#                    date. The basis is in providerExtensions.
#   next reduction   the decision's planned_reduction (date + target rating) when
#                    one is recorded, else the remediation deadline.
#   overdue          explains the overdue status (deadline, and why it is still
#                    open), never the suppression.
#   supplementary    the decision behind the record: its justification (VDT only;
#                    the AVI carries it as the rationale), when it was decided and
#                    is reviewed, the resources it names, any remediation plan or
#                    mitigation.
#   rating history   the historical rating and every re-evaluation, from the VDR
#                    ledger. The schema has a field only for completed reductions,
#                    so the full history is in providerExtensions.
#
# The schemas carry no field for the component, the CVE, the scanner check or the
# decision. Those are the joins a reader needs to trace a finding to the system,
# so each record carries them under `providerExtensions` (the schemas allow
# additional properties).
#
# Report periods (VER-RPT-PER: summarize ALL activity since the previous report):
# each VDT/AVI runs from the previous published report's end to now, and carries
# an activity summary for that period (providerExtensions.activitySummary):
# detections, evaluations, rating changes and reductions, records that stopped
# being reported, decisions recorded and closed, every scan and feed the VDR
# build read with its time, and the runtime verification run it read, linked.
#
# The MRH accumulates. A record that leaves the VDR stays in the history for
# HISTORY_DAYS with the time it stopped being reported. It gets a final
# disposition only from evidence: a closed decision that says remediated, a
# false-positive suppression of its check, or its scanner having run again over
# the same scope without reporting it. Otherwise it is recorded as no longer
# reported, with the reason (a risk-accepted suppression, or unknown), and no
# final disposition. Closed (remediated) decisions are carried in the history
# too, including those from before the pipeline's ledger began.
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
    "codeql": "GitHub CodeQL (static analysis of first-party code)",
    "opa": "OPA policy evaluation of the deployed configuration",
}
SOURCE_BY_LABEL = {v: k for k, v in SOURCES.items()}
# The detection-gate feed that shows a source's scanner ran in a build. A source
# with no feed here (OPA) never earns a disposition from coverage.
COVERAGE_FEEDS = {"grype": "grype", "dependabot": "dependabot", "checkov": "checkov",
                  "checkov-suppression": "checkov", "tfsec": "tfsec", "codeql": "codeql"}
SCAN_FEEDS = {"grype": "Grype software composition scan", "dependabot": "Dependabot alerts",
              "checkov": "Checkov IaC scan", "tfsec": "tfsec IaC scan",
              "kev": "CISA KEV catalog", "epss": "FIRST EPSS scores",
              "codeql": "CodeQL code scan", "zap-api": "OWASP ZAP authenticated API scan"}

OFFERING = Path(__file__).resolve().parent.parent / "data" / "cds" / "offering.json"


def fedramp_id(path=OFFERING):
    """The offering's FedRAMP ID (CDS-CSO-FID), stamped on every report as
    providerExtensions.fedRampId. Reads the same field as _offering.fedramp_id()
    (feat/sdr-schema); missing or empty stops the build."""
    try:
        v = json.loads(Path(path).read_text(encoding="utf-8")).get("fedramp_id")
    except (OSError, json.JSONDecodeError) as exc:
        _fail(f"{path}: unreadable ({exc.__class__.__name__})")
    if not isinstance(v, str) or not v.strip():
        _fail(f"{path}: fedramp_id is missing")
    return v


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


def _dt(value, where):
    if not isinstance(value, str):
        _fail(f"{where}: missing timestamp")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail(f"{where}: {value!r} is not an ISO 8601 timestamp")
    if dt.tzinfo is None:
        _fail(f"{where}: {value!r} has no time zone")
    return dt.astimezone(timezone.utc)


def _ts(value, where):
    return _dt(value, where).isoformat()


def _maybe_dt(value):
    """A timestamp, or a YYYY-MM-DD date read as midnight UTC; None if neither."""
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def _day(value):
    """A register date (YYYY-MM-DD) as midnight UTC, ISO 8601; None if absent."""
    dt = _maybe_dt(value)
    return dt.isoformat() if dt else None


def _description(f):
    title, desc = (f.get("title") or "").strip(), (f.get("description") or "").strip()
    if title and desc and desc != title:
        return f"{title}: {desc}"
    return title or desc


def is_accepted(f):
    disp = f.get("final_disposition") or f.get("current_disposition")
    return disp in ACCEPTED_KINDS or bool(f.get("accepted"))


# --- per-record fields --------------------------------------------------------------

def _detection(f, rec, tid):
    """(detectedAt, basis): the earliest evidence of the weakness."""
    seen = _dt(f.get("first_detected"), f"{tid}.first_detected")
    # Only a decision that names this exact record (a vulnerability ID such as
    # zap-10099, or a suppressed check) dates it. A decision about a check across
    # many resources dates the check, not a resource added after it.
    if rec and tid in _decision_claims(rec):
        known = _maybe_dt(rec.get("original_detection_date"))
        if known and known < seen:
            return known.isoformat(), (f"{rec['id']} original_detection_date: found before the "
                                       "pipeline's scanner first reported it")
        decided = _maybe_dt(rec.get("decided_on"))
        if not known and f.get("source") == "checkov-suppression" and decided and decided < seen:
            return decided.isoformat(), (f"{rec['id']} decided_on: the decision records no detection "
                                         "date, and the weakness was known when it was decided (a "
                                         "suppressed check is never reported by the scanner)")
    return seen.isoformat(), "first reported by the scanner (VDR ledger)"


def _rating_history(f, tid):
    out = []
    for h in f.get("rating_history") or []:
        if not isinstance(h, dict):
            continue
        out.append({"at": _ts(h.get("at"), f"{tid}.rating_history"), "rating": _rating(h.get("pain")),
                    "isInternetReachable": h.get("irv"), "isLikelyExploitable": h.get("lev"),
                    "reason": h.get("reason")})
    return out


def _overdue(f, rec, final):
    """overdueStatus whose explanation explains the overdue status itself."""
    over = bool(f.get("is_overdue"))
    due = f.get("remediation_due_at") or (f.get("next_reduction") or {}).get("estimated_time")
    did = rec["id"] if rec else f.get("decision_id")
    if over:
        if f.get("accepted") and f.get("accepted_at"):
            why = ("Overdue: not fully mitigated or remediated within the VER-TFR-MAV maximum "
                   f"period, which ended {f['accepted_at'][:10]}")
        elif due:
            why = f"Overdue: its remediation deadline, {due[:10]}, passed without remediation"
        else:
            why = f"Overdue: {f.get('block_reason') or 'past its deadline'}"
        if rec and rec.get("disposition") in ACCEPTED_KINDS:
            why += (f". It is still open because {did} accepts it ({rec['disposition']}, decided "
                    f"{rec.get('decided_on', 'on a date not recorded')}), so no remediation is planned")
        elif rec and rec.get("disposition") == "vendor-dependency":
            why += f". It is waiting on a vendor fix ({did})"
        elif f.get("block_reason") and due:
            why += f" ({f['block_reason']})"
        return {"isOverdue": True, "explanation": why + "."}
    if f.get("will_be_overdue") and due:
        return {"isOverdue": False,
                "explanation": f"Not yet overdue, but likely to become overdue: remediation is due {due[:10]}."}
    if final:
        return {"isOverdue": False,
                "explanation": f"Not overdue: closed as {final}{f' under {did}' if did else ''}."}
    if due:
        return {"isOverdue": False, "explanation": f"Not overdue: remediation is due {due[:10]}."}
    return {"isOverdue": False}


def _supplementary(f, rec, accepted):
    parts = []
    if rec:
        head = (f"{rec['id']} ({rec['disposition']}; decided {rec.get('decided_on', 'on a date not recorded')}"
                f"{', review by ' + rec['review_by'] if rec.get('review_by') else ''})")
        parts.append(head + ("." if accepted else f": {rec['justification'].strip()}"))
        res = (rec.get("applies_to") or {}).get("resources") or []
        if res:
            parts.append(f"Resources named by the decision: {', '.join(res)}.")
        if rec.get("remediation_plan"):
            parts.append(f"Remediation plan: {rec['remediation_plan'].strip()}")
        mit = (rec.get("vuln_fields") or {}).get("mitigation")
        if mit:
            parts.append(f"Mitigation record: {mit}.")
    m = f.get("mitigation")
    if isinstance(m, dict) and m.get("id"):
        state = "verified" if m.get("valid") else f"void ({m.get('void_reason') or 'not verified'})"
        parts.append(f"Mitigation {m['id']} ({m.get('effect')}): {state}.")
    if f.get("supplementary_info"):
        parts.append(str(f["supplementary_info"]).strip())
    return " ".join(p for p in parts if p)


def _projection(f, rec, rating, tid):
    """(projectedNextReduction, basis), or (None, None) when none is planned."""
    plan = (rec or {}).get("planned_reduction")
    if plan:
        target = _rating(plan.get("target_pain"))
        if target < rating:
            return ({"estimatedAt": _ts(_day(plan.get("date")), f"{rec['id']}.planned_reduction"),
                     "targetRating": target}, f"{rec['id']} planned_reduction")
    nxt = f.get("next_reduction")
    if nxt and nxt.get("estimated_time"):
        target = nxt.get("target_pain")
        basis = "remediation deadline (no planned reduction recorded)"
        if plan:
            basis = f"remediation deadline ({rec['id']} planned_reduction is not below the current rating)"
        # "remediated" removes the vulnerability: no impact remains (N0).
        return ({"estimatedAt": _ts(nxt["estimated_time"], f"{tid}.next_reduction"),
                 "targetRating": 0 if target == "remediated" else _rating(target)}, basis)
    return None, None


def detail(f, recs=None, accepted=False):
    """A VDR finding as a FedRAMP vulnerabilityDetail record."""
    recs = recs or {}
    tid = f.get("tracking_id")
    if not tid:
        _fail("a finding has no tracking_id")
    rec = recs.get(f.get("decision_id"))
    pain = f.get("current_pain") or f.get("pain")
    rating = _rating(pain)
    detected_at, detected_basis = _detection(f, rec, tid)
    out = {
        "providerTrackingId": tid,
        "detection": {
            "detectedAt": detected_at,
            "detectionSource": SOURCES.get(f.get("source"), f.get("source") or "unknown"),
        },
        "vulnerabilityDescription": _description(f) or tid,
        "potentialAgencyImpact": (f"Potential Agency Impact {f['impact_rationale']}"
                                  if f.get("impact_rationale") else
                                  f"Potential Agency Impact {pain} "
                                  f"(technical impact {f.get('technical_impact') or 'not rated'}; "
                                  "see VER-EVA-EPA for the N-rating scale)."),
        "evaluationCompletedAt": _ts(f.get("first_evaluated") or f.get("completed_evaluation"),
                                     f"{tid}.first_evaluated"),
        "isInternetReachable": bool(f.get("internet_reachable")),
        "isLikelyExploitable": bool(f.get("likely_exploitable")),
        "currentRating": rating,
    }
    disp = f.get("final_disposition") or f.get("current_disposition") or "open"
    final = None
    if disp in FINAL:
        final = FINAL[disp]
    elif disp == "mitigated":
        final = "Fully Mitigated" if f.get("fully_mitigated") else "Partially Mitigated"
    out["overdueStatus"] = _overdue(f, rec, final)
    supp = _supplementary(f, rec, accepted)
    if supp:
        out["supplementaryRiskInformation"] = supp
    reductions = [{"reducedAt": _ts(r.get("at"), f"{tid}.completed_reductions"), "rating": _rating(r.get("to"))}
                  for r in f.get("completed_reductions") or []]
    if reductions:
        out["painReductionEvents"] = reductions
    if final:
        out["finalDisposition"] = final
    projection_basis = None
    if final is None and not is_accepted(f):
        projection, projection_basis = _projection(f, rec, rating, tid)
        if projection:
            out["projectedNextReduction"] = projection
    ext = {
        "source": f.get("source"),
        "componentId": f.get("component_id"),
        "resource": f.get("resource") or None,
        "cve": f.get("cve"),
        "scannerCheck": f.get("tool_id"),
        "decisionId": f.get("decision_id"),
        "disposition": disp,
        "isKev": bool(f.get("is_kev")),
        "remediationDueAt": f.get("remediation_due_at"),
        "detectedAtBasis": detected_basis,
        "firstReportedAt": _ts(f.get("first_detected"), f"{tid}.first_detected"),
    }
    # VER-EVA-*: the evaluation record, the group the finding is evaluated in,
    # and the disclosure determination, as the VDR report states them.
    for k, name in (("evaluation", "evaluation"), ("group_id", "groupId"), ("group_due_at", "groupDueAt"),
                    ("evaluation_late", "evaluationLate"), ("public_disclosure", "publicDisclosure"),
                    ("accepted_basis", "acceptedBasis")):
        if f.get(k) is not None:
            ext[name] = f[k]
    if f.get("is_kev"):
        # VDR-TFR-KEV: the CISA catalog's remediation date and whether it passed.
        ext["kevDueAt"] = f.get("kev_due_at")
        ext["kevDateAdded"] = f.get("kev_date_added")
        ext["kevOverdue"] = bool(f.get("kev_overdue"))
    if f.get("affected_resources"):
        ext["affectedResources"] = list(f["affected_resources"])
    if projection_basis:
        ext["projectionBasis"] = projection_basis
    # VER-RPT-VDT asks for the historical and current ratings; the schema has a
    # field only for the current one and for completed reductions.
    if f.get("historical_pain"):
        ext["historicalRating"] = _rating(f["historical_pain"])
    history = _rating_history(f, tid)
    if history:
        ext["ratingHistory"] = history
    out["providerExtensions"] = ext
    return out


def accepted_info(f, recs):
    did = f.get("decision_id")
    why = ((recs.get(did) or {}).get("justification") or "").strip() if did else ""
    if not why and f.get("accepted") and f.get("acceptance_explanation"):
        why = f["acceptance_explanation"]
    if not why:
        _fail(f"accepted finding {f.get('tracking_id')} has no decision justification ({did or 'no decision_id'})")
    return {"vulnerabilityDetail": detail(f, recs, accepted=True), "acceptanceRationale": why}


# --- periods ------------------------------------------------------------------------

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


def activity_summary(vdr, mrh, register, frm, to):
    """VER-RPT-PER: the vulnerability detection and response activity in
    [frm, to], from the VDR report, the history and the decision register."""
    lo, hi = _dt(frm, "period.from"), _dt(to, "period.to")

    def within(value):
        dt = _maybe_dt(value)
        return bool(dt and lo <= dt <= hi)

    rows = [f for f in vdr.get("findings") or [] if isinstance(f, dict)] + \
           [r for r in vdr.get("risk_accepted") or [] if isinstance(r, dict)]
    detections = [{"providerTrackingId": f["tracking_id"], "at": f["first_detected"]}
                  for f in rows if within(f.get("first_detected"))]
    evaluations = [{"providerTrackingId": f["tracking_id"], "at": f["first_evaluated"]}
                   for f in rows if within(f.get("first_evaluated"))]
    changes = [{"providerTrackingId": f["tracking_id"], "at": h["at"], "rating": h.get("pain"),
                "reason": h.get("reason")}
               for f in rows for h in f.get("rating_history") or []
               if isinstance(h, dict) and within(h.get("at")) and h.get("reason") != "first evaluation"]
    reductions = [{"providerTrackingId": f["tracking_id"], "at": r["at"], "from": r.get("from"), "to": r.get("to")}
                  for f in rows for r in f.get("completed_reductions") or []
                  if isinstance(r, dict) and within(r.get("at"))]
    gone = [{"providerTrackingId": r["providerTrackingId"],
             "at": r["providerExtensions"]["noLongerReportedAt"],
             "finalDisposition": r.get("finalDisposition"),
             "reason": r["providerExtensions"].get("noLongerReportedReason")}
            for r in mrh.get("activeVulnerabilities") or []
            if within((r.get("providerExtensions") or {}).get("noLongerReportedAt"))]
    decided = [{"decisionId": d["id"], "on": d["decided_on"], "disposition": d["disposition"]}
               for d in register.get("decisions", []) if within(_day(d.get("decided_on")))]
    closed = [{"decisionId": d["id"], "on": d["closed_on"], "disposition": d["disposition"]}
              for d in register.get("decisions", [])
              if d.get("status") == "closed" and within(_day(d.get("closed_on")))]
    remediated = {g["providerTrackingId"] for g in gone if g["finalDisposition"] == "Remediated"} | \
                 {c["decisionId"] for c in closed}
    meth = vdr.get("methodology") or {}
    det = meth.get("detection") or {}
    scans = [{"activity": "VDR build: every finding re-evaluated (PAIN, IRV, LEV, deadlines)",
              "at": vdr.get("emitted_at"), "timeBasis": "build time", "status": "ok",
              "inPeriod": within(vdr.get("emitted_at"))}]
    for feed in det.get("feeds") or []:
        name = SCAN_FEEDS.get(feed.get("feed")) if isinstance(feed, dict) else None
        if not name:
            continue
        if feed.get("feed") in ("kev", "epss"):
            at, basis = feed.get("source_date"), "published by the source"
        else:
            at, basis = det.get("checked_at"), "run or fetched in this build (when the detection gate checked it)"
        row = {"activity": f"{name} ({feed.get('file')})", "at": at, "timeBasis": basis,
               "status": feed.get("status"), "count": feed.get("count"), "inPeriod": within(at)}
        if feed.get("feed") == "grype" and feed.get("source_date"):
            row["vulnerabilityDatabaseBuiltAt"] = feed["source_date"]
        scans.append(row)
    dast = meth.get("dast")
    if isinstance(dast, dict):
        scans.append({"activity": "OWASP ZAP dynamic scan of the site", "at": dast.get("generated_at"),
                      "timeBasis": "scan report generated", "status": dast.get("status"),
                      "count": dast.get("alerts"), "inPeriod": within(dast.get("generated_at"))})
    rt = meth.get("runtime_verification")
    runtime = None
    if isinstance(rt, dict):
        runtime = {"uri": rt.get("uri"), "signalId": rt.get("signal_id"), "emittedAt": rt.get("emitted_at"),
                   "signatureVerified": bool(rt.get("verified")), "validations": rt.get("validations"),
                   "failed": rt.get("failed"), "divergence": rt.get("divergence"),
                   "inPeriod": within(rt.get("emitted_at")),
                   "note": ("The runtime emitter publishes only its latest run; this is the run the VDR "
                            "build read. A run it replaced before this build is not retained.")}
        hist = rt.get("run_history")
        if rt.get("verified") and isinstance(hist, list) and hist:
            # The emitter retains its runs in the signed signal: every run in
            # the period is counted, not only the latest.
            runs = [r for r in hist if within(r.get("emitted_at"))]
            runtime["runsInPeriod"] = len(runs)
            runtime["failedRunsInPeriod"] = sum(1 for r in runs if r.get("failed"))
            runtime["note"] = ("Every runtime run in the period, from the run history the emitter signs into "
                               "its signal (bounded to the newest runs).")
        if not rt.get("verified"):
            runtime["note"] = f"Runtime signal not verified ({rt.get('reason')}); its results are not reported."
    in_period = [s for s in scans if s["inPeriod"]]
    run_in_period = bool(runtime and runtime["inPeriod"] and runtime["signatureVerified"])
    return {
        "period": {"from": frm, "to": to},
        "counts": {"detections": len(detections), "evaluations": len(evaluations),
                   "ratingChanges": len(changes), "reductions": len(reductions),
                   "noLongerReported": len(gone), "remediations": len(remediated),
                   "decisionsRecorded": len(decided), "decisionsClosed": len(closed),
                   "scansInPeriod": len(in_period),
                   "runtimeRunsInPeriod": (runtime["runsInPeriod"] if runtime and "runsInPeriod" in runtime
                                           else 1 if run_in_period else 0),
                   "runtimeFailuresInPeriod": (runtime["failedRunsInPeriod"] if runtime and "runsInPeriod" in runtime
                                               else (runtime["failed"] or 0) if run_in_period else 0)},
        "detections": detections, "evaluations": evaluations, "ratingChanges": changes,
        "reductions": reductions, "noLongerReported": gone, "remediations": sorted(remediated),
        "decisionsRecorded": decided, "decisionsClosed": closed, "scans": scans,
        "runtimeVerification": runtime,
    }


# --- build --------------------------------------------------------------------------

def build(vdr, register, previous_vdt, previous_avi, previous_mrh, now):
    if not isinstance(vdr, dict) or not isinstance(vdr.get("findings"), list):
        _fail("vdr-report.json has no findings list")
    recs = _decisions.records(register)
    scanner = list(vdr["findings"])
    # Suppressed checks the VDR lists as risk-accepted are accepted vulnerabilities too.
    suppressed = [dict(r, final_disposition="risk-accepted") for r in vdr.get("risk_accepted") or []]
    active = [detail(f, recs) for f in scanner if not is_accepted(f)]
    accepted = [accepted_info(f, recs) for f in scanner + suppressed if is_accepted(f)]
    times = [r["detection"]["detectedAt"] for r in active] + \
            [a["vulnerabilityDetail"]["detection"]["detectedAt"] for a in accepted]
    earliest = min(times) if times else now.isoformat()
    to = now.isoformat()
    cpo = {"certificationPackageOverviewUri": fs.CPO_URI}
    # REQ-GOV-2: like every VDR-family output, each names the method profile and
    # conformance results of the VDR report it came from.
    ext = {"fedRampId": fedramp_id(), "source": "vdr-report.json", "vdrReportId": vdr.get("report_id"),
           "ksiSignalId": vdr.get("ksi_signal_id"), "profile": (vdr.get("methodology") or {}).get("profile")}
    vdt = {"$schema": fs.stamp("vdt"), **cpo,
           "reportPeriod": {"from": _period_start(previous_vdt, earliest), "to": to},
           "vulnerabilities": active, "providerExtensions": dict(ext)}
    avi = {"$schema": fs.stamp("avi"), **cpo,
           "reportPeriod": {"from": _period_start(previous_avi, earliest), "to": to},
           "acceptedVulnerabilities": accepted, "providerExtensions": dict(ext)}
    for doc, period in ((vdt, "VDT"), (avi, "AVI")):
        if doc["reportPeriod"]["from"] > doc["reportPeriod"]["to"]:
            _fail(f"{period} period starts after it ends")
    mrh = build_history(active, accepted, previous_mrh, now, vdr=vdr, register=register)
    mrh["providerExtensions"] = {**ext, **mrh["providerExtensions"]}
    for doc in (vdt, avi):
        doc["providerExtensions"]["activitySummary"] = activity_summary(
            vdr, mrh, register, doc["reportPeriod"]["from"], doc["reportPeriod"]["to"])
    return vdt, avi, mrh


# --- history ------------------------------------------------------------------------

def _keys(rec):
    ext = rec.get("providerExtensions") or {}
    return {k for k in (rec.get("providerTrackingId"), ext.get("scannerCheck"), ext.get("cve")) if k}


def _decision_claims(d):
    a = d.get("applies_to") or {}
    return set(a.get("check_ids") or []) | set(a.get("vuln_ids") or [])


def _coverage(source, vdr, last_reported):
    """Evidence that `source`'s scanner ran again over the same scope after the
    record was last reported, or None."""
    meth = (vdr or {}).get("methodology") or {}
    if source == "zap":
        dast = meth.get("dast") or {}
        gen, last = _maybe_dt(dast.get("generated_at")), _maybe_dt(last_reported)
        if dast.get("status") == "ok" and gen and last and gen > last:
            return f"the ZAP scan of {gen.isoformat()} ran after it was last reported and does not report it"
        return None
    feed = COVERAGE_FEEDS.get(source)
    det = meth.get("detection") or {}
    rows = [r for r in det.get("feeds") or [] if isinstance(r, dict) and r.get("feed") == feed]
    if feed and det.get("checked_at") and rows and all(r.get("status") == "ok" for r in rows):
        return (f"{feed} ran in the VDR build checked {det['checked_at']} (status ok) "
                "and no longer reports it")
    return None


def _disposition_from_evidence(rec, vdr, register, last_reported):
    """(finalDisposition or None, reason, basis) for a record that left the VDR."""
    ext = rec.get("providerExtensions") or {}
    keys = _keys(rec)
    did = ext.get("decisionId")
    for d in (register or {}).get("decisions", []):
        if d.get("status") == "closed" and (d["id"] == did or keys & _decision_claims(d)):
            return ("Remediated", "remediated",
                    f"{d['id']} closed as remediated on {d.get('closed_on', 'a date not recorded')}")
    check = ext.get("scannerCheck")
    for section, final, reason in (("false_positives", "False Positive", "false-positive"),
                                   ("risk_accepted", None, "suppressed")):
        for s in (vdr or {}).get(section) or []:
            if (isinstance(s, dict) and check and s.get("tool_id") == check
                    and s.get("tracking_id") != rec.get("providerTrackingId")):
                return final, reason, (f"its check {check} is now suppressed in .checkov.yaml "
                                       f"({s.get('decision_id') or 'no decision'}, {s.get('current_disposition')})")
    source = ext.get("source") or SOURCE_BY_LABEL.get((rec.get("detection") or {}).get("detectionSource"))
    if source == "checkov-suppression":
        again = [f["tracking_id"] for f in (vdr or {}).get("findings") or []
                 if isinstance(f, dict) and check and f.get("tool_id") == check]
        if again:
            return None, "reported-again", (f"its check {check} is no longer suppressed and the scanner "
                                            f"reports it again as {', '.join(sorted(again))}")
    covered = _coverage(source, vdr, last_reported)
    if covered:
        return "Remediated", "remediated", covered
    return None, "unknown", ("no evidence of why: no closed decision names it, no suppression covers it, "
                             "and its scanner is not shown to have run over it again since it was last reported")


_BACKFILL_DETECTION = (
    ("original_detection_date", "original_detection_date"),
    ("decided_on", "decided_on: no detection date is recorded; known by the decision date"),
    ("closed_on", "closed_on: neither a detection nor a decision date is recorded; detected no later "
                  "than it was closed"),
)
_BACKFILL_SOURCE = {"original_risk_rating": "originalRiskRating", "adjusted_risk_rating": "adjustedRiskRating",
                    "identifier": "sourceIdentifier"}


def _backfill(d, now):
    """A closed (remediated) decision as a history record."""
    at, basis = now.isoformat(), f"{d['id']}: no date is recorded"
    for field, why in _BACKFILL_DETECTION:
        if _day(d.get(field)):
            at, basis = _day(d[field]), f"{d['id']} {why}"
            break
    src = d.get("source") or {}
    ext = {"decisionId": d["id"], "disposition": "remediated", "backfilledFromDecision": True,
           "remediatedOn": d.get("closed_on"), "detectedAtBasis": basis,
           "dispositionBasis": f"{d['id']} closed as remediated on {d.get('closed_on', 'a date not recorded')}",
           "affectedResources": list((d.get("applies_to") or {}).get("resources") or [])}
    if d.get("former_id"):
        ext["formerId"] = d["former_id"]
    if d.get("remediation_plan"):
        ext["remediationPlan"] = d["remediation_plan"]
    ext.update({out: src[k] for k, out in _BACKFILL_SOURCE.items() if src.get(k)})
    return {"providerTrackingId": d["id"],
            "detection": {"detectedAt": at, "detectionSource": src.get("detector") or "not recorded"},
            "vulnerabilityDescription": d["title"],
            "supplementaryRiskInformation": d["justification"].strip(),
            "finalDisposition": "Remediated",
            "providerExtensions": ext}


def build_history(active, accepted, previous, now, vdr=None, register=None):
    """VER-TFR-MRH: every current record; every record that left the VDR within
    HISTORY_DAYS, with a final disposition only where evidence gives one; and
    every closed (remediated) decision closed within HISTORY_DAYS."""
    cutoff = now - timedelta(days=HISTORY_DAYS)
    current = {r["providerTrackingId"] for r in active} | \
              {a["vulnerabilityDetail"]["providerTrackingId"] for a in accepted}
    carried = []
    prev = previous or {}
    for rec in (prev.get("activeVulnerabilities") or []) + \
               [a.get("vulnerabilityDetail") for a in prev.get("acceptedVulnerabilities") or []]:
        if not isinstance(rec, dict) or rec.get("providerTrackingId") in current:
            continue
        ext = dict(rec.get("providerExtensions") or {})
        if ext.get("backfilledFromDecision"):
            continue  # rebuilt from the register below
        gone = ext.get("noLongerReportedAt") or now.isoformat()
        if (_maybe_dt(gone) or now) < cutoff:
            continue
        closed = dict(rec)
        closed.pop("projectedNextReduction", None)
        ext["noLongerReportedAt"] = gone
        ext.setdefault("lastReportedAt", prev.get("generatedAt"))
        final = closed.get("finalDisposition")
        if final and (ext.get("dispositionBasis") or final != "Remediated"):
            # Settled: the disposition it had when last reported, or one already
            # earned from evidence.
            ext.setdefault("dispositionBasis", "its final disposition when it was last reported")
            ext.setdefault("noLongerReportedReason", "closed")
        else:
            # Re-decided each run until evidence settles it (a closed decision
            # may come later). A Remediated with no evidence is withdrawn.
            closed.pop("finalDisposition", None)
            final, reason, basis = _disposition_from_evidence(closed, vdr, register, ext["lastReportedAt"])
            ext["noLongerReportedReason"] = reason
            ext.pop("noLongerReportedBasis", None)
            if final:
                closed["finalDisposition"] = final
                ext["dispositionBasis"] = basis
            else:
                ext["noLongerReportedBasis"] = basis
        if closed.get("finalDisposition"):
            closed["overdueStatus"] = {"isOverdue": False, "explanation":
                                       f"Not overdue: no longer reported; {closed['finalDisposition']}."}
        carried.append({**closed, "providerExtensions": ext})
    linked = {(r.get("providerExtensions") or {}).get("decisionId") for r in carried + active} | \
             {(a["vulnerabilityDetail"].get("providerExtensions") or {}).get("decisionId") for a in accepted}
    claimed = set().union(*(_keys(r) for r in carried))
    backfilled = []
    for d in (register or {}).get("decisions", []):
        if d.get("status") != "closed" or d["id"] in linked or _decision_claims(d) & claimed:
            continue
        closed_on = _maybe_dt(d.get("closed_on"))
        if closed_on and closed_on < cutoff:
            continue
        backfilled.append(_backfill(d, now))
    return {"$schema": fs.stamp("mrh"), "certificationPackageOverviewUri": fs.CPO_URI,
            "generatedAt": now.isoformat(),
            "activeVulnerabilities": active + sorted(carried + backfilled, key=lambda r: r["providerTrackingId"]),
            "acceptedVulnerabilities": accepted,
            "providerExtensions": {
                "retention": (f"Records that leave the VDR stay {HISTORY_DAYS} days with the time they stopped "
                              "being reported (noLongerReportedAt). A final disposition is set only from "
                              "evidence (dispositionBasis): a closed decision, a false-positive suppression, "
                              "or the scanner running again without reporting it. Otherwise "
                              "noLongerReportedReason says why it is not reported, or 'unknown', and no final "
                              "disposition is given. Closed (remediated) decisions are included "
                              "(backfilledFromDecision) for the same period from their closing date.")}}


# --- markdown -----------------------------------------------------------------------

def _cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_activity(summary):
    c = summary["counts"]
    out = ["## Activity this period", "",
           f"{summary['period']['from']} to {summary['period']['to']}", "",
           f"- Detections: {c['detections']}; evaluations: {c['evaluations']}; rating changes: "
           f"{c['ratingChanges']}; reductions: {c['reductions']}",
           f"- No longer reported: {c['noLongerReported']}; remediations: {c['remediations']}; "
           f"decisions recorded: {c['decisionsRecorded']}; decisions closed: {c['decisionsClosed']}",
           "", "| Scan or feed | Time | Status | Count | In period |", "|---|---|---|---|---|"]
    for s in summary["scans"]:
        out.append(f"| {_cell(s['activity'])} | {s.get('at') or 'not recorded'} ({s['timeBasis']}) | "
                   f"{s.get('status')} | {'' if s.get('count') is None else s['count']} | "
                   f"{'yes' if s['inPeriod'] else 'no'} |")
    rt = summary.get("runtimeVerification")
    out.append("")
    if rt:
        out.append(f"Runtime verification: [{rt['uri']}]({rt['uri']}) emitted {rt.get('emittedAt')}, "
                   f"{rt.get('validations')} validations, {rt.get('failed')} failed, divergence "
                   f"{rt.get('divergence')}; {'in' if rt['inPeriod'] else 'not in'} this period. {rt['note']}")
    else:
        out.append("Runtime verification: not recorded by the VDR build.")
    return out


def render_markdown(title, rule, records, accepted=False, summary=None):
    out = [f"# {title}", "", f"_FedRAMP {rule}. Source of truth: the signed JSON beside this file._", ""]
    if summary:
        out += render_activity(summary) + ["", "## Vulnerabilities", ""]
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
            n=d["currentRating"], od="yes" if d["overdueStatus"]["isOverdue"] else "no", last=_cell(last)))
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
        render_markdown("Vulnerability Detail Report", "VER-RPT-VDT", vdt["vulnerabilities"],
                        summary=vdt["providerExtensions"]["activitySummary"]) + "\n")
    (out / AVI_OUT.replace(".json", ".md")).write_text(
        render_markdown("Accepted Vulnerability Info", "VER-RPT-AVI", avi["acceptedVulnerabilities"],
                        accepted=True, summary=avi["providerExtensions"]["activitySummary"]) + "\n")
    print(f"CR26 vulnerability reports: VDT {len(vdt['vulnerabilities'])}, "
          f"AVI {len(avi['acceptedVulnerabilities'])}, history {len(mrh['activeVulnerabilities'])} active + "
          f"{len(mrh['acceptedVulnerabilities'])} accepted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
