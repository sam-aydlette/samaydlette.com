#!/usr/bin/env python3
# =============================================================================
# SECURITY DECISION RECORD BUILDER  (CR26 SDR — the 20x SSP replacement)
# =============================================================================
# CR26 replaces the traditional System Security Plan with a persistently
# maintained Security Decision Record (SDR-CSO-FRR): for each applicable FedRAMP
# rule, an explanation of how it is followed, plus verification, validation,
# independent verification, independent validation, responses to assessor
# comments, and rule-specific artifacts. SDR-CSO-MTD carries version + last
# update + source; the 20x extension SDR-CSX-KSI carries per-KSI summaries, and
# SDR-CSX-KMT (Class C) carries metric summaries over 30 days / up to a year /
# all daily metric data.
#
# This is the *20x-paradigm* artifact. The Rev5-paradigm artifact, the OSCAL
# System Security Plan (scripts/build-oscal-ssp.py), is STILL generated from the
# same control hub: one inventory yields conformant evidence in both shapes,
# which is the whole point. The SDR derives its per-KSI records from the KSI
# catalog and the OSCAL SSP, so the two never disagree.
#
#   build-sdr.py --ssp oscal-ssp.json --catalog schemas/ksi-catalog.json \
#       --ksi-signal ksi-signal.json --vdr vdr-report.json --previous-sdr prev.json
# =============================================================================

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HISTORY_DAYS = 366  # SDR-CSX-KMT: all daily metric data up to the past year

NA = "N/A — self-attested proof of concept; no FedRAMP Recognized independent assessment service engaged (IVV is not applicable to an unsponsored system)."


def _prop(o, name):
    for p in o.get("props", []) or []:
        if p.get("name") == name:
            return p.get("value")
    return None


def _control_map(ssp):
    """control_id -> {status, origination} from the OSCAL SSP."""
    m = {}
    for ir in ssp["system-security-plan"]["control-implementation"]["implemented-requirements"]:
        m[ir["control-id"]] = {"status": _prop(ir, "implementation-status"),
                               "origination": _prop(ir, "control-origination")}
    return m


def build_records(catalog, cmap):
    """One SDR-CSO-FRR record per in-scope KSI, derived from its controls' SSP state."""
    records = []
    for fam in catalog.get("KSI", {}).values():
        for ind in fam.get("indicators", []) or []:
            if ind.get("retired"):
                continue
            controls = []
            impl = inh = na = 0
            for c in ind.get("controls", []) or []:
                cid = c.get("control_id")
                st = cmap.get(cid, {})
                controls.append({"control_id": cid, "status": st.get("status"),
                                 "origination": st.get("origination")})
                o = st.get("origination")
                if st.get("status") == "not-applicable":
                    na += 1
                elif o == "inherited" or o == "shared":
                    inh += 1
                else:
                    impl += 1
            if controls:
                expl = (f"Satisfied through {len(controls)} NIST 800-53 control(s) "
                        f"({impl} system-implemented, {inh} inherited/shared, {na} not-applicable); "
                        f"see the OSCAL SSP for each control's implementation statement.")
            else:
                expl = ("Process/organizational indicator with no direct 800-53 control mapping; "
                        "satisfied at the operator level and documented in the linked policy.")
            records.append({
                "rule_id": ind["id"],
                "statement": ind.get("statement", ""),
                "controls": controls,
                "explanation": expl,
                "verification": ("Automated: the deploy-time OPA gate and the per-deploy KSI signal "
                                 "record the implementing controls; the daily runtime emitter "
                                 "re-validates the live configuration against the same compiled policy."),
                "validation": ("Effectiveness reviewed continuously by the daily runtime revalidation "
                               "(drift detector) and annually by the structural security review."),
                "independent_verification": NA,
                "independent_validation": NA,
                "assessor_comment_responses": [],
                "artifacts": ["/.well-known/ksi-signal.json", "/.well-known/oscal-ssp.json"],
            })
    return records


def build_metrics(records, controls_in_scope, vdr, signal, history, now):
    """SDR-CSX-KMT: metric snapshot + appended daily history (toward one year)."""
    sig_vals = signal.get("validations", []) if signal else []
    failing = sum(1 for v in sig_vals if v.get("result") == "fail")
    vsum = (vdr or {}).get("summary", {})
    today = now.date().isoformat()
    point = {
        "date": today,
        "ksi_in_scope": len(records),
        "controls_in_scope": controls_in_scope,
        "signal_validations": len(sig_vals),
        "signal_failing": failing,
        "vdr_total": vsum.get("total_findings", 0),
        "vdr_blocking": vsum.get("blocking", 0),
        "vdr_accepted": vsum.get("risk_accepted", 0),
        "vdr_kev": vsum.get("kev", 0),
    }
    history = [h for h in history if h.get("date") != today]
    history.append(point)
    history = sorted(history, key=lambda h: h.get("date", ""))[-HISTORY_DAYS:]
    last30 = history[-30:]

    def _summ(window):
        if not window:
            return {}
        return {"days": len(window),
                "max_blocking": max(h.get("vdr_blocking", 0) for h in window),
                "max_failing_validations": max(h.get("signal_failing", 0) for h in window),
                "current_accepted": window[-1].get("vdr_accepted", 0)}

    return {
        "current": point,
        "summary_30d": _summ(last30),
        "summary_1y": _summ(history),
        "daily_metric_data": history,   # all daily points up to a year (SDR-CSX-KMT)
        "note": ("Daily metric history accumulates one point per deploy/day; the full "
                 "one-year window builds over time from the first published SDR."),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ssp", default="oscal-ssp.json")
    ap.add_argument("--catalog", default="schemas/ksi-catalog.json")
    ap.add_argument("--ksi-signal", default="ksi-signal.json")
    ap.add_argument("--vdr", default="vdr-report.json")
    ap.add_argument("--profile", default="../data/system-profile.json")
    ap.add_argument("--previous-sdr", default=None)
    ap.add_argument("--output", default="security-decision-record.json")
    ap.add_argument("--md-output", default="security-decision-record.md")
    a = ap.parse_args()

    now = datetime.now(timezone.utc)
    ssp = json.loads(Path(a.ssp).read_text())
    catalog = json.loads(Path(a.catalog).read_text())
    signal = json.loads(Path(a.ksi_signal).read_text()) if Path(a.ksi_signal).exists() else {}
    vdr = json.loads(Path(a.vdr).read_text()) if Path(a.vdr).exists() else {}
    prof = json.loads(Path(a.profile).read_text()) if Path(a.profile).exists() else {}
    history = []
    if a.previous_sdr and Path(a.previous_sdr).exists():
        try:
            history = json.loads(Path(a.previous_sdr).read_text()).get("metrics", {}).get("daily_metric_data", []) or []
        except Exception:
            history = []

    cmap = _control_map(ssp)
    records = build_records(catalog, cmap)
    metrics = build_metrics(records, len(cmap), vdr, signal, history, now)

    sdr = {
        "record_type": "security-decision-record",
        "schema": "fedramp-security-decision-record-schema-2026-06-24.json",
        "note": "The 20x-paradigm replacement for the System Security Plan. The Rev5 OSCAL SSP "
                "is still generated from the same control hub (paradigm-agnostic automation).",
        # SDR-CSO-MTD
        "metadata": {
            "version": "live (regenerated each deploy)",
            "last_updated": now.isoformat(),
            "source_of_update": "scripts/build-sdr.py, derived from the canonical KSI inventory and OSCAL SSP",
        },
        "class": prof.get("fedramp_class"),
        "impact_level": prof.get("impact_level"),
        "ksi_signal_id": (signal or {}).get("signal_id"),
        "rule_records": records,                 # SDR-CSO-FRR + SDR-CSX-KSI
        "metrics": metrics,                      # SDR-CSX-KMT
    }
    Path(a.output).write_text(json.dumps(sdr, indent=2) + "\n")
    if a.md_output:
        Path(a.md_output).write_text(render_markdown(sdr) + "\n")
    print(f"security-decision-record: {len(records)} per-KSI rule records; "
          f"{metrics['current']['controls_in_scope']} controls in scope; "
          f"{len(metrics['daily_metric_data'])} day(s) of metric history")
    return 0


def render_markdown(sdr):
    m = sdr["metadata"]
    cur = sdr["metrics"]["current"]
    out = ["# Security Decision Record", "",
           f"_{sdr['note']}_", "",
           f"- **Class:** {sdr['class']} | **Impact:** {sdr['impact_level']}",
           f"- **Version:** {m['version']} | **Last updated:** {m['last_updated']}",
           f"- **Source:** {m['source_of_update']}",
           f"- **Bound to inventory signal:** `{sdr['ksi_signal_id']}`",
           "",
           "## Metrics (SDR-CSX-KMT)", "",
           f"- KSIs in scope: **{cur['ksi_in_scope']}** | Controls in scope: **{cur['controls_in_scope']}**",
           f"- Signal validations: {cur['signal_validations']} ({cur['signal_failing']} failing)",
           f"- Vulnerabilities: {cur['vdr_total']} total, {cur['vdr_blocking']} blocking, "
           f"{cur['vdr_accepted']} accepted, {cur['vdr_kev']} KEV",
           f"- Daily metric history: {len(sdr['metrics']['daily_metric_data'])} day(s) on record "
           "(builds toward one year)",
           "",
           "## Per-rule records (SDR-CSO-FRR / SDR-CSX-KSI)", "",
           "Independent verification and validation are N/A for this self-attested system "
           "(no FedRAMP Recognized assessor). Verification and validation below are the "
           "provider-side evidence an assessor would consume.", "",
           "| KSI | Controls | Explanation |", "|---|---|---|"]
    for r in sdr["rule_records"]:
        cids = ", ".join(c["control_id"] for c in r["controls"]) or "—"
        out.append("| `{rid}` | {cids} | {ex} |".format(
            rid=r["rule_id"], cids=cids, ex=r["explanation"].replace("|", "\\|")))
    out += ["", "---", "_Source of truth: the signed `security-decision-record.json`. The Rev5 "
            "OSCAL SSP at `/.well-known/oscal-ssp.json` is the same evidence in the Rev5 shape._"]
    return "\n".join(out)


if __name__ == "__main__":
    sys.exit(main())
