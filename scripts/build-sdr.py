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
# It carries both views CR26 defines over the same rule families: per KSI
# (SDR-CSX-KSI, the 20x record) and per applicable Rev5 control (SDR-CSF-CTF,
# the Rev5 record, in rev5_controls). Both come from the control projection
# (scripts/_controls.py) computed from the canonical inventory and the KSI
# catalog, so they cannot disagree. The OSCAL SSP that used to carry the
# per-control statements is retired (CR26); this record replaces it.
#
#   build-sdr.py --catalog schemas/ksi-catalog.json --ksi-signal ksi-signal.json \
#       --vdr vdr-report.json --previous-sdr prev.json
# =============================================================================

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Shared generator helpers. The insert is __file__-relative, so this script stays
# runnable standalone from any working directory (see scripts/_common.py).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import prop  # noqa: E402
import _assessor  # noqa: E402
import _controls  # noqa: E402

HISTORY_DAYS = 366  # SDR-CSX-KMT: all daily metric data up to the past year

NA = "N/A — self-attested proof of concept; no FedRAMP Recognized independent assessment service engaged (IVV is not applicable to an unsponsored system)."


def _control_map(irs):
    """control_id -> {status, origination} from the control projection."""
    m = {}
    for ir in irs:
        m[ir["control-id"]] = {"status": prop(ir, "implementation-status"),
                               "origination": prop(ir, "control-origination")}
    return m


def build_records(catalog, cmap):
    """One SDR-CSO-FRR record per in-scope KSI, derived from its controls' projected state."""
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
                        f"see rev5_controls in this record for each control's implementation statement.")
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
                "artifacts": ["/.well-known/ksi-signal.json", "/.well-known/security-decision-record.json"],
            })
    return records


# CR26 implementation-status vocabulary (SDR-CSF-CTF) for the projection's
# OSCAL tokens.
REV5_STATUS = {"implemented": "Implemented", "partial": "Partially Implemented", "planned": "Planned",
               "alternative": "Alternative Implementation", "not-applicable": "Not Applicable"}


def build_rev5_controls(irs, catalog):
    """SDR-CSF-CTF: a summary for each applicable Rev5 control: parameter values,
    implementation status, the mechanisms (the projection's statement, including
    any inheritance), verification, validation, independent verification and
    validation, and control-specific artifacts. Verification and validation
    point at the records of the KSIs that claim the control rather than
    restating them; a control no KSI claims says so."""
    ksis_by_control, _ = _controls.contributing_ksis(catalog)
    out = []
    for ir in irs:
        cid = ir["control-id"]
        status = prop(ir, "implementation-status")
        origination = prop(ir, "control-origination")
        ksis = sorted(ksis_by_control.get(cid, ()))
        if status == "not-applicable":
            verification = validation = "Not applicable."
        elif origination == "inherited":
            verification = validation = ("Inherited from AWS under its FedRAMP certification "
                                         "(leveraged authorization); verified and validated there.")
        elif ksis:
            verification = validation = ("See the rule records (rule_records) of the contributing KSIs: "
                                         + ", ".join(ksis) + ".")
        else:
            verification = ("No KSI claims this control; the statement is maintained in the control "
                             "projection (scripts/_controls.py, data/component-definitions/) and "
                             "reviewed with it.")
            validation = "No automated validation."
        remarks = [ir["statements"][0]["remarks"]] if ir.get("statements") else []
        live = prop(ir, "implementation-status-remarks")
        out.append({
            "control_id": cid,
            "implementation_status": REV5_STATUS.get(status, status),
            "origination": origination,
            "parameters": [{"param_id": sp["param-id"], "values": sp.get("values", [])}
                           for sp in ir.get("set-parameters", [])],
            "mechanisms": " ".join(remarks + ([live] if live else [])),
            "contributing_ksis": ksis,
            "verification": verification,
            "validation": validation,
            "independent_verification": NA,
            "independent_validation": NA,
            "assessor_comment_responses": [],
            "artifacts": [lk["href"] for lk in ir.get("links", [])],
        })
    return out


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
    ap.add_argument("--catalog", default="schemas/ksi-catalog.json")
    ap.add_argument("--ksi-signal", default="ksi-signal.json")
    ap.add_argument("--vdr", default="vdr-report.json")
    ap.add_argument("--profile", default="../data/system-profile.json")
    ap.add_argument("--previous-sdr", default=None)
    ap.add_argument("--output", default="security-decision-record.json")
    ap.add_argument("--md-output", default="security-decision-record.md")
    ap.add_argument("--assessor-records", default=str(_assessor.RECORDS_DIR),
                    help="directory of signed assessor records (REQ-ASR-1); empty = no assessor record")
    ap.add_argument("--assessor-identity", default=str(_assessor.IDENTITY_PATH),
                    help="pinned assessor identity the records must verify against")
    a = ap.parse_args()

    now = datetime.now(timezone.utc)
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

    # The projection needs the inventory: without it there is no control state
    # to record, so a missing signal stops the build (fail-closed).
    irs = _controls.load(a.ksi_signal, a.catalog)
    cmap = _control_map(irs)
    records = build_records(catalog, cmap)
    # REQ-ASR-1: assessor records enter only through the signed port; any record
    # that does not verify fails the build. They are carried verbatim.
    assessor_records = _assessor.load_records(a.assessor_records, a.assessor_identity)
    assessor_block = _assessor.attach(records, assessor_records)
    metrics = build_metrics(records, len(cmap), vdr, signal, history, now)

    sdr = {
        "record_type": "security-decision-record",
        "schema": "fedramp-security-decision-record-schema-2026-06-24.json",
        "note": "The CR26 replacement for the System Security Plan: per-KSI records (20x) and "
                "per-Rev5-control records (rev5_controls), both from one control projection.",
        # SDR-CSO-MTD
        "metadata": {
            "version": "live (regenerated each deploy)",
            "last_updated": now.isoformat(),
            "source_of_update": "scripts/build-sdr.py, derived from the canonical KSI inventory and the control projection",
        },
        "class": prof.get("fedramp_class"),
        "impact_level": prof.get("impact_level"),
        "ksi_signal_id": (signal or {}).get("signal_id"),
        "rule_records": records,                 # SDR-CSO-FRR + SDR-CSX-KSI
        "rev5_controls": build_rev5_controls(irs, catalog),   # SDR-CSF-CTF
        "metrics": metrics,                      # SDR-CSX-KMT
        # REQ-ASR-1: verified, signed assessor records not tied to one rule, and
        # the status ("no assessor record" when none exist).
        "assessor_records": assessor_block,
    }
    _assessor.verify_output(sdr, assessor_records)  # T74: output text == signed text
    Path(a.output).write_text(json.dumps(sdr, indent=2) + "\n")
    if a.md_output:
        Path(a.md_output).write_text(render_markdown(sdr) + "\n")
    print(f"security-decision-record: {len(records)} per-KSI rule records; "
          f"{metrics['current']['controls_in_scope']} controls in scope; "
          f"{len(metrics['daily_metric_data'])} day(s) of metric history")
    return 0


def _assessor_lines(sdr):
    block = sdr.get("assessor_records") or {"status": _assessor.NO_RECORD, "records": []}
    entries = list(block.get("records", []))
    for r in sdr["rule_records"]:
        entries += [dict(e, rule_id=r["rule_id"]) for e in r.get("assessor_comment_responses", [])]
    if not entries:
        return ["**Assessor records:** No assessor record. Nothing on this page was written "
                "or signed by an assessor."]
    out = [f"**Assessor records:** {block['status']}. Each is quoted verbatim from the "
           "assessor's signed record; the signature is in the JSON."]
    for e in sorted(entries, key=lambda e: e["record_id"]):
        rule = f" (`{e['rule_id']}`)" if e.get("rule_id") else ""
        out.append(f"- `{e['record_id']}`{rule}, {e['kind']}, {e['assessor']['organization']}, "
                   f"{e['issued_at']}: > {e['text']}")
    return out


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
           *_assessor_lines(sdr), "",
           "| KSI | Controls | Explanation |", "|---|---|---|"]
    for r in sdr["rule_records"]:
        cids = ", ".join(c["control_id"] for c in r["controls"]) or "—"
        out.append("| `{rid}` | {cids} | {ex} |".format(
            rid=r["rule_id"], cids=cids, ex=r["explanation"].replace("|", "\\|")))
    rc = sdr.get("rev5_controls", [])
    by_status = {}
    for c in rc:
        by_status[c["implementation_status"]] = by_status.get(c["implementation_status"], 0) + 1
    out += ["", "## Rev5 controls (SDR-CSF-CTF)", "",
            f"{len(rc)} controls, each with its parameter values, implementation status, mechanisms, "
            "verification and validation in `rev5_controls` of the JSON record. By status: "
            + (", ".join(f"{k} {v}" for k, v in sorted(by_status.items())) or "none") + "."]
    out += ["", "---", "_Source of truth: the signed `security-decision-record.json`._"]
    return "\n".join(out)


if __name__ == "__main__":
    sys.exit(main())
