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
import importlib.util
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
import _fedramp_schema  # noqa: E402
import _frr  # noqa: E402
import _ksi_methods  # noqa: E402
import _rules  # noqa: E402
import _triage  # noqa: E402

HISTORY_DAYS = 366  # SDR-CSX-KMT: all daily metric data up to the past year

REGRESSION_POLICY = Path(__file__).resolve().parent.parent / "policies" / "compliance" / "regression.rego"
NO_IVV = "None performed. Independent verification and validation are Impractical here: one-person, no-budget."


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
                expl = (f"Maps to {len(controls)} NIST 800-53 control(s) "
                        f"({impl} system-implemented, {inh} inherited/shared, {na} not-applicable); "
                        f"see rev5_controls in this record for each control's implementation statement.")
            else:
                expl = ("Process/organizational indicator with no direct 800-53 control mapping; "
                        "its status is in keySecurityIndicators.")
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
                "independent_verification": NO_IVV,
                "independent_validation": NO_IVV,
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
            "independent_verification": NO_IVV,
            "independent_validation": NO_IVV,
            "assessor_comment_responses": [],
            "artifacts": [lk["href"] for lk in ir.get("links", [])],
        })
    return out


SITE = "https://samaydlette.com"
# The FedRAMP status enum has no Not Applicable; our status rides along in
# `statusDetail` on every item (the schema allows the extension).
FRR_FEDRAMP_STATUS = {"Implemented": "Implemented", "Not Demonstrated": "Not Implemented",
                      "Impractical": "Not Implemented"}
STAGE_SOURCE = {"plan": "/.well-known/ksi-signal.json", "deploy": "/.well-known/ksi-signal.json",
                "live": "/.well-known/ksi-signal-runtime.json", "nightly": "/.well-known/vdr-status.json"}


NOT_FOLLOWED_RISK = ("Resulting risk to customers: this system has no agency customers or federal data, so no agency "
                     "carries this risk. A real customer would lose the assurance this rule provides.")
NOT_APPLICABLE_RISK = "Resulting risk to customers: none, because the rule's trigger cannot happen in this system."
NO_INDEPENDENT_WORK = ("No independent verification or validation was performed (cost $0), so there are no assessor "
                       "comments to respond to.")


def _frr_item(rec, rule):
    st = rec["status"]
    if st == "Implemented":
        text = rec["implementation"]
    elif st == "Not Demonstrated":
        text = f"Not Demonstrated: {rec['not_demonstrated']}"
    elif st == "Impractical":
        imp = rec["impractical"]
        text = (f"Impractical ({', '.join(imp.get('reasons', []))}): {imp.get('why', '')}"
                + (f" Cost: {imp['cost']}" if imp.get("cost") else "")
                + (f" Built anyway: {imp['built']}" if imp.get("built") else ""))
    else:
        text = f"Not Applicable: {rec['not_applicable']}"
    if st != "Implemented":
        text += f" {NOT_APPLICABLE_RISK if st == 'Not Applicable' else NOT_FOLLOWED_RISK}"
    accepted = rec.get("approval") or rec.get("acceptance")
    item = {"frrID": rec["frr_id"], "frrImplementation": [text],
            "frrValidation": [f"{e['kind']}: {e['ref']}" for e in rec.get("evidence", [])]
            + ([] if st == "Implemented" else
               [f"Reason accepted by a senior official: {accepted['by']}, {accepted['on']}." if accepted
                else "The reason has not been accepted by a senior official."]),
            "frrAssessment": [NO_INDEPENDENT_WORK],
            "statusDetail": {"status": st, "force": rule["force"],
                             "approved": bool(rec.get("approval")) if st in ("Impractical", "Not Applicable") else None}}
    if st in FRR_FEDRAMP_STATUS:
        item["frrImplementationStatus"] = FRR_FEDRAMP_STATUS[st]
    return item


def _ksi_item(kid, res, methods_by_key):
    st = res["status"]
    item = {"ksiId": kid, "ksiImplementation": [], "ksiValidation": [], "ksiAssessment": [
                "No independent assessment: this system has no assessor."],
            "ksiTests": [f"{m['method']}@{m['stage']}" for m in res["methods"]],
            "ksiEvidence": [{"evidenceType": "Report", "evidenceLocation": SITE + loc,
                             "evidenceDescription": "Published results this KSI's methods are counted from"}
                            for loc in sorted({STAGE_SOURCE[m["stage"]] for m in res["methods"]})],
            "statusDetail": {"status": st, "passing": res["passing"], "failing": res["failing"]}}
    if st == "Not Applicable":
        item["ksiImplementation"].append("Not Applicable (approved by the operator); see data/ksi-applicability.json.")
        return item
    n = res["passing"]
    item["ksiImplementationStatus"] = ("Implemented" if st == "Implemented"
                                       else "Partially Implemented" if n == 1 and not res["failing"] else "Not Implemented")
    item["ksiImplementation"].append(
        f"{n} passing automated method(s); Class C needs two (FRC-CSX-VVK)."
        + (f" Failing: {', '.join(res['failing'])}." if res["failing"] else ""))
    for m in res["methods"]:
        key = m["method"].split(":", 1)[1]
        what = (methods_by_key[key]["measure"] if m["method"].startswith("check:") and key in methods_by_key
                else f"OPA rule {key} evaluated the resources it governs")
        item["ksiValidation"].append(f"{m['method']}@{m['stage']} ({'pass' if m['passed'] else 'FAIL'}): {what}")
    return item


def build_fedramp(frr_doc, applicable, ksi_result, methods):
    """The FedRAMP-shaped part of the SDR, validated against FedRAMP's schema."""
    by_key = {m["key"]: m for m in methods}
    doc = {
        "$schema": _fedramp_schema.BASES[0] + _fedramp_schema.SCHEMAS["sdr"],
        "certificationPackageOverviewUri": _fedramp_schema.CPO_URI,
        "fedRampRequirements": [_frr_item(r, applicable[r["frr_id"]]) for r in frr_doc["records"]],
        "keySecurityIndicators": [_ksi_item(k, v, by_key) for k, v in sorted(ksi_result["ksis"].items())],
    }
    errors = _fedramp_schema.validate(doc, "sdr")
    if errors:
        sys.exit("build-sdr: the FedRAMP section does not match FedRAMP's schema: " + "; ".join(errors[:10]))
    return doc


def status_summary(frr_doc, applicable, ksi_result):
    by = {}
    for v in ksi_result["ksis"].values():
        by[v["status"]] = by.get(v["status"], 0) + 1
    return {"rules": _frr.summary(frr_doc, applicable),
            "ksis": {"total": len(ksi_result["ksis"]), "by_status": dict(sorted(by.items())),
                     "short_of_two_methods": ksi_result["short"],
                     # Anything not verified is a finding (a check that did not
                     # run, a rule with nothing to evaluate, a failed method).
                     "findings": ksi_result["findings"]}}


def _statuses(doc):
    """{"rule": {id: status}, "ksi": {id: status}} from an SDR's FedRAMP section."""
    return {"rule": {i["frrID"]: (i.get("statusDetail") or {}).get("status") for i in doc.get("fedRampRequirements") or []},
            "ksi": {i["ksiId"]: (i.get("statusDetail") or {}).get("status") for i in doc.get("keySecurityIndicators") or []}}


def compare_statuses(previous, fedramp):
    """Regressions since the previous SDR (policies/compliance/regression.rego).
    A previous record that cannot be compared is reported, never read as clean."""
    previous = previous if isinstance(previous, dict) else {}
    prev = _statuses(previous)
    if not prev["rule"] and not prev["ksi"]:
        return {"compared": False, "why": "no previous record with statuses to compare", "compared_with": None, "items": []}
    out = _triage.evaluate("data.compliance.regression.result", {"previous": prev, "current": _statuses(fedramp)},
                           policy=REGRESSION_POLICY)
    return {"compared": True, "compared_with": (previous.get("metadata") or {}).get("last_updated"), "items": out["items"]}


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
    ap.add_argument("--runtime-signal", default="ksi-signal-runtime.json",
                    help="the published runtime signal (optional: absent or stale earns no live credit)")
    ap.add_argument("--vdr-status", default="vdr-status.json",
                    help="the nightly status beacon (optional: absent or stale earns no nightly credit)")
    ap.add_argument("--frr-records", default=str(_frr.DEFAULT_PATH))
    ap.add_argument("--ksi-short-output", default="ksi-short.json",
                    help="KSIs short of two methods, for the claims gate (_frr.py --claims --ksi-short)")
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

    def _optional(path):
        try:
            return json.loads(Path(path).read_text())
        except (OSError, json.JSONDecodeError):
            return None
    def _verified_runtime(path):
        """The runtime signal only when its signature verifies against the
        pinned key (the VDR builder's check); otherwise no live credit."""
        spec = importlib.util.spec_from_file_location(
            "build_vdr_report", Path(__file__).resolve().parent / "build-vdr-report.py")
        assert spec and spec.loader
        vdr_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(vdr_mod)
        check = vdr_mod.load_runtime_signal(path, now=now)
        if not check["verified"]:
            print(f"note: no live KSI credit: {check['reason']}")
            return None
        return _optional(path)
    frr_doc = _frr.load(a.frr_records)
    applicable = _rules.applicable_provider_rules()
    methods = _ksi_methods.load_methods()
    ksi_result = _ksi_methods.decide(_ksi_methods.facts(
        deploy_signal=signal, vdr=vdr, beacon=_optional(a.vdr_status),
        runtime_signal=_verified_runtime(a.runtime_signal), now=now, methods=methods))
    fedramp = build_fedramp(frr_doc, applicable, ksi_result, methods)
    for r in records:
        r["ksi_status"] = ksi_result["ksis"].get(r["rule_id"], {}).get("status")
    Path(a.ksi_short_output).write_text(json.dumps(ksi_result["short"]) + "\n")

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
        # CR26 statuses: every applicable rule (data/frr-records.json, claims
        # decided by policies/compliance/claims.rego) and every KSI (methods
        # counted by policies/compliance/ksi.rego).
        "status_summary": {**status_summary(frr_doc, applicable, ksi_result),
                           "regressions": compare_statuses(_optional(a.previous_sdr) if a.previous_sdr else None, fedramp)},
        "certificationPackageOverviewUri": fedramp["certificationPackageOverviewUri"],
        "fedRampRequirements": fedramp["fedRampRequirements"],
        "keySecurityIndicators": fedramp["keySecurityIndicators"],
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


def _status_lines(sdr):
    s = sdr["status_summary"]
    rules, ksis = s["rules"], s["ksis"]
    return ["## Status", "",
            f"- FedRAMP rules ({rules['rules']}): "
            + ", ".join(f"{n} {k}" for k, n in rules["by_status"].items())
            + f"; {rules['awaiting_approval']} awaiting the operator's approval",
            f"- Key Security Indicators ({ksis['total']}): "
            + ", ".join(f"{n} {k}" for k, n in ksis["by_status"].items())
            + ". Only Implemented counts as met.",
            *([f"- Unverified or failed methods (findings): {len(ksis['findings'])}"] if ksis.get("findings") else [])]


def _rule_lines(sdr):
    def cell(parts):
        return " ".join(parts).replace("|", "\\|").replace("\n", " ") or "None recorded."
    out = ["## FedRAMP rules (SDR-CSO-FRR)", "", "| Rule | Status | Explanation | Verification and validation | Independent |",
           "|---|---|---|---|---|"]
    for i in sdr.get("fedRampRequirements", []):
        out.append(f"| `{i['frrID']}` | {i['statusDetail']['status']} | {cell(i['frrImplementation'])} | "
                   f"{cell(i['frrValidation'])} | {cell(i['frrAssessment'])} |")
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
           *_status_lines(sdr), "",
           *_rule_lines(sdr), "",
           "## Per-KSI records (SDR-CSX-KSI)", "",
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
