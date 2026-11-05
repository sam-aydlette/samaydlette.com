#!/usr/bin/env python3
# =============================================================================
# SECURITY DECISION RECORD BUILDER  (CR26 SDR, FedRAMP's 2026-06-24 schema)
# =============================================================================
# The SDR says, for this 20x Class C offering:
#
#   fedRampRequirements   every applicable FedRAMP rule (SDR-CSO-FRR), from the
#                         governed records in data/frr-records.json, which
#                         scripts/_frr.py holds to the pinned rules and to
#                         evidence that resolves;
#   keySecurityIndicators every KSI (SDR-CSX-KSI): its measures (the OPA rules
#                         annotated with it), the automated methods that verify
#                         it (the deploy-time plan gate and the signed runtime
#                         re-validation), tests and evidence;
#   securityControls      every NIST 800-53 Rev5 control in the FedRAMP Moderate
#                         baseline, plus the controls FedRAMP's KSIs map beyond
#                         it: how 20x meets each Rev5 objective. A control's
#                         status is no stronger than what backs it.
#
# The record is 20x. The control view explains how the Rev5 objectives are met
# by the 20x evidence; it is not a second certification claim.
#
# Status rules for a control (the honesty rule, applied to Rev5):
#   Implemented            inherited from AWS (its FedRAMP authorization), or
#                          backed by a KSI whose measures are checked
#                          automatically, or by an implemented FedRAMP rule, or,
#                          for a policy-and-procedure control (XX-1), the
#                          family's published policy;
#   (no status)            not applicable, with the reason;
#   Partially Implemented  everything else the projection calls implemented:
#                          the mechanism is described but nothing checks it yet.
#
# Validated against the vendored schema before it is written; nothing that
# fails is written. Site-specific data is under providerExtensions.
#
#   build-sdr.py --catalog schemas/ksi-catalog.json --ksi-signal ksi-signal.json \
#       --runtime-signal ksi-signal-runtime.json --vdr vdr-report.json --previous-sdr prev.json
# =============================================================================

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _assessor  # noqa: E402
import _controls  # noqa: E402
import _fedramp_schema as fs  # noqa: E402
import _frr  # noqa: E402
import _rules  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
MODERATE_PROFILE = REPO / "data" / "profiles" / "FedRAMP_rev5_MODERATE-baseline_profile.json"
POLICY_DIR = REPO / "infrastructure" / "policy"
POLICIES = REPO / "docs" / "policies"
SITE = "https://samaydlette.com"
REPO_URL = "https://github.com/sam-aydlette/samaydlette.com/blob/main"
HISTORY_DAYS = 366  # SDR-CSX-KMT: daily metric data up to the past year
SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")

NO_ASSESSMENT = ("No independent assessment: no FedRAMP Recognized assessment service is engaged. "
                 "The provider-side verification and validation above is what an assessor would examine.")
WORKSTREAMS = {
    "W2": "vulnerability report follow-ups", "W3": "certification package in FedRAMP's schemas",
    "W4": "quarterly reporting cycle", "W5": "significant change notifications",
    "W6": "incident reporting", "W7": "detection and evaluation", "W8": "trust center",
    "W9": "FedRAMP Security Inbox", "W10": "scope, cryptography and secure configuration",
    "sam": "an act of the operator (registration, assessor, application)",
}
EVIDENCE_WORDS = {"test": "test", "step": "pipeline step", "artifact": "published artifact",
                  "decision": "decision record"}


def _fail(msg):
    raise SystemExit(f"::error::SDR: {msg} (fail-closed)")


# --- inputs ---------------------------------------------------------------------------

def moderate_ids(path=MODERATE_PROFILE):
    prof = json.loads(Path(path).read_text())["profile"]
    return {i for imp in prof["imports"] for inc in imp.get("include-controls", []) for i in inc.get("with-ids", [])}


def policy_rules(policy_dir=POLICY_DIR):
    """{KSI ID: [{"id", "title", "file"}]} from the OPA rule annotations
    (custom.ksi_ids), read with `opa inspect` like check-policy-annotations."""
    out = subprocess.run(["opa", "inspect", "-a", str(policy_dir), "--format", "json"],
                         capture_output=True, text=True, check=True)
    by_ksi = {}
    for entry in json.loads(out.stdout).get("annotations", []) or []:
        ann = entry.get("annotations") or {}
        custom = ann.get("custom") or {}
        if ann.get("scope") != "rule" or not custom.get("id"):
            continue
        f = Path((entry.get("location") or {}).get("file", "?")).name
        for k in custom.get("ksi_ids") or []:
            by_ksi.setdefault(k, []).append({"id": custom["id"], "title": ann.get("title", ""), "file": f})
    for rules in by_ksi.values():
        rules.sort(key=lambda r: (r["file"], r["id"]))
    return by_ksi


def runtime_validations(path):
    """Validations from the signed runtime signal, only when it verifies and is
    fresh (the VDR builder's own loader); otherwise none, with the reason."""
    spec = importlib.util.spec_from_file_location("vdr_builder", REPO / "scripts" / "build-vdr-report.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    rt = mod.load_runtime_signal(path)
    if not (rt["verified"] and rt["fresh"]):
        return [], rt["reason"] or "runtime signal not usable"
    return rt["validations"], None


# --- FedRAMP rules --------------------------------------------------------------------

def _evidence_line(ev):
    return f"{EVIDENCE_WORDS[ev['kind']]} `{ev['ref']}`"


def _assessment(rule_id, assessor_by_rule):
    entries = assessor_by_rule.get(rule_id) or []
    if not entries:
        return [NO_ASSESSMENT]
    return [f"Assessor record {e['record_id']} ({e['kind']}): {e['text']}" for e in entries]


def build_requirements(records, applicable, assessor_by_rule):
    out = []
    for r in records["records"]:
        rid, status = r["frr_id"], r["status"]
        impl = [r["implementation"]]
        if status == "Not Applicable":
            impl.append(f"Not applicable: {r['not_applicable']}")
        if r.get("may_rationale"):
            impl.append(f"Use of this permission: {r['may_rationale']}")
        val = []
        if r.get("evidence"):
            val.append("Evidence: " + "; ".join(_evidence_line(e) for e in r["evidence"]) + ".")
        val.append("Checked on every build by scripts/_frr.py: the rule set matches the pinned FedRAMP "
                   "rules and every piece of evidence cited resolves.")
        if r.get("gap"):
            val.append(f"Gap: {r['gap']}")
            val.append("Closes with: " + "; ".join(f"{c} ({WORKSTREAMS[c]})" for c in r["closes_with"]) + ".")
        rec = {"frrID": rid}
        if status != "Not Applicable":
            rec["frrImplementationStatus"] = status
        rec["frrImplementation"] = impl
        rec["frrValidation"] = val
        rec["frrAssessment"] = _assessment(rid, assessor_by_rule)
        rec["providerExtensions"] = {"status": status, "force": applicable[rid]["force"],
                                     "evidence": r.get("evidence", []),
                                     "closesWith": r.get("closes_with", [])}
        out.append(rec)
    return out


# --- KSIs -----------------------------------------------------------------------------

def ksi_status(k):
    """Implemented only when the KSI passes and its measures are checked
    automatically against the plan; a pass by inventory or document alone is
    partial."""
    if k.get("status") != "pass":
        return "Not Implemented"
    if k.get("method") == "policy-validation" and (k.get("evidence") or {}).get("validation_ids"):
        return "Implemented"
    return "Partially Implemented"


def build_ksis(catalog, signal, rules_by_ksi, runtime, runtime_reason, assessor_by_rule):
    statements = {i["id"]: i for f in catalog["KSI"].values() for i in f["indicators"]}
    sig = {k["id"]: k for k in signal.get("ksis", [])}
    missing = sorted(set(statements) - set(sig))
    if missing:
        _fail(f"the KSI signal carries no result for {', '.join(missing)}")
    emitted = (signal.get("emitted_at") or "")[:10] or None
    out, status = [], {}
    for kid in sorted(statements):
        k, cat = sig[kid], statements[kid]
        st = ksi_status(k)
        status[kid] = st
        ev = k.get("evidence") or {}
        comps = set(ev.get("component_refs") or [])
        rt = [v for v in runtime if comps & set(v.get("component_refs") or [])]
        plan_ok = bool(ev.get("validation_ids"))
        methods = int(plan_ok) + int(bool(rt))
        rules = rules_by_ksi.get(kid, [])
        impl = [cat["statement"]]
        if rules:
            impl.append("Measures: " + "; ".join(f"{r['title']} (`{r['file']}#{r['id']}`)" for r in rules) + ".")
        impl.append(f"Measured by {k.get('method')}: {len(comps)} inventory component(s), "
                    f"{len(ev.get('validation_ids') or [])} deploy-time validation(s), "
                    f"{len(ev.get('failed_validation_ids') or [])} failing.")
        val = []
        if plan_ok:
            val.append("Verified on every deploy: OPA evaluates the Terraform plan against the measures above "
                       "before apply, and the deploy stops on a violation.")
        if rt:
            val.append(f"Re-validated daily at runtime: the signed runtime signal re-evaluates the same compiled "
                       f"policy against live configuration for {len(rt)} of these components.")
        elif runtime_reason:
            val.append(f"Runtime re-validation not counted for this build: {runtime_reason}.")
        val.append(f"Automated methods in place: {methods} (FRC-CSX-VVK requires 2 for Class C).")
        if st != "Implemented":
            val.append("Status is not Implemented because "
                       + ("the KSI does not pass." if st == "Not Implemented" else
                          f"its evidence is {k.get('method')}, not an automated check of its measures."))
        evidence = [{"evidenceType": "Report",
                     "evidenceDescription": "Deploy-time KSI signal: inventory, validations and per-KSI results, "
                                            "signed with cosign by the deploy workflow.",
                     "evidenceLocation": f"{SITE}/.well-known/ksi-signal.json",
                     **({"lastUpdated": emitted} if emitted else {})}]
        if rt:
            evidence.append({"evidenceType": "Report",
                             "evidenceDescription": "Runtime KSI signal: daily re-validation of live configuration, "
                                                    "signed with the runtime KMS key.",
                             "evidenceLocation": f"{SITE}/.well-known/ksi-signal-runtime.json"})
        out.append({
            "ksiId": kid,
            "ksiImplementationStatus": st,
            "ksiImplementation": impl,
            "ksiValidation": val,
            "ksiAssessment": _assessment(kid, assessor_by_rule),
            "ksiTests": [f"infrastructure/policy/{r['file']}#{r['id']}" for r in rules],
            "ksiEvidence": evidence,
            "providerExtensions": {"method": k.get("method"), "automatedMethods": methods,
                                   "controls": [c["control_id"] for c in cat["controls"]]},
        })
    return out, status


# --- controls -------------------------------------------------------------------------

def nist_id(cid):
    """ac-2.1 -> AC-2(1)."""
    base, _, enh = cid.partition(".")
    return base.upper() + (f"({enh})" if enh else "")


def control_basis(ir, ksis_for, ksi_st, frrs_for, frr_st, policies):
    """(status, or None when not applicable; the basis sentence)."""
    cid = ir["control-id"]
    st = _controls.prop(ir, "implementation-status")
    orig = _controls.prop(ir, "control-origination")
    if st == "not-applicable":
        return None, "Not applicable."
    if st == "partial":
        return "Partially Implemented", "A contributing KSI is failing."
    checked = sorted(k for k in ksis_for.get(cid, ()) if ksi_st.get(k) == "Implemented")
    rules = sorted(r for r in frrs_for.get(cid, ()) if frr_st.get(r) == "Implemented")
    fam = cid.split("-")[0]
    if orig == "inherited":
        return "Implemented", "Inherited from AWS under its FedRAMP authorization."
    if checked:
        return "Implemented", "Backed by automatically checked KSI(s): " + ", ".join(checked) + "."
    if rules:
        return "Implemented", "Backed by implemented FedRAMP rule(s): " + ", ".join(rules) + "."
    if re.fullmatch(r"[a-z]{2}-1", cid) and fam in policies:
        return "Implemented", f"Policy and procedures, published: {policies[fam]}"
    return "Partially Implemented", ("The mechanism is described, but no automated check, implemented "
                                     "FedRAMP rule or published policy shows it yet.")


def _find_rule(rules, rid):
    for fam in rules["FRR"].values():
        for groups in fam["data"].values():
            for members in groups.values():
                if rid in members:
                    return members[rid]
    _fail(f"{rid} is not in the pinned rules")


def _sort_key(cid):
    fam, _, rest = cid.partition("-")
    num, _, enh = rest.partition(".")
    return (fam, int(num), int(enh or 0))


def build_controls(irs, catalog, ksi_st, applicable, records, moderate, policies):
    ksis_for, _ = _controls.contributing_ksis(catalog)
    frr_st = {r["frr_id"]: r["status"] for r in records["records"]}
    rules, _ = _rules.load_rules()
    frrs_for = {}
    for rid in applicable:
        for c in _find_rule(rules, rid).get("controls", []) or []:
            frrs_for.setdefault(str(c).lower(), set()).add(rid)
    missing = sorted(moderate - {ir["control-id"] for ir in irs})
    if missing:
        _fail(f"{len(missing)} Moderate control(s) have no implementation record: {', '.join(missing[:10])}")
    out = []
    for ir in sorted(irs, key=lambda i: _sort_key(i["control-id"])):
        cid = ir["control-id"]
        status, basis = control_basis(ir, ksis_for, ksi_st, frrs_for, frr_st, policies)
        statement = ir["statements"][0]["remarks"] if ir.get("statements") else ""
        orig = _controls.prop(ir, "control-origination")
        ks = sorted(ksis_for.get(cid, ()))
        fr = sorted(frrs_for.get(cid, ()))
        desc = [f"**Not applicable.** {statement}"] if status is None else [f"**Basis:** {basis}", statement]
        desc.append(f"**Origination:** {orig}.")
        desc.append("**20x coverage:** " + (", ".join(ks) if ks else "no KSI maps this control")
                    + ("; FedRAMP rules: " + ", ".join(fr) if fr else "") + ".")
        if cid not in moderate:
            desc.append("Beyond the FedRAMP Moderate baseline; included because a FedRAMP KSI maps it.")
        rec = {"controlId": nist_id(cid)}
        params = [{"parameterId": sp["param-id"], "parameterValue": ", ".join(sp["values"])}
                  for sp in ir.get("set-parameters", []) if sp.get("values")]
        if params:
            rec["parameterValues"] = params
        if status:
            rec["controlImplementationStatus"] = status
        rec["controlImplementationDescription"] = "\n\n".join(d for d in desc if d)
        rec["providerExtensions"] = {"basis": basis, "origination": orig, "ksis": ks, "fedrampRules": fr,
                                     "inModerateBaseline": cid in moderate,
                                     "status": status or "Not Applicable"}
        out.append(rec)
    return out


def policy_documents(policy_dir=POLICIES):
    """{control family: URL of its published policy} for families with one."""
    return {p.stem.removesuffix("-policy"): f"{REPO_URL}/docs/policies/{p.name}"
            for p in sorted(Path(policy_dir).glob("??-policy.md"))}


# --- metrics, version -----------------------------------------------------------------

def build_metrics(counts, vdr, signal, history, now):
    """SDR-CSX-KMT: today's point and daily history toward one year."""
    sig_vals = signal.get("validations", []) if signal else []
    vsum = (vdr or {}).get("summary", {})
    today = now.date().isoformat()
    point = {"date": today, **counts,
             "signal_validations": len(sig_vals),
             "signal_failing": sum(1 for v in sig_vals if v.get("result") == "fail"),
             "vdr_total": vsum.get("total_findings", 0), "vdr_blocking": vsum.get("blocking", 0),
             "vdr_accepted": vsum.get("risk_accepted", 0), "vdr_kev": vsum.get("kev", 0)}
    history = [h for h in history if h.get("date") != today] + [point]
    history = sorted(history, key=lambda h: h.get("date", ""))[-HISTORY_DAYS:]

    def summ(window):
        return {"days": len(window),
                "max_blocking": max(h.get("vdr_blocking", 0) for h in window),
                "max_failing_validations": max(h.get("signal_failing", 0) for h in window),
                "current_accepted": window[-1].get("vdr_accepted", 0)}
    return {"current": point, "summary_30d": summ(history[-30:]), "summary_1y": summ(history),
            "daily_metric_data": history}


def previous_history(prev):
    pe = prev.get("providerExtensions") or {}
    hist = (pe.get("metrics") or {}).get("daily_metric_data")
    if hist is None:  # the record before the schema reshape kept it at the top level
        hist = (prev.get("metrics") or {}).get("daily_metric_data")
    return [h for h in hist or [] if isinstance(h, dict)]


def content_hash(doc):
    """What the version tracks: everything but the metadata, the daily
    metrics and the hash itself."""
    body = {k: v for k, v in doc.items() if k not in ("metadata", "providerExtensions")}
    pe = {k: v for k, v in (doc.get("providerExtensions") or {}).items() if k not in ("metrics", "contentSha256")}
    raw = json.dumps({"body": body, "pe": pe}, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def next_version(prev, digest):
    """Semver: unchanged content keeps the previous version; changed content
    bumps the patch; a previous record without a semver starts at 1.0.0."""
    v = (prev.get("metadata") or {}).get("version", "")
    m = SEMVER.match(v or "")
    if not m:
        return "1.0.0"
    if (prev.get("providerExtensions") or {}).get("contentSha256") == digest:
        return v
    return f"{m.group(1)}.{m.group(2)}.{int(m.group(3)) + 1}"


# --- build ----------------------------------------------------------------------------

def _tally(items, key):
    out = {}
    for it in items:
        s = it["providerExtensions"][key]
        out[s] = out.get(s, 0) + 1
    return dict(sorted(out.items()))


def build(catalog, signal, records, applicable, irs, moderate, rules_by_ksi, runtime, runtime_reason,
          assessor_records, prof, prev, vdr, now, policies):
    ids = [r["frr_id"] for r in records["records"]] + sorted(
        i["id"] for f in catalog["KSI"].values() for i in f["indicators"])
    pseudo = [{"rule_id": i, "assessor_comment_responses": []} for i in ids]
    block = _assessor.attach(pseudo, assessor_records)
    by_rule = {p["rule_id"]: p["assessor_comment_responses"] for p in pseudo if p["assessor_comment_responses"]}

    reqs = build_requirements(records, applicable, by_rule)
    ksis, ksi_st = build_ksis(catalog, signal, rules_by_ksi, runtime, runtime_reason, by_rule)
    controls = build_controls(irs, catalog, ksi_st, applicable, records, moderate, policies)
    in_mod = [c for c in controls if c["providerExtensions"]["inModerateBaseline"]]
    beyond = [c for c in controls if not c["providerExtensions"]["inModerateBaseline"]]
    ksi_counts = {}
    for s in ksi_st.values():
        ksi_counts[s] = ksi_counts.get(s, 0) + 1
    counts = {"rules": len(reqs), "ksis": len(ksis), "controls_moderate": len(in_mod),
              "controls_beyond_moderate": len(beyond)}
    doc = {
        "$schema": fs.stamp("sdr"),
        "certificationPackageOverviewUri": fs.CPO_URI,
        "metadata": {},
        "fedRampRequirements": reqs,
        "keySecurityIndicators": ksis,
        "securityControls": controls,
        "providerExtensions": {
            "certification": "FedRAMP 20x, Program path, Class C",
            "class": prof.get("fedramp_class"),
            "impact_level": prof.get("impact_level"),
            "ksi_signal_id": signal.get("signal_id"),
            "rules": _rules.pin(),
            "summary": {"fedRampRequirements": _tally(reqs, "status"),
                        "keySecurityIndicators": dict(sorted(ksi_counts.items())),
                        "securityControlsModerate": _tally(in_mod, "status"),
                        "securityControlsBeyondModerate": _tally(beyond, "status")},
            "assessorRecords": block,
            "assessorCommentResponses": by_rule,
            "metrics": build_metrics(counts, vdr, signal, previous_history(prev), now),
        },
    }
    digest = content_hash(doc)
    doc["providerExtensions"]["contentSha256"] = digest
    doc["metadata"] = {"version": next_version(prev, digest), "lastUpdated": now.isoformat(),
                       "updateSource": "Automated: scripts/build-sdr.py in the deploy workflow, from "
                                       "data/frr-records.json, the KSI signal and the control projection"}
    return doc


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--catalog", default="schemas/ksi-catalog.json")
    ap.add_argument("--ksi-signal", default="ksi-signal.json")
    ap.add_argument("--runtime-signal", default="ksi-signal-runtime.json")
    ap.add_argument("--vdr", default="vdr-report.json")
    ap.add_argument("--profile", default="../data/system-profile.json")
    ap.add_argument("--frr-records", default=str(_frr.DEFAULT_PATH))
    ap.add_argument("--previous-sdr", default=None)
    ap.add_argument("--output", default="security-decision-record.json")
    ap.add_argument("--md-output", default="security-decision-record.md")
    ap.add_argument("--assessor-records", default=str(_assessor.RECORDS_DIR))
    ap.add_argument("--assessor-identity", default=str(_assessor.IDENTITY_PATH))
    a = ap.parse_args(argv)

    now = datetime.now(timezone.utc)
    catalog = json.loads(Path(a.catalog).read_text())
    if not Path(a.ksi_signal).exists():
        _fail(f"{a.ksi_signal} not found")
    signal = json.loads(Path(a.ksi_signal).read_text())
    vdr = json.loads(Path(a.vdr).read_text()) if Path(a.vdr).exists() else {}
    prof = json.loads(Path(a.profile).read_text()) if Path(a.profile).exists() else {}
    prev = {}
    if a.previous_sdr and Path(a.previous_sdr).exists():
        try:
            prev = json.loads(Path(a.previous_sdr).read_text())
        except json.JSONDecodeError:
            prev = {}
    records = _frr.load(a.frr_records)
    applicable = _rules.applicable_provider_rules()
    irs = _controls.load(a.ksi_signal, a.catalog)
    runtime, reason = runtime_validations(a.runtime_signal)
    assessor_records = _assessor.load_records(a.assessor_records, a.assessor_identity)
    doc = build(catalog, signal, records, applicable, irs, moderate_ids(), policy_rules(), runtime, reason,
                assessor_records, prof, prev, vdr, now, policy_documents())
    _assessor.verify_output(doc, assessor_records)  # T74
    fs.write_validated(doc, "sdr", a.output)
    if a.md_output:
        Path(a.md_output).write_text(render_markdown(doc) + "\n")
    s = doc["providerExtensions"]["summary"]
    print(f"security-decision-record {doc['metadata']['version']}: rules {s['fedRampRequirements']}; "
          f"KSIs {s['keySecurityIndicators']}; Moderate controls {s['securityControlsModerate']}")
    return 0


# --- human-readable view (CDS-CSO-CBF: same data as the JSON) -------------------------

def _cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def _assessor_lines(doc):
    pe = doc["providerExtensions"]
    entries = list(pe["assessorRecords"].get("records", []))
    for rid, es in pe.get("assessorCommentResponses", {}).items():
        entries += [dict(e, rule_id=rid) for e in es]
    if not entries:
        return ["**Assessor records:** No assessor record. Nothing on this page was written "
                "or signed by an assessor."]
    out = [f"**Assessor records:** {pe['assessorRecords']['status']}. Each is quoted verbatim from the "
           "assessor's signed record; the signature is in the JSON."]
    for e in sorted(entries, key=lambda e: e["record_id"]):
        rule = f" (`{e['rule_id']}`)" if e.get("rule_id") else ""
        out.append(f"- `{e['record_id']}`{rule}, {e['kind']}, {e['assessor']['organization']}, "
                   f"{e['issued_at']}: > {e['text']}")
    return out


def _summary_line(d):
    return ", ".join(f"{k} {v}" for k, v in d.items()) or "none"


def render_markdown(doc):
    m, pe = doc["metadata"], doc["providerExtensions"]
    s = pe["summary"]
    out = ["# Security Decision Record", "",
           f"_{pe['certification']}. Every applicable FedRAMP rule, every Key Security Indicator, and every "
           "NIST 800-53 Rev5 control in the Moderate baseline, with how 20x evidence meets it._", "",
           f"- **Version:** {m['version']} | **Last updated:** {m['lastUpdated']}",
           f"- **Source:** {m['updateSource']}",
           f"- **Bound to inventory signal:** `{pe['ksi_signal_id']}`",
           f"- **FedRAMP rules (pinned):** {pe['rules']['version']} at `{pe['rules']['commit'][:12]}`",
           "", "## Summary", "",
           f"- FedRAMP rules ({len(doc['fedRampRequirements'])}): {_summary_line(s['fedRampRequirements'])}",
           f"- Key Security Indicators ({len(doc['keySecurityIndicators'])}): "
           f"{_summary_line(s['keySecurityIndicators'])}",
           f"- Rev5 Moderate controls ({sum(s['securityControlsModerate'].values())}): "
           f"{_summary_line(s['securityControlsModerate'])}",
           f"- Controls beyond Moderate mapped by KSIs ({sum(s['securityControlsBeyondModerate'].values())}): "
           f"{_summary_line(s['securityControlsBeyondModerate'])}",
           "", *_assessor_lines(doc), "",
           "## FedRAMP rules", "", "| Rule | Status | Implementation | Gap / closes with |", "|---|---|---|---|"]
    for r in doc["fedRampRequirements"]:
        x = r["providerExtensions"]
        gap = next((v for v in r["frrValidation"] if v.startswith("Gap: ")), "")
        closes = next((v for v in r["frrValidation"] if v.startswith("Closes with: ")), "")
        out.append(f"| `{r['frrID']}` | {x['status']} | {_cell(' '.join(r['frrImplementation']))} | "
                   f"{_cell((gap + ' ' + closes).strip()) or '—'} |")
    out += ["", "## Key Security Indicators", "",
            "| KSI | Status | Automated methods | Measures |", "|---|---|---|---|"]
    for k in doc["keySecurityIndicators"]:
        x = k["providerExtensions"]
        out.append(f"| `{k['ksiId']}` | {k['ksiImplementationStatus']} | {x['automatedMethods']} | "
                   f"{_cell('; '.join(k['ksiTests'])) or '—'} |")
    out += ["", "## NIST 800-53 Rev5 controls", "",
            "| Control | Status | Basis | 20x coverage |", "|---|---|---|---|"]
    for c in doc["securityControls"]:
        x = c["providerExtensions"]
        cov = ", ".join(x["ksis"] + x["fedrampRules"]) or "—"
        tag = "" if x["inModerateBaseline"] else " (beyond Moderate)"
        out.append(f"| {c['controlId']}{tag} | {x['status']} | {_cell(x['basis'])} | {_cell(cov)} |")
    out += ["", "---", "_Source of truth: the signed `security-decision-record.json`._"]
    return "\n".join(out)


if __name__ == "__main__":
    sys.exit(main())
