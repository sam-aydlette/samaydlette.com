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
import _decisions  # noqa: E402
import _fedramp_schema as fs  # noqa: E402
import _freshness  # noqa: E402
import _frr  # noqa: E402
import _offering  # noqa: E402
import _rules  # noqa: E402
import _training  # noqa: E402

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


def runtime_bound(path, commit):
    """None when the runtime signal re-validated the inventory of `commit`
    (provenance.source.commit, copied by the emitter from the inventory it
    read); else why not. The deploy stages its own inventory for the emitter,
    so a signal from the previously published inventory does not count."""
    try:
        got = ((json.loads(Path(path).read_text()).get("provenance") or {}).get("source") or {}).get("commit")
    except (OSError, json.JSONDecodeError):
        return "the runtime signal is unreadable"
    if got != commit:
        return f"the runtime signal re-validated commit {str(got)[:12]}, not this build's {commit[:12]}"
    return None


# --- FRC-CSX-VVK: the automated methods counted per KSI ---------------------------------
# 1. the OPA plan gate (the KSI's measures validated against the plan);
# 2. the runtime re-validation (the signed runtime signal, verified and fresh);
# 3. dependency vulnerability scanning, for a KSI whose components include npm or
#    PyPI packages: the VDR built from this inventory's Syft SBOM and Grype scans,
#    bound to this inventory, its signature verified, inside its freshness window,
#    with every Grype scan passing the detection gate;
# 4 and 5. for KSI-CED-RAT only, the two training checks of scripts/_training.py:
#    the latest completed packet covers what the system's data requires
#    (currency), and the current packet was completed by its due date with a
#    passing score and a steady score trend (completion and effectiveness). The
#    trainee is simulated (counterparty `personnel`, DEC-194).
# A KSI with fewer than two is a shortfall unless an in-force `accepted`
# decision record names it (resource "ksi::<KSI ID>").
PACKAGE_TYPES = ("npm_package", "pypi_package")
TRAINING_KSI = "KSI-CED-RAT"
REQUIRED_METHODS = 2
VDR_PATH = ".well-known/vdr-report.json"
COSIGN_ISSUER = "https://token.actions.githubusercontent.com"


def cosign_verify(path, bundle, identities):
    """True when cosign verifies `bundle` over `path` for any of `identities`."""
    for ident in identities:
        r = subprocess.run(["cosign", "verify-blob", "--bundle", str(bundle), "--certificate-identity", ident,
                            "--certificate-oidc-issuer", COSIGN_ISSUER, str(path)],
                           capture_output=True, text=True, check=False)  # nosec B603: fixed argument list
        if r.returncode == 0:
            return True
    return False


def vdr_signature(path, bundle, identities, verifier=cosign_verify):
    """(verified, reason) for the VDR report's Sigstore bundle."""
    if not bundle or not identities:
        return False, "no VDR signature was supplied to check"
    if not Path(path).is_file() or not Path(bundle).is_file():
        return False, "the VDR report or its signature is missing"
    try:
        ok = verifier(path, bundle, identities)
    except OSError as exc:
        return False, f"the VDR signature could not be checked ({type(exc).__name__})"
    return (True, None) if ok else (False, "the VDR signature does not verify against the allowed identities")


def _ts(v):
    try:
        t = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def dependency_scan(vdr, signal, now, signature, max_age_hours):
    """(True, None) when the VDR counts as a dependency-scanning method for this
    inventory; else (False, the reason)."""
    if not vdr:
        return False, "no VDR report in this build"
    if not signal.get("signal_id") or vdr.get("ksi_signal_id") != signal.get("signal_id"):
        return False, "the VDR report is not bound to this inventory's signal_id"
    if not signature[0]:
        return False, signature[1] or "the VDR signature is not verified"
    emitted = _ts(vdr.get("emitted_at"))
    if emitted is None or not 0 <= (now - emitted).total_seconds() <= max_age_hours * 3600:
        return False, f"the VDR report is not within its {max_age_hours}-hour window"
    feeds = [f for f in ((vdr.get("methodology") or {}).get("detection") or {}).get("feeds") or []
             if f.get("feed") == "grype"]
    if not feeds:
        return False, "the VDR's detection record lists no Grype dependency scan"
    if any(f.get("status") != "ok" for f in feeds):
        return False, "a Grype dependency scan failed the detection gate"
    return True, None


def training_methods(prev, reg, incidents, n_rules, n_ksis, now):
    """{"currency": (ok, reason), "completion": (ok, reason), "summary": {...}}
    for KSI-CED-RAT, the history carried forward from the previous SDR."""
    previous = (prev.get("providerExtensions") or {}).get("training") if isinstance(prev, dict) else None
    cur, comp, summ = _training.evaluate(previous if isinstance(previous, dict) else None, reg, incidents,
                                         n_rules, n_ksis, now)
    return {"currency": cur, "completion": comp, "summary": summ}


INCIDENTS_PATH = Path(__file__).resolve().parent.parent / "data" / "incidents.json"


def _ksi_count(catalog):
    return sum(len(f["indicators"]) for f in catalog["KSI"].values())


NO_TRAINING = {"currency": (False, "not evaluated in this build"),
               "completion": (False, "not evaluated in this build"), "summary": None}


def vvk_acceptances(reg, now):
    """{KSI ID: DEC ID} for in-force, unexpired `accepted` records naming a KSI."""
    out = {}
    for r in _decisions.in_force(reg) if reg else []:
        if r.get("disposition") != "accepted" or str(r.get("review_by", "")) < now.date().isoformat():
            continue
        for res in (r.get("applies_to") or {}).get("resources") or []:
            if res.startswith("ksi::"):
                out[res[len("ksi::"):]] = r["id"]
    return out


def vvk_shortfalls(doc):
    """KSIs with fewer than two automated methods and no accepted decision."""
    return [f"{k['ksiId']}: {k['providerExtensions']['automatedMethods']} automated method(s); FRC-CSX-VVK "
            f"requires {REQUIRED_METHODS} and no in-force accepted decision record names it"
            for k in doc["keySecurityIndicators"]
            if k["providerExtensions"]["automatedMethods"] < REQUIRED_METHODS
            and not k["providerExtensions"].get("fewerMethodsAccepted")]


# --- FedRAMP rules --------------------------------------------------------------------

def _evidence_line(ev):
    return f"{EVIDENCE_WORDS[ev['kind']]} `{ev['ref']}`"


def evidence_context(freshness_path=None, decisions_path=None):
    """What a rule's evidence lines say about cycle and authority: the freshness
    entry of each published artifact and the in-force decision records."""
    cfg = _freshness.load_freshness_config(freshness_path)
    decs = _decisions.in_force(_decisions.load(decisions_path or REPO / "data" / "decisions.json"))
    return {"artifacts": {a["path"]: a for a in cfg["artifacts"]}, "decisions": {d["id"]: d for d in decs}}


def _evidence_validation(ev, ctx):
    """IVV-CSO-SEI/SEE: what one piece of evidence verifies, and on what cycle."""
    kind, ref = ev["kind"], ev["ref"]
    if kind == "test":
        return (f"Verified by the test `{ref}`, run on every pull request and before every deploy "
                "(the deploy's unit-test job); the deploy does not proceed if it fails.")
    if kind == "step":
        return (f"Exercised by the workflow step `{ref}` each time that workflow runs; the run fails if the "
                "step does.")
    if kind == "artifact":
        a = (ctx or {}).get("artifacts", {}).get(ref)
        cyc = (f", refreshed on its {a['cadence']} cadence and alarmed past {a['max_age_hours']} hours by the "
               "evidence watchdog") if a else ""
        return f"Shown by the published artifact `{ref}`{' (signed)' if a and a.get('signed') else ''}{cyc}."
    d = (ctx or {}).get("decisions", {}).get(ref)
    when = f", decided by {d.get('decided_by')} on {d.get('decided_on')}, review by {d.get('review_by')}" if d else ""
    return f"Attested by the decision record {ref}{when}: {d.get('title') if d else 'in force'}."


def _assessment(rule_id, assessor_by_rule):
    entries = assessor_by_rule.get(rule_id) or []
    if not entries:
        return [NO_ASSESSMENT]
    return [f"Assessor record {e['record_id']} ({e['kind']}): {e['text']}" for e in entries]


def build_requirements(records, applicable, assessor_by_rule, evidence_ctx=None):
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
            val += [_evidence_validation(e, evidence_ctx) for e in r["evidence"]]
        if r.get("simulated"):
            val.append(f"Simulated counterparty ({r['simulated']['counterparty']}): {r['simulated']['how']}")
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
        if r.get("simulated"):
            rec["providerExtensions"]["simulated"] = r["simulated"]
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


def _names(items, n=6):
    items = sorted(items)
    return ", ".join(f"`{i}`" for i in items[:n]) + (f" and {len(items) - n} more" if len(items) > n else "")


def ksi_text(kid, cat, k, rules, comps, rt, runtime_reason, nval, nfail, plan_ok):
    """SDR-CSX-KSI, written for this KSI from its own measures, components and
    results: (implementation lines, validation lines) covering the measures and
    their objective (or the reason there are none, and the risk), their cycle,
    verification that they demonstrate the KSI and that the automation is
    accurate, and validation that they are in place and working."""
    stmt = cat["statement"]
    impl = [stmt]
    if rules:
        impl.append(f"Measures ({len(rules)}), each an OPA rule annotated with {kid}: "
                    + "; ".join(f"{r['title']} (`{r['file']}#{r['id']}`)" for r in rules)
                    + f". Objective: together they show that {stmt[0].lower() + stmt[1:]}")
        impl.append(f"Cycle: on every deploy, before apply, against the Terraform plan for {len(comps)} "
                    f"component(s) ({_names(comps)})"
                    + (f"; and daily at runtime against the live configuration of {len(rt)} of them." if rt else "."))
    else:
        impl.append(f"No automated measure is annotated with {kid} in this build. Evidence is "
                    f"{k.get('method')}" + (f" over {len(comps)} inventory component(s) ({_names(comps)})" if comps
                                            else "") + ". Reason: no policy rule checks this KSI yet. Risk to "
                    "customers: a regression against the KSI would not stop a deploy and would surface only "
                    "when the inventory or the documentation is reviewed.")
        impl.append("Cycle: the inventory behind it is re-derived from live state on every deploy; there is no "
                    "persistent check.")
    val = []
    if rules:
        files = sorted({r["file"] for r in rules})
        val.append(f"Verification that the measures demonstrate {kid}: each rule carries {kid} in its "
                   "custom.ksi_ids annotation, and scripts/check-policy-annotations.py fails CI when an "
                   "annotation and the KSI catalog disagree. Verification that the automation is accurate: "
                   f"the rules' own tests ({', '.join(f'infrastructure/policy/{f[:-5]}_test.rego' for f in files)}) "
                   "run with a coverage floor on every pull request, and the parity test checks that the CLI and "
                   "the compiled Wasm the runtime uses decide alike.")
    if plan_ok:
        val.append(f"Validation on this deploy: {nval} validation(s) of these measures against the plan, "
                   f"{nfail} failing; the deploy stops on a violation.")
    if rt:
        val.append(f"Re-validated daily at runtime: the signed runtime signal re-evaluates the same compiled "
                   f"policy against live configuration for {len(rt)} of these components.")
    elif runtime_reason:
        val.append(f"Runtime re-validation not counted for this build: {runtime_reason}.")
    if not rules:
        val.append(f"Verification: none automated for {kid}; the inventory attestation is checked only for "
                   "completeness by the reconciliation gate. The reason for having no measure is not accepted: no "
                   "decision record accepts it, so the KSI is reported at the status its evidence supports.")
        val.append("Validation: there is no measure to validate as in place and working; the reason (no policy rule "
                   "yet) is valid for this build and is removed by annotating a rule with the KSI.")
    return impl, val


def build_ksis(catalog, signal, rules_by_ksi, runtime, runtime_reason, assessor_by_rule,
               dep_scan=(False, "not evaluated in this build"), training=None, accepted=None):
    statements = {i["id"]: i for f in catalog["KSI"].values() for i in f["indicators"]}
    sig = {k["id"]: k for k in signal.get("ksis", [])}
    missing = sorted(set(statements) - set(sig))
    if missing:
        _fail(f"the KSI signal carries no result for {', '.join(missing)}")
    emitted = (signal.get("emitted_at") or "")[:10] or None
    types = {c.get("component_id"): c.get("type") for c in signal.get("components", [])}
    accepted = accepted or {}
    out, status = [], {}
    for kid in sorted(statements):
        k, cat = sig[kid], statements[kid]
        st = ksi_status(k)
        status[kid] = st
        ev = k.get("evidence") or {}
        comps = set(ev.get("component_refs") or [])
        rt = [v for v in runtime if comps & set(v.get("component_refs") or [])]
        plan_ok = bool(ev.get("validation_ids"))
        pkgs = sorted(c for c in comps if types.get(c) in PACKAGE_TYPES)
        dep_ok = bool(pkgs) and dep_scan[0]
        training = training or NO_TRAINING
        train = [training[m] for m in ("currency", "completion")] if kid == TRAINING_KSI else []
        methods = int(plan_ok) + int(bool(rt)) + int(dep_ok) + sum(int(ok) for ok, _ in train)
        rules = rules_by_ksi.get(kid, [])
        nval, nfail = len(ev.get("validation_ids") or []), len(ev.get("failed_validation_ids") or [])
        impl, val = ksi_text(kid, cat, k, rules, comps, rt, runtime_reason, nval, nfail, plan_ok)
        if pkgs and dep_ok:
            val.append(f"Dependency vulnerability scanning of its {len(pkgs)} npm and PyPI package component(s): "
                       "the VDR report built from this inventory's Syft SBOM and Grype scans, bound to this "
                       "inventory, signature verified, inside its freshness window, every Grype scan passing the "
                       f"detection gate ({SITE}/.well-known/vdr-report.json).")
        elif pkgs:
            val.append(f"Dependency vulnerability scanning not counted for this build: {dep_scan[1]}.")
        if kid == TRAINING_KSI:
            cur, comp = train
            val.append("Training currency check: the latest completed training packet covers every decision of "
                       "the last 12 months, every incident and exercise, and the current rule and KSI counts "
                       "(providerExtensions.training)." if cur[0] else
                       f"Training currency check not counted for this build: {cur[1]}.")
            val.append("Training completion and effectiveness check: the current packet was completed by its due "
                       f"date with a score of at least {_training.PASS}, and the score trend holds; the trainee "
                       "is simulated (DEC-194)." if comp[0] else
                       f"Training completion and effectiveness check not counted for this build: {comp[1]}.")
        val.append(f"Automated methods in place: {methods} (FRC-CSX-VVK requires {REQUIRED_METHODS} for Class C).")
        if methods < REQUIRED_METHODS and kid in accepted:
            val.append(f"Fewer than {REQUIRED_METHODS} automated methods is an accepted finding: {accepted[kid]}.")
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
                                   **({"fewerMethodsAccepted": accepted[kid]}
                                      if methods < REQUIRED_METHODS and kid in accepted else {}),
                                   "packageComponents": len(pkgs),
                                   "controls": [c["control_id"] for c in cat["controls"]],
                                   "measures": [f"{r['file']}#{r['id']}" for r in rules],
                                   "components": len(comps), "validations": nval, "failingValidations": nfail,
                                   "runtimeComponents": len(rt)},
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

KSI_CODES = {"Implemented": "I", "Partially Implemented": "P", "Not Implemented": "N"}


def ksi_point(ksis):
    """Today's per-KSI metric data (SDR-CSX-KMT): status code (I/P/N), deploy-time
    validations and failures, automated methods, and whether the runtime signal
    re-validated it (the status of persistent validation)."""
    return {k["ksiId"]: {"s": KSI_CODES.get(k["ksiImplementationStatus"], "N"),
                         "v": k["providerExtensions"]["validations"],
                         "f": k["providerExtensions"]["failingValidations"],
                         "m": k["providerExtensions"]["automatedMethods"],
                         "r": int(k["providerExtensions"]["runtimeComponents"] > 0)} for k in ksis}


def ksi_summaries(history):
    """Per KSI: a summary of each metric over the past 30 days and up to the
    past year, from the days that carry per-KSI data."""
    def summ(window, kid):
        pts = [h["ksis"][kid] for h in window if isinstance(h.get("ksis"), dict) and kid in h["ksis"]]
        if not pts:
            return {"days": 0}
        return {"days": len(pts), "daysImplemented": sum(p["s"] == "I" for p in pts),
                "daysNotImplemented": sum(p["s"] == "N" for p in pts),
                "maxFailingValidations": max(p["f"] for p in pts),
                "minAutomatedMethods": min(p["m"] for p in pts),
                "daysRuntimeValidated": sum(p["r"] for p in pts),
                "current": KSI_NAMES[pts[-1]["s"]]}
    kids = sorted({kid for h in history if isinstance(h.get("ksis"), dict) for kid in h["ksis"]})
    return {kid: {"summary_30d": summ(history[-30:], kid), "summary_1y": summ(history, kid)} for kid in kids}


KSI_NAMES = {v: k for k, v in KSI_CODES.items()}


def build_metrics(counts, vdr, signal, history, now, ksis_today=None):
    """SDR-CSX-KMT: today's point and daily history toward one year, with
    per-KSI data and summaries."""
    sig_vals = signal.get("validations", []) if signal else []
    vsum = (vdr or {}).get("summary", {})
    today = now.date().isoformat()
    point = {"date": today, **counts,
             "signal_validations": len(sig_vals),
             "signal_failing": sum(1 for v in sig_vals if v.get("result") == "fail"),
             "vdr_total": vsum.get("total_findings", 0), "vdr_blocking": vsum.get("blocking", 0),
             "vdr_accepted": vsum.get("risk_accepted", 0), "vdr_kev": vsum.get("kev", 0)}
    if ksis_today is not None:
        point["ksis"] = ksis_today
    history = [h for h in history if h.get("date") != today] + [point]
    history = sorted(history, key=lambda h: h.get("date", ""))[-HISTORY_DAYS:]

    def summ(window):
        return {"days": len(window),
                "max_blocking": max(h.get("vdr_blocking", 0) for h in window),
                "max_failing_validations": max(h.get("signal_failing", 0) for h in window),
                "current_accepted": window[-1].get("vdr_accepted", 0)}
    return {"current": point, "summary_30d": summ(history[-30:]), "summary_1y": summ(history),
            "ksi_summaries": ksi_summaries(history),
            "daily_metric_keys": {"ksis": "per KSI: s status (I Implemented, P Partially, N Not), v deploy-time "
                                          "validations, f failing, m automated methods, r runtime re-validated "
                                          "(1/0)"},
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


def simulated_summary(reqs):
    """How many rule records rely on a simulated outside party, and which."""
    by = {}
    for r in reqs:
        sim = r["providerExtensions"].get("simulated")
        if sim:
            by[sim["counterparty"]] = by.get(sim["counterparty"], 0) + 1
    return {"records": sum(by.values()), "of": len(reqs), "byCounterparty": dict(sorted(by.items())),
            "statement": f"{sum(by.values())} of {len(reqs)} rule records rely on a simulated counterparty "
                         "(an assessor, FedRAMP, an agency, an incident recipient, personnel, the mail system or "
                         "SAM.gov): "
                         "the mechanism is real and runs on every deploy; only the outside party is simulated."}


def assessment_coverage(subject):
    """What the assessor results carried here covered (IVV-CSO-FIA, SDR-CSO-FRR),
    from the set's subject after scripts/_assessor.py checked it against the
    commit and signal the deploy stated."""
    return {
        "phase": subject.get("phase"),
        "commit": subject["commit"],
        "signalId": subject["signal_id"],
        "signalCommit": subject.get("signal_commit"),
        "statement": (
            f"The assessor results in this record come from the pre-deploy assessment. It verified the repository "
            f"at commit {subject['commit']} (the commit this record was built from) and validated the published "
            f"state that commit replaces: KSI signal {subject['signal_id']} (commit "
            f"{subject.get('signal_commit') or 'unknown'}). It is a gate: the deploy did not proceed until it "
            f"passed. After publishing, the same assessor assesses the just-published state of this commit; a "
            f"failure there fails the deploy run and raises the deployment-failure issue."),
    }


def build(catalog, signal, records, applicable, irs, moderate, rules_by_ksi, runtime, runtime_reason,
          assessor_records, prof, prev, vdr, now, policies, evidence_ctx=None, fedramp_id=None,
          dep_scan=(False, "not evaluated in this build"), training=None, accepted=None, coverage=None):
    ids = [r["frr_id"] for r in records["records"]] + sorted(
        i["id"] for f in catalog["KSI"].values() for i in f["indicators"])
    pseudo = [{"rule_id": i, "assessor_comment_responses": []} for i in ids]
    block = _assessor.attach(pseudo, assessor_records)
    by_rule = {p["rule_id"]: p["assessor_comment_responses"] for p in pseudo if p["assessor_comment_responses"]}

    reqs = build_requirements(records, applicable, by_rule, evidence_ctx)
    ksis, ksi_st = build_ksis(catalog, signal, rules_by_ksi, runtime, runtime_reason, by_rule,
                              dep_scan, training, accepted)
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
            "fedRampId": fedramp_id or _offering.fedramp_id(),
            # Sought, never held (scripts/_offering.py, the CPO's same field).
            "certification": _offering.certification(),
            "class": prof.get("fedramp_class"),
            "impact_level": prof.get("impact_level"),
            "ksi_signal_id": signal.get("signal_id"),
            "rules": _rules.pin(),
            "summary": {"fedRampRequirements": _tally(reqs, "status"),
                        "simulatedCounterparties": simulated_summary(reqs),
                        "keySecurityIndicators": dict(sorted(ksi_counts.items())),
                        "securityControlsModerate": _tally(in_mod, "status"),
                        "securityControlsBeyondModerate": _tally(beyond, "status")},
            "assessorRecords": block,
            "assessorCommentResponses": by_rule,
            **({"assessmentCoverage": coverage} if coverage else {}),
            **({"training": training["summary"]} if training and training.get("summary") else {}),
            "metrics": build_metrics(counts, vdr, signal, previous_history(prev), now, ksi_point(ksis)),
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
    # A keyless-signed assessment set (the simulated assessor's, on every deploy):
    # given, it is required to exist and verify; its records replace the loose ones.
    ap.add_argument("--assessment", default=None)
    ap.add_argument("--assessment-bundle", default=None)
    # The state the set must cover (required with --assessment): the commit
    # being deployed and the published KSI signal the assessor validated. A set
    # covering anything else is refused, and the SDR states these.
    ap.add_argument("--assessment-commit", default=None)
    ap.add_argument("--assessment-signal-id", default=None)
    # FRC-CSX-VVK: the VDR's Sigstore bundle and the identities allowed to sign
    # it (dependency scanning counts only when it verifies), the decision
    # register (taught in the training packet; accepted shortfalls), the incident
    # register (taught in the training packet), and whether
    # a KSI short of two methods without an accepted decision fails the build.
    ap.add_argument("--vdr-bundle", default=None)
    ap.add_argument("--vdr-identity", action="append", default=[])
    ap.add_argument("--decisions", default=None)
    ap.add_argument("--incidents", default=str(INCIDENTS_PATH))
    ap.add_argument("--freshness", default=None)
    ap.add_argument("--require-two-methods", action="store_true")
    # The commit whose inventory the runtime signal must have re-validated (the
    # deploy's staged emitter run); runtime validations of any other count for nothing.
    ap.add_argument("--runtime-commit", default=None)
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
    if a.runtime_commit and runtime:
        reason = runtime_bound(a.runtime_signal, a.runtime_commit)
        runtime = [] if reason else runtime
    coverage = None
    if a.assessment:
        assessor_records, subject = _assessor.load_assessment_with_subject(
            a.assessment, a.assessment_bundle, a.assessor_identity,
            expect_commit=a.assessment_commit, expect_signal_id=a.assessment_signal_id)
        coverage = assessment_coverage(subject)
    else:
        assessor_records = _assessor.load_records(a.assessor_records, a.assessor_identity)
    reg = _decisions.load(a.decisions)
    window = _freshness.load_freshness_config(a.freshness)["windows"][VDR_PATH]
    dep_scan = dependency_scan(vdr, signal, now, vdr_signature(a.vdr, a.vdr_bundle, a.vdr_identity), window)
    doc = build(catalog, signal, records, applicable, irs, moderate_ids(), policy_rules(), runtime, reason,
                assessor_records, prof, prev, vdr, now, policy_documents(), evidence_context(),
                dep_scan=dep_scan, accepted=vvk_acceptances(reg, now),
                training=training_methods(prev, reg, json.loads(Path(a.incidents).read_text()),
                                          len(records["records"]), _ksi_count(catalog), now),
                coverage=coverage)
    _assessor.verify_output(doc, assessor_records)  # T74
    short = vvk_shortfalls(doc)
    for msg in short:
        print(f"::{'error' if a.require_two_methods else 'warning'}::FRC-CSX-VVK: {msg}", file=sys.stderr)
    if short and a.require_two_methods:
        _fail(f"{len(short)} KSI(s) short of {REQUIRED_METHODS} automated methods; nothing written"
              + (f" (runtime re-validation not counted: {reason})" if reason else ""))
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
    if pe.get("assessmentCoverage"):
        out += ["", f"**What the assessment covered:** {pe['assessmentCoverage']['statement']}", ""]
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
           f"_{pe['certification']['program']} (sought; status: {pe['certification']['status']}). Every "
           "applicable FedRAMP rule, every Key Security Indicator, and every NIST 800-53 Rev5 control in the Moderate baseline, with how 20x evidence meets it._", "",
           f"- **FedRAMP ID:** {pe.get('fedRampId')} (simulated: no FedRAMP ID has been assigned)",
           f"- **Version:** {m['version']} | **Last updated:** {m['lastUpdated']}",
           f"- **Source:** {m['updateSource']}",
           f"- **Bound to inventory signal:** `{pe['ksi_signal_id']}`",
           f"- **FedRAMP rules (pinned):** {pe['rules']['version']} at `{pe['rules']['commit'][:12]}`",
           "", "## Summary", "",
           f"- FedRAMP rules ({len(doc['fedRampRequirements'])}): {_summary_line(s['fedRampRequirements'])}",
           f"- {(s.get('simulatedCounterparties') or {}).get('statement', 'No rule record relies on a simulated counterparty.')}",
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
        sim = f" (simulated {x['simulated']['counterparty']})" if x.get("simulated") else ""
        out.append(f"| `{r['frrID']}` | {x['status']}{sim} | {_cell(' '.join(r['frrImplementation']))} | "
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
