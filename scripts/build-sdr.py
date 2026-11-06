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
#                         annotated with it), the automated methods that
#                         genuinely test them (FRC-CSX-VVK, the strict count of
#                         scripts/_ksi_methods.py), tests and evidence, and its
#                         status: Implemented (two or more methods on real
#                         inputs), Simulated (two only with a stand-in input),
#                         Not Demonstrated (fewer than two), or Not Applicable
#                         (data/ksi-applicability.json, approved by the operator);
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
# The four statuses of a rule or KSI are projected onto FedRAMP's enum
# (Implemented, Partially Implemented, Not Implemented): Implemented as
# Implemented, Not Demonstrated as Not Implemented, and Simulated and Not
# Applicable leave the official field out, since the enum has no value for
# them. The real status, what is real and what is simulated, the stand-in
# proof and the approval are in providerExtensions.
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
import _ksi_applicability  # noqa: E402
import _ksi_methods  # noqa: E402
import _offering  # noqa: E402
import _rules  # noqa: E402
import _signers  # noqa: E402
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
# The four statuses and FedRAMP's enum: Simulated and Not Applicable have no
# FedRAMP value, so the official field is left out for them.
STATUSES = _frr.STATUSES
OFFICIAL_STATUS = {"Implemented": "Implemented", "Not Demonstrated": "Not Implemented"}
EVIDENCE_WORDS = {"test": "test", "step": "pipeline step", "artifact": "published artifact",
                  "decision": "decision record"}


def _fail(msg):
    raise SystemExit(f"::error::SDR: {msg} (fail-closed)")


# --- inputs ---------------------------------------------------------------------------

def moderate_ids(path=MODERATE_PROFILE):
    prof = json.loads(Path(path).read_text())["profile"]
    return {i for imp in prof["imports"] for inc in imp.get("include-controls", []) for i in inc.get("with-ids", [])}


def policy_rules(policy_dir=POLICY_DIR):
    """{KSI ID: [{"id", "title", "file", "resource_types", "runtime_only"}]} from
    the OPA rule annotations (custom.ksi_ids, custom.resource_types,
    custom.runtime_only), read with `opa inspect` like check-policy-annotations,
    which requires every rule to state its resource types."""
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
            by_ksi.setdefault(k, []).append({"id": custom["id"], "title": ann.get("title", ""), "file": f,
                                             "resource_types": list(custom.get("resource_types") or []),
                                             "runtime_only": bool(custom.get("runtime_only"))})
    for rules in by_ksi.values():
        rules.sort(key=lambda r: (r["file"], r["id"]))
    return by_ksi


def _runtime_signal(path):
    spec = importlib.util.spec_from_file_location("vdr_builder", REPO / "scripts" / "build-vdr-report.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.load_runtime_signal(path)


def runtime_validations(path):
    """Validations from the signed runtime signal, only when it verifies and is
    fresh (the VDR builder's own loader); otherwise none, with the reason."""
    rt = _runtime_signal(path)
    if not (rt["verified"] and rt["fresh"]):
        return [], rt["reason"] or "runtime signal not usable"
    return rt["validations"], None


def runtime_divergence(path, unusable_reason=None):
    """(ok, reason) for the runtime-divergence method: the verified, fresh
    runtime signal (bound to this build when the deploy says so; otherwise
    `unusable_reason`) reports `converged`."""
    if unusable_reason:
        return False, unusable_reason
    rt = _runtime_signal(path)
    if not (rt["verified"] and rt["fresh"]):
        return False, rt["reason"] or "runtime signal not usable"
    status = rt.get("divergence")
    if status != "converged":
        return False, f"the runtime signal reports divergence status {status!r}, not 'converged'"
    return True, None


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


# --- FRC-CSX-VVK: the automated methods counted per KSI (strict) -------------------------
# A method counts for a KSI only when it genuinely tests that KSI's measures
# (operator's decision of 2026-11-06; scripts/_ksi_methods.py):
#   plan     an OPA rule annotated with the KSI evaluated, in this deploy's plan,
#            a resource of one of the rule's resource_types;
#   runtime  the same, in the signed runtime re-validation of live configuration;
#   the mechanisms of infrastructure/schemas/ksi-methods.json, each counted only
#            when its verifier passes (signature, freshness, a pass result).
# The inventory's family-level links (build-ksi-signal.py) never count.
# A KSI's status: Implemented with two or more methods on real inputs; Simulated
# when it reaches two only with a stand-in input; Not Demonstrated with fewer
# than two, or when it does not pass. FRC-CSX-VVK's record may claim no more
# than these counts support: it is Implemented only when every applicable KSI
# has two, otherwise Not Demonstrated naming each KSI short of two (unless an
# in-force `accepted` decision record names it, resource "ksi::<KSI ID>").
REQUIRED_METHODS = 2
VDR_PATH = ".well-known/vdr-report.json"
COSIGN_ISSUER = "https://token.actions.githubusercontent.com"
VVK = "FRC-CSX-VVK"
# Sub-resources a component's validation also evaluates: the plan folds an API's
# stages and routes into its component (build-ksi-signal.py
# PLAN_VALIDATED_CHILD_TYPES) and the runtime reader of an API reads them; the
# runtime reader of a function also evaluates its deployed code package
# (infrastructure/lambda/describers.js).
SUB_TYPES = {"api_gateway": ("aws_apigatewayv2_route", "aws_apigatewayv2_stage"),
             "function": ("lambda_deployment_package",)}
# Sub-resources only the plan evaluates with the component: a bucket's policy is
# a plan result credited to its bucket (build-ksi-signal.py
# PLAN_VALIDATED_CHILD_TYPES), but the runtime reader of a bucket does not read
# its policy, so it never adds runtime credit.
PLAN_SUB_TYPES = {"object_store": ("aws_s3_bucket_policy",)}
NOT_EVALUATED = _ksi_methods.NOT_EVALUATED


def cosign_verify(path, bundle, identities):
    """True when cosign verifies `bundle` over `path` for any of `identities`."""
    for ident in identities:
        r = subprocess.run(["cosign", "verify-blob", "--bundle", str(bundle), "--certificate-identity", ident,
                            "--certificate-oidc-issuer", COSIGN_ISSUER, str(path)],
                           capture_output=True, text=True, check=False)  # nosec B603: fixed argument list
        if r.returncode == 0:
            return True
    return False


def bundle_signature(path, bundle, identities, what, verifier=cosign_verify):
    """(verified, reason) for a Sigstore bundle over `path` (`what` names it)."""
    if not bundle or not identities:
        return False, f"no {what} signature was supplied to check"
    if not Path(path).is_file() or not Path(bundle).is_file():
        return False, f"the {what} or its signature is missing"
    try:
        ok = verifier(path, bundle, identities)
    except OSError as exc:
        return False, f"the {what} signature could not be checked ({type(exc).__name__})"
    return (True, None) if ok else (False, f"the {what} signature does not verify against the allowed identities")


def vdr_signature(path, bundle, identities, verifier=cosign_verify):
    """(verified, reason) for the VDR report's Sigstore bundle."""
    return bundle_signature(path, bundle, identities, "VDR report", verifier)


def _ts(v):
    try:
        t = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def vdr_usable(vdr, signal, now, signature, max_age_hours):
    """(True, None) when this build's VDR report can stand behind a detection
    feed method: bound to this inventory, signature verified, inside its window."""
    if not vdr:
        return False, "no VDR report in this build"
    if not signal.get("signal_id") or vdr.get("ksi_signal_id") != signal.get("signal_id"):
        return False, "the VDR report is not bound to this inventory's signal_id"
    if not signature[0]:
        return False, signature[1] or "the VDR signature is not verified"
    emitted = _ts(vdr.get("emitted_at"))
    if emitted is None or not 0 <= (now - emitted).total_seconds() <= max_age_hours * 3600:
        return False, f"the VDR report is not within its {max_age_hours}-hour window"
    return True, None


def plan_gate_run(signal, signature):
    """(ok, reason) for the plan-gate-run method: the signed KSI signal carries
    this deploy's plan validations, none failing."""
    if not signature[0]:
        return False, signature[1] or "the KSI signal's signature is not verified"
    vals = signal.get("validations") or []
    if not vals:
        return False, "the KSI signal carries no plan validations"
    if any(v.get("result") != "pass" for v in vals):
        return False, "a plan validation failed"
    return True, None


def training_methods(prev, reg, incidents, n_rules, n_ksis, now):
    """{"currency": (ok, reason), "completion": (ok, reason), "summary": {...}}
    for KSI-CED-RAT, the history carried forward from the previous SDR."""
    previous = (prev.get("providerExtensions") or {}).get("training") if isinstance(prev, dict) else None
    cur, comp, summ = _training.evaluate(previous if isinstance(previous, dict) else None, reg, incidents,
                                         n_rules, n_ksis, now)
    return {"currency": cur, "completion": comp, "summary": summ}


def training_result(training):
    """Training is one mechanism: it counts when both its checks pass."""
    if not training:
        return NOT_EVALUATED
    for k in ("currency", "completion"):
        if not training[k][0]:
            return False, f"training {k}: {training[k][1]}"
    return True, None


INCIDENTS_PATH = Path(__file__).resolve().parent.parent / "data" / "incidents.json"


def _ksi_count(catalog):
    return sum(len(f["indicators"]) for f in catalog["KSI"].values())


NO_TRAINING = {"currency": NOT_EVALUATED, "completion": NOT_EVALUATED, "summary": None}


def published_methods(methods_doc, records, now, cfg, verifier=cosign_verify):
    """{method key: (ok, reason)} for the methods whose result is a published
    record. `records` is {key: (json path, bundle path)}; a record counts only
    when its bundle verifies against the workflows that publish it
    (scripts/_signers.py), it is inside its freshness window and it passes its
    check."""
    out = {}
    for key, name in _ksi_methods.published_keys(methods_doc).items():
        if key not in records:
            out[key] = NOT_EVALUATED
            continue
        path, bundle = records[key]
        ids = [_signers.IDENTITIES[w] for w in _signers.signers(name)]
        out[key] = _ksi_methods.verify_published(_ksi_methods.by_key(methods_doc)[key], path, bundle, now, cfg,
                                                 verifier, ids)
    return out


def method_results(methods_doc, published, vdr_ok, vdr, divergence, plan_gate, training):
    """{method key: (ok, reason)} for every method of the table."""
    out = {}
    for m in methods_doc["methods"]:
        kind = m["verifier"]["kind"]
        if kind == "published":
            out[m["key"]] = published.get(m["key"], NOT_EVALUATED)
        elif kind == "vdr-feed":
            out[m["key"]] = _ksi_methods.verify_vdr_feeds(m, vdr_ok, vdr or {})
        elif kind == "runtime-divergence":
            out[m["key"]] = divergence
        elif kind == "plan-gate":
            out[m["key"]] = plan_gate
        else:
            out[m["key"]] = training_result(training)
    return out


def component_types(components, extra=None):
    """{component ID: the Terraform types a validation of it evaluates}; `extra`
    adds sub-types only one of the two paths evaluates (PLAN_SUB_TYPES)."""
    out = {}
    for c in components:
        types = {((c.get("attributes") or {}).get("tf_type"))} - {None}
        subs = set(SUB_TYPES.get(c.get("type"), ())) | set((extra or {}).get(c.get("type"), ()))
        out[c.get("component_id")] = types | subs
    return out


def evaluated_types(validations, types_of):
    """Every Terraform type the given validations evaluated."""
    out = set()
    for v in validations:
        for ref in v.get("component_refs") or []:
            out |= types_of.get(ref, set())
    return out


def _rule_matches(rule, types):
    rts = rule.get("resource_types") or []
    if "*" in rts:
        return bool(types)
    return bool(set(rts) & types)


def rule_methods(rules, plan_types, runtime_types):
    """(plan rules, runtime rules): the KSI's annotated rules that evaluated a
    resource of their types in this plan, and against live configuration.

    Plan credit and runtime credit are two separate methods, even when one rule
    provides both (operator's decision, 2026-11-06): at plan time the rule reads
    the Terraform plan through the deploy gate, at runtime it reads live
    configuration through the runtime emitter, so the inputs and the code paths
    that gather them differ. One annotated rule that evaluated a resource of its
    type in both counts 2 for its KSI; in the plan only, 1."""
    plan = [r for r in rules if not r.get("runtime_only") and _rule_matches(r, plan_types)]
    rt = [r for r in rules if _rule_matches(r, runtime_types)]
    return plan, rt


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
    """KSIs with fewer than two automated methods and no accepted decision
    (Not Applicable KSIs are not counted)."""
    return [f"{k['ksiId']}: {k['providerExtensions']['automatedMethods']} automated method(s); FRC-CSX-VVK "
            f"requires {REQUIRED_METHODS} and no in-force accepted decision record names it"
            for k in doc["keySecurityIndicators"]
            if k["providerExtensions"]["status"] != "Not Applicable"
            and k["providerExtensions"]["automatedMethods"] < REQUIRED_METHODS
            and not k["providerExtensions"].get("fewerMethodsAccepted")]


def vvk_claim(doc, records):
    """[why] when the FRC-CSX-VVK record claims more than this build's computed
    counts support: Implemented while any applicable KSI is short of two
    methods, or a status other than the two the counts allow (Implemented, or
    Not Demonstrated). Not Demonstrated claims nothing the counts could
    contradict; the SDR lists the short KSIs of each build itself
    (vvk_computed)."""
    rec = next((r for r in records["records"] if r["frr_id"] == VVK), None)
    if rec is None:
        return [f"{VVK} has no record"]
    short = sorted(s.split(":", 1)[0] for s in vvk_shortfalls(doc))
    if rec["status"] == "Implemented":
        return [f"{VVK} is recorded Implemented but {len(short)} KSI(s) have fewer than {REQUIRED_METHODS} "
                f"automated methods: {', '.join(short)}"] if short else []
    if rec["status"] == "Not Demonstrated":
        return []
    return [f"{VVK} is recorded {rec['status']}; its status follows the counts (Implemented or Not Demonstrated)"]


def vvk_computed(doc):
    """The per-KSI count behind FRC-CSX-VVK, as this build computed it: the line
    and the extension the SDR's FRC-CSX-VVK entry carries."""
    applicable = [k for k in doc["keySecurityIndicators"] if k["providerExtensions"]["status"] != "Not Applicable"]
    short = sorted(s.split(":", 1)[0] for s in vvk_shortfalls(doc))
    line = (f"Computed in this build: {len(applicable) - len(short)} of {len(applicable)} applicable KSIs have "
            f"{REQUIRED_METHODS} or more automated methods that test their measures"
            + (f"; short of {REQUIRED_METHODS}: {', '.join(short)}." if short else "."))
    return line, {"applicableKsis": len(applicable), "short": short}


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


def _signoff(v):
    return f"{v['by']} on {v['on']}"


def _approval_lines(r, what):
    """Who proposed the stand-in or scope cut, and whether the operator approved it."""
    out = []
    if r.get("proposal"):
        out.append(f"{what} proposed by {_signoff(r['proposal'])}.")
    out.append(f"Approved by {_signoff(r['approval'])}." if r.get("approval") else
               f"Not yet approved by the operator ({_frr.OPERATOR}); the deploy's claim check stops until it is.")
    return out


def build_requirements(records, applicable, assessor_by_rule, evidence_ctx=None):
    out = []
    for r in records["records"]:
        rid, status = r["frr_id"], r["status"]
        impl = [r["implementation"]]
        if status == "Not Applicable":
            impl.append(f"Not applicable: {r['not_applicable']}")
        if status == "Not Demonstrated":
            impl.append(f"Not demonstrated: {r['not_demonstrated']}")
        if r.get("may_rationale"):
            impl.append(f"Use of this permission: {r['may_rationale']}")
        val = []
        if r.get("evidence"):
            val.append("Evidence: " + "; ".join(_evidence_line(e) for e in r["evidence"]) + ".")
            val += [_evidence_validation(e, evidence_ctx) for e in r["evidence"]]
        sim = r.get("simulated")
        if sim:
            val.append(f"Simulated counterparty ({sim['counterparty']}): {sim['how']}")
            if sim.get("real"):
                val.append(f"What is real: {sim['real']}")
            if sim.get("stand_in"):
                val.append(f"What is simulated: {sim['stand_in']}")
        proof = r.get("stand_in_proof")
        if proof:
            val.append(f"Stand-in proof: a bad stand-in changes the result (`{proof['bad_input']}`); "
                       f"replaceable: {proof['replaceable']['statement']}"
                       + (f" (`{proof['replaceable']['test']}`)" if proof["replaceable"].get("test") else "") + ".")
        elif status == "Simulated":
            val.append("Stand-in proof: none recorded yet.")
        if status in _frr.NEEDS_APPROVAL:
            val += _approval_lines(r, {"Simulated": "The stand-in was", "Not Demonstrated": "The status was",
                                       "Not Applicable": "The scope cut was"}[status])
        val.append("Checked on every build by scripts/_frr.py: the rule set matches the pinned FedRAMP "
                   "rules and every piece of evidence cited resolves; the deploy checks that the record's "
                   "fields support its status.")
        rec = {"frrID": rid}
        if status in OFFICIAL_STATUS:
            rec["frrImplementationStatus"] = OFFICIAL_STATUS[status]
        rec["frrImplementation"] = impl
        rec["frrValidation"] = val
        rec["frrAssessment"] = _assessment(rid, assessor_by_rule)
        ext = {"status": status, "force": applicable[rid]["force"], "evidence": r.get("evidence", [])}
        for k, name in (("simulated", "simulated"), ("stand_in_proof", "standInProof"),
                        ("not_demonstrated", "notDemonstrated"), ("not_applicable", "notApplicable"),
                        ("proposal", "proposal"), ("approval", "approval")):
            if r.get(k):
                ext[name] = r[k]
        rec["providerExtensions"] = ext
        out.append(rec)
    return out


# --- KSIs -----------------------------------------------------------------------------

def ksi_status(k, real, total):
    """Implemented: the KSI passes with two or more methods on real inputs.
    Simulated: it reaches two only with a stand-in input. Not Demonstrated:
    fewer than two, or the KSI does not pass."""
    if k.get("status") != "pass":
        return "Not Demonstrated"
    if real >= REQUIRED_METHODS:
        return "Implemented"
    if total >= REQUIRED_METHODS:
        return "Simulated"
    return "Not Demonstrated"


def _names(items, n=6):
    items = sorted(items)
    return ", ".join(f"`{i}`" for i in items[:n]) + (f" and {len(items) - n} more" if len(items) > n else "")


def ksi_text(kid, cat, k, rules, comps, plan_rules, rt_rules, runtime_reason, nval, nfail, counted):
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
        impl.append("Cycle: on every deploy, before apply, against the Terraform plan"
                    + (f" ({len(plan_rules)} of these rules evaluated a resource of their type)" if plan_rules
                       else " (no resource of these rules' types is in the plan)")
                    + (f"; and daily at runtime against live configuration ({len(rt_rules)} of them)." if rt_rules
                       else "."))
    else:
        impl.append(f"No OPA rule is annotated with {kid} in this build. Evidence beyond the methods below is "
                    f"{k.get('method')}" + (f" over {len(comps)} inventory component(s) ({_names(comps)})" if comps
                                            else "") + ". Reason: no policy rule tests this KSI's measures. Risk to "
                    "customers: a regression against the KSI that the methods below do not test would not stop a "
                    "deploy.")
        impl.append("Cycle: the inventory behind it is re-derived from live state on every deploy; any other "
                    "cycle is that of the methods below.")
    val = []
    if rules:
        files = sorted({r["file"] for r in rules})
        val.append(f"Verification that the measures demonstrate {kid}: each rule carries {kid} in its "
                   "custom.ksi_ids annotation and states the resource types it evaluates in custom.resource_types; "
                   "scripts/check-policy-annotations.py fails CI when an annotation and the KSI catalog disagree. "
                   "Verification that the automation is accurate: "
                   f"the rules' own tests ({', '.join(f'infrastructure/policy/{f[:-5]}_test.rego' for f in files)}) "
                   "run with a coverage floor on every pull request, and the parity test checks that the CLI and "
                   "the compiled Wasm the runtime uses decide alike.")
    if plan_rules:
        val.append(f"Validation on this deploy: {nval} validation(s) against the plan, {nfail} failing; the deploy "
                   "stops on a violation. Rules that evaluated a resource of their type at plan (Terraform plan): "
                   + ", ".join(f"`{r['file'][:-5]}#{r['id']}`" for r in plan_rules) + ".")
    if rt_rules:
        val.append("Re-validated daily at runtime: the signed runtime signal re-evaluates the same compiled policy "
                   "against live configuration, where these rules evaluated a resource of their type at runtime "
                   "(live read): " + ", ".join(f"`{r['file'][:-5]}#{r['id']}`" for r in rt_rules) + ". Plan and "
                   "runtime are counted as two methods, since their inputs and code paths differ.")
    elif rules and runtime_reason:
        val.append(f"Runtime re-validation not counted for this build: {runtime_reason}.")
    for m in counted:
        if m["key"] in ("plan", "runtime"):
            continue
        val.append(f"{m['mechanism']}: {m['measure']}"
                   + (" Runs on a labelled stand-in input." if m["input"] == "stand-in" else "")
                   + (" Its verified result is current and passing." if m["counted"] else
                      f" Not counted for this build: {m['reason']}."))
    n = sum(1 for m in counted if m["counted"])
    if n == 0:
        val.append(f"Verification: none automated for {kid}. No method that tests this KSI's measures ran and "
                   "verified in this build; the KSI is reported at the status that supports.")
    return impl, val


def _ksi_na(kid, cat, entry, assessor_by_rule):
    """A KSI that does not apply (data/ksi-applicability.json): published with
    its reason and approval, no official status, no method count."""
    val = _approval_lines(entry, "The scope cut was")
    return {"ksiId": kid,
            "ksiImplementation": [cat["statement"], f"Not applicable: {entry['not_applicable']}"],
            "ksiValidation": val + ["Not counted toward FRC-CSX-VVK: the KSI does not apply."],
            "ksiAssessment": _assessment(kid, assessor_by_rule), "ksiTests": [], "ksiEvidence": [],
            "providerExtensions": {"status": "Not Applicable", "notApplicable": entry["not_applicable"],
                                   **{k: entry[k] for k in ("proposal", "approval") if entry.get(k)},
                                   "controls": [c["control_id"] for c in cat["controls"]]}}


def build_ksis(catalog, signal, rules_by_ksi, runtime, runtime_reason, assessor_by_rule,
               methods_doc=None, results=None, accepted=None, not_applicable=None):
    statements = {i["id"]: i for f in catalog["KSI"].values() for i in f["indicators"]}
    not_applicable = not_applicable or {}
    sig = {k["id"]: k for k in signal.get("ksis", [])}
    missing = sorted(set(statements) - set(sig) - set(not_applicable))
    if missing:
        _fail(f"the KSI signal carries no result for {', '.join(missing)}")
    emitted = (signal.get("emitted_at") or "")[:10] or None
    types_of = component_types(signal.get("components", []))
    plan_types = evaluated_types(signal.get("validations") or [],
                                 component_types(signal.get("components", []), PLAN_SUB_TYPES))
    runtime_types = evaluated_types(runtime, types_of)
    table = {}
    for m in (methods_doc or {"methods": []})["methods"]:
        for kid in m["ksis"]:
            table.setdefault(kid, []).append(m)
    results = results or {}
    accepted = accepted or {}
    out, status = [], {}
    for kid in sorted(statements):
        cat = statements[kid]
        if kid in not_applicable:
            out.append(_ksi_na(kid, cat, not_applicable[kid], assessor_by_rule))
            continue
        k = sig[kid]
        ev = k.get("evidence") or {}
        comps = set(ev.get("component_refs") or [])
        rules = rules_by_ksi.get(kid, [])
        plan_rules, rt_rules = rule_methods(rules, plan_types, runtime_types)
        counted = [
            {"key": "plan", "mechanism": "OPA plan gate", "input": "real", "counted": bool(plan_rules),
             "measure": "the KSI's annotated rules evaluated resources of their types at plan (Terraform plan)",
             "reason": None if plan_rules else ("no rule is annotated with this KSI" if not rules else
                                                "no resource of its rules' types is in this plan")},
            {"key": "runtime", "mechanism": "Runtime re-validation", "input": "real", "counted": bool(rt_rules),
             "measure": "the KSI's annotated rules evaluated resources of their types at runtime (live read)",
             "reason": None if rt_rules else ("no rule is annotated with this KSI" if not rules else
                                              runtime_reason or "no live resource of its rules' types was "
                                                                "re-validated")}]
        for m in table.get(kid, []):
            ok, why = results.get(m["key"], NOT_EVALUATED)
            counted.append({"key": m["key"], "mechanism": m["mechanism"], "measure": m["measure"],
                            "input": m["input"], "counted": bool(ok), "reason": why})
        methods = sum(1 for m in counted if m["counted"])
        real = sum(1 for m in counted if m["counted"] and m["input"] == "real")
        st = ksi_status(k, real, methods)
        status[kid] = st
        nval, nfail = len(ev.get("validation_ids") or []), len(ev.get("failed_validation_ids") or [])
        impl, val = ksi_text(kid, cat, k, rules, comps, plan_rules, rt_rules, runtime_reason, nval, nfail, counted)
        val.append(f"Automated methods in place: {methods}, {real} on real inputs (FRC-CSX-VVK requires "
                   f"{REQUIRED_METHODS} for Class C; only a method that tests this KSI's measures counts).")
        if methods < REQUIRED_METHODS and kid in accepted:
            val.append(f"Fewer than {REQUIRED_METHODS} automated methods is an accepted finding: {accepted[kid]}.")
        if st == "Simulated":
            val.append(f"Status is Simulated: it reaches {REQUIRED_METHODS} methods only with a method that runs on "
                       "a labelled stand-in input.")
        elif st == "Not Demonstrated":
            val.append("Status is Not Demonstrated because "
                       + ("the KSI does not pass." if k.get("status") != "pass" else
                          f"fewer than {REQUIRED_METHODS} methods that test its measures ran and verified."))
        evidence = [{"evidenceType": "Report",
                     "evidenceDescription": "Deploy-time KSI signal: inventory, validations and per-KSI results, "
                                            "signed with cosign by the deploy workflow.",
                     "evidenceLocation": f"{SITE}/.well-known/ksi-signal.json",
                     **({"lastUpdated": emitted} if emitted else {})}]
        if rt_rules:
            evidence.append({"evidenceType": "Report",
                             "evidenceDescription": "Runtime KSI signal: daily re-validation of live configuration, "
                                                    "signed with the runtime KMS key.",
                             "evidenceLocation": f"{SITE}/.well-known/ksi-signal-runtime.json"})
        rec = {"ksiId": kid}
        if st in OFFICIAL_STATUS:
            rec["ksiImplementationStatus"] = OFFICIAL_STATUS[st]
        rec.update({
            "ksiImplementation": impl,
            "ksiValidation": val,
            "ksiAssessment": _assessment(kid, assessor_by_rule),
            "ksiTests": [f"infrastructure/policy/{r['file']}#{r['id']}" for r in rules],
            "ksiEvidence": evidence,
            "providerExtensions": {"status": st, "method": k.get("method"), "automatedMethods": methods,
                                   "realInputMethods": real,
                                   "methods": [{x: m[x] for x in ("key", "mechanism", "input", "counted", "reason")}
                                               for m in counted],
                                   **({"fewerMethodsAccepted": accepted[kid]}
                                      if methods < REQUIRED_METHODS and kid in accepted else {}),
                                   "controls": [c["control_id"] for c in cat["controls"]],
                                   "measures": [f"{r['file']}#{r['id']}" for r in rules],
                                   "components": len(comps), "validations": nval, "failingValidations": nfail,
                                   "runtimeRules": len(rt_rules)},
        })
        out.append(rec)
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

KSI_CODES = {"Implemented": "I", "Simulated": "S", "Not Demonstrated": "D"}
# Days recorded before the four statuses carry FedRAMP's codes: P (Partially
# Implemented: passing, but not by an automated check of its measures) and N
# (Not Implemented); both count as not demonstrated.
LEGACY_CODES = {"P": "Partially Implemented", "N": "Not Implemented"}


def ksi_point(ksis):
    """Today's per-KSI metric data (SDR-CSX-KMT): status code (I/S/D), deploy-time
    validations and failures, automated methods, and whether the runtime signal
    re-validated it (the status of persistent validation). A KSI that does not
    apply carries none."""
    return {k["ksiId"]: {"s": KSI_CODES[k["providerExtensions"]["status"]],
                         "v": k["providerExtensions"]["validations"],
                         "f": k["providerExtensions"]["failingValidations"],
                         "m": k["providerExtensions"]["automatedMethods"],
                         "r": int(k["providerExtensions"]["runtimeRules"] > 0)}
            for k in ksis if k["providerExtensions"]["status"] in KSI_CODES}


def ksi_summaries(history):
    """Per KSI: a summary of each metric over the past 30 days and up to the
    past year, from the days that carry per-KSI data."""
    def summ(window, kid):
        pts = [h["ksis"][kid] for h in window if isinstance(h.get("ksis"), dict) and kid in h["ksis"]]
        if not pts:
            return {"days": 0}
        return {"days": len(pts), "daysImplemented": sum(p["s"] == "I" for p in pts),
                "daysSimulated": sum(p["s"] == "S" for p in pts),
                "daysNotDemonstrated": sum(p["s"] in ("D", *LEGACY_CODES) for p in pts),
                "maxFailingValidations": max(p["f"] for p in pts),
                "minAutomatedMethods": min(p["m"] for p in pts),
                "daysRuntimeValidated": sum(p["r"] for p in pts),
                "current": KSI_NAMES.get(pts[-1]["s"], pts[-1]["s"])}
    kids = sorted({kid for h in history if isinstance(h.get("ksis"), dict) for kid in h["ksis"]})
    return {kid: {"summary_30d": summ(history[-30:], kid), "summary_1y": summ(history, kid)} for kid in kids}


KSI_NAMES = {**{v: k for k, v in KSI_CODES.items()}, **LEGACY_CODES}


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
            "daily_metric_keys": {"ksis": "per KSI: s status (I Implemented, S Simulated, D Not Demonstrated; "
                                          "days before 2026-11-06 carry P Partially Implemented or N Not "
                                          "Implemented), v deploy-time validations, f failing, m automated "
                                          "methods, r runtime re-validated (1/0)"},
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


def status_counts(items):
    """Every one of the four statuses, zero included, in their order."""
    t = _tally(items, "status")
    return {st: t.get(st, 0) for st in STATUSES}


def awaiting_approval(items, statuses):
    """How many items in `statuses` carry no operator approval."""
    return sum(1 for it in items if it["providerExtensions"]["status"] in statuses
               and not it["providerExtensions"].get("approval"))


def simulated_summary(reqs):
    """How many rule records rely on a simulated outside party, and which."""
    by = {}
    for r in reqs:
        sim = r["providerExtensions"].get("simulated")
        if sim:
            by[sim["counterparty"]] = by.get(sim["counterparty"], 0) + 1
    return {"records": sum(by.values()), "of": len(reqs), "byCounterparty": dict(sorted(by.items())),
            "statement": f"{sum(by.values())} of {len(reqs)} rule records are Simulated: a real mechanism runs on "
                         "a labelled stand-in (an assessor, FedRAMP, an agency, an incident recipient, personnel, "
                         "the mail system or SAM.gov) on every deploy."}


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
          methods_doc=None, results=None, training=None, accepted=None, coverage=None, not_applicable=None):
    """`results` is {method key: (ok, reason)} for the methods of `methods_doc`
    (default: the governed table); a method missing from it is not counted.
    `not_applicable` is {KSI ID: entry} from data/ksi-applicability.json."""
    methods_doc = methods_doc if methods_doc is not None else _ksi_methods.load()
    ids = [r["frr_id"] for r in records["records"]] + sorted(
        i["id"] for f in catalog["KSI"].values() for i in f["indicators"])
    pseudo = [{"rule_id": i, "assessor_comment_responses": []} for i in ids]
    block = _assessor.attach(pseudo, assessor_records)
    by_rule = {p["rule_id"]: p["assessor_comment_responses"] for p in pseudo if p["assessor_comment_responses"]}

    reqs = build_requirements(records, applicable, by_rule, evidence_ctx)
    ksis, ksi_st = build_ksis(catalog, signal, rules_by_ksi, runtime, runtime_reason, by_rule,
                              methods_doc, results, accepted, not_applicable)
    line, computed = vvk_computed({"keySecurityIndicators": ksis})
    for r in reqs:
        if r["frrID"] == VVK:
            r["frrValidation"].insert(0, line)
            r["providerExtensions"]["computed"] = computed
    controls = build_controls(irs, catalog, ksi_st, applicable, records, moderate, policies)
    in_mod = [c for c in controls if c["providerExtensions"]["inModerateBaseline"]]
    beyond = [c for c in controls if not c["providerExtensions"]["inModerateBaseline"]]
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
            "summary": {"fedRampRequirements": status_counts(reqs),
                        "fedRampRequirementsAwaitingApproval": awaiting_approval(reqs, _frr.NEEDS_APPROVAL),
                        "simulatedCounterparties": simulated_summary(reqs),
                        "keySecurityIndicators": status_counts(ksis),
                        "keySecurityIndicatorsAwaitingApproval": awaiting_approval(ksis, ("Not Applicable",)),
                        "statusProjection": "FedRAMP's status enum is Implemented, Partially Implemented and Not "
                                            "Implemented. Implemented is published as Implemented and Not "
                                            "Demonstrated as Not Implemented; Simulated and Not Applicable leave "
                                            "the official field out. providerExtensions.status carries the real "
                                            "status of every rule and KSI.",
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


def _method_record_args(values, methods_doc):
    """{key: (json path, bundle path)} from KEY=<file>.json, the bundle beside it."""
    keys = _ksi_methods.published_keys(methods_doc)
    out = {}
    for v in values:
        key, _, path = v.partition("=")
        if key not in keys or not path.endswith(".json"):
            _fail(f"--method-record {v!r}: expected KEY=<file>.json with KEY one of {', '.join(sorted(keys))}")
        out[key] = (path, path[:-5] + ".bundle")
    return out


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
    # it (its detection feeds count only when it verifies), the KSI signal's
    # bundle (the plan-gate run counts only when it verifies against the deploy),
    # the decision register (taught in the training packet; accepted
    # shortfalls), the incident register (taught in the training packet), the
    # method table and the KSI scope cuts.
    ap.add_argument("--vdr-bundle", default=None)
    ap.add_argument("--vdr-identity", action="append", default=[])
    ap.add_argument("--ksi-signal-bundle", default=None)
    ap.add_argument("--decisions", default=None)
    ap.add_argument("--incidents", default=str(INCIDENTS_PATH))
    ap.add_argument("--freshness", default=None)
    ap.add_argument("--ksi-methods", default=None)
    ap.add_argument("--ksi-applicability", default=None)
    # The claim check on FRC-CSX-VVK (the name predates it): fail, writing
    # nothing, when the record claims more than the computed per-KSI counts
    # support. Without it the mismatch is a warning.
    ap.add_argument("--require-two-methods", action="store_true")
    # The published records of the table's `published` methods, each KEY=JSON
    # with its Sigstore bundle beside it (<stem>.bundle); each counts for its
    # KSIs only when the bundle verifies against its publisher, it is inside its
    # window and its check passes.
    ap.add_argument("--method-record", action="append", default=[], metavar="KEY=JSON")
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
    divergence = runtime_divergence(a.runtime_signal, reason)
    coverage = None
    if a.assessment:
        assessor_records, subject = _assessor.load_assessment_with_subject(
            a.assessment, a.assessment_bundle, a.assessor_identity,
            expect_commit=a.assessment_commit, expect_signal_id=a.assessment_signal_id)
        coverage = assessment_coverage(subject)
    else:
        assessor_records = _assessor.load_records(a.assessor_records, a.assessor_identity)
    reg = _decisions.load(a.decisions)
    cfg = _freshness.load_freshness_config(a.freshness)
    methods_doc = _ksi_methods.load(a.ksi_methods, a.catalog, a.freshness)
    na = _ksi_applicability.not_applicable(_ksi_applicability.load(a.ksi_applicability, a.catalog))
    vdr_ok = vdr_usable(vdr, signal, now, vdr_signature(a.vdr, a.vdr_bundle, a.vdr_identity),
                        cfg["windows"][VDR_PATH])
    sig_ok = bundle_signature(a.ksi_signal, a.ksi_signal_bundle,
                              [_signers.IDENTITIES[w] for w in _signers.signers("ksi-signal.json")], "KSI signal")
    training = training_methods(prev, reg, json.loads(Path(a.incidents).read_text()), len(records["records"]),
                                _ksi_count(catalog), now)
    published = published_methods(methods_doc, _method_record_args(a.method_record, methods_doc), now, cfg)
    results = method_results(methods_doc, published, vdr_ok, vdr, divergence, plan_gate_run(signal, sig_ok),
                             training)
    doc = build(catalog, signal, records, applicable, irs, moderate_ids(), policy_rules(), runtime, reason,
                assessor_records, prof, prev, vdr, now, policy_documents(), evidence_context(),
                methods_doc=methods_doc, results=results, accepted=vvk_acceptances(reg, now),
                training=training, coverage=coverage, not_applicable=na)
    _assessor.verify_output(doc, assessor_records)  # T74
    for msg in vvk_shortfalls(doc):
        print(f"::notice::FRC-CSX-VVK: {msg}", file=sys.stderr)
    over = vvk_claim(doc, records)
    for msg in over:
        print(f"::{'error' if a.require_two_methods else 'warning'}::{msg}", file=sys.stderr)
    if over and a.require_two_methods:
        _fail(f"the {VVK} record claims more than the per-KSI method counts support; nothing written"
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
           f"- {s['statusProjection']}",
           f"- Awaiting the operator's approval: {s['fedRampRequirementsAwaitingApproval']} rule record(s), "
           f"{s['keySecurityIndicatorsAwaitingApproval']} KSI scope cut(s)",
           "", *_assessor_lines(doc), "",
           "## FedRAMP rules", "",
           "| Rule | Status | Implementation | Stand-in, reason and approval |", "|---|---|---|---|"]
    for r in doc["fedRampRequirements"]:
        x = r["providerExtensions"]
        sim = f" ({x['simulated']['counterparty']} stand-in)" if x.get("simulated") else ""
        notes = [v for v in r["frrValidation"] if v.startswith(("What is real:", "What is simulated:", "Stand-in proof:",
                                                               "Approved by", "Not yet approved"))
                 or " proposed by " in v]
        out.append(f"| `{r['frrID']}` | {x['status']}{sim} | {_cell(' '.join(r['frrImplementation']))} | "
                   f"{_cell(' '.join(notes)) or '—'} |")
    out += ["", "## Key Security Indicators", "",
            "| KSI | Status | Methods counted (real inputs) | Measures |", "|---|---|---|---|"]
    for k in doc["keySecurityIndicators"]:
        x = k["providerExtensions"]
        if x["status"] == "Not Applicable":
            out.append(f"| `{k['ksiId']}` | Not Applicable | — | {_cell(x['notApplicable'])} |")
            continue
        names = ", ".join(m["key"] for m in x["methods"] if m["counted"]) or "none"
        out.append(f"| `{k['ksiId']}` | {x['status']} | {x['automatedMethods']} ({x['realInputMethods']}): "
                   f"{_cell(names)} | {_cell('; '.join(k['ksiTests'])) or '—'} |")
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
