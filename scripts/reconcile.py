#!/usr/bin/env python3
# =============================================================================
# RECONCILIATION GATE  (assessment keystone — Task 1)
# =============================================================================
# The central finding of the assessment was that the published artifacts were
# trusted blindly and had drifted from reality. This gate is the logic layer
# that makes drift impossible to publish: it runs in CI before publish and
# FAILS CLOSED if any cross-artifact invariant is broken.
#
# Invariants (assessment Task 1):
#   (a) completeness   — every live in-boundary resource is in the inventory
#                        (deny-by-default; enumerated from live AWS, not state)
#   (b) referential    — every SSP component and POA&M asset resolves to an
#                        inventory entry
#   (c) suppressions   — every suppressed Checkov finding is categorized as
#                        exactly one of risk-accepted / false-positive /
#                        remediated, consistently across .checkov.yaml,
#                        docs/poam.md, and the VDR
#   (d) impact level   — one identical impact level across signal, SSP, POA&M,
#                        VDR, and dashboard; nothing asserts the system is Low
#   (e) binding        — all artifacts are built from one inventory signal_id
#                        and carry it
#   (f) publish freshness — staged artifacts carry the current commit and a
#                        fresh emitted_at (the live round-trip half is Task 1.5)
#   (g) POA&M parity   — the OSCAL POA&M's item set exactly equals the formal
#                        POA&M items in docs/poam.md, so the human and
#                        machine-readable registers can never silently drift
#   (h) finding coverage — every VDR finding carries a poam_ref that resolves
#                        to a POA&M item
#   (i) classification tags — live resource tags match the inventory's
#                        projected classification (with --live)
#   (j) POA&M reference validity — every POAM-NNN mentioned anywhere in a
#                        generated artifact resolves to a formal POA&M item
#                        (or an explicitly retired ID), so a typo'd or
#                        vanished cross-reference cannot publish silently
#   (k) SCuBA bundle binding — when the published customer-assessment bundle
#                        is present it binds to the same inventory signal_id
#                        and its policy set equals the SSP's control set
#                        (the executable CRM cannot drift from the SSP it
#                        derives from)
#
# Usage:
#   reconcile.py --artifacts-dir infrastructure [--live] [--expect-commit SHA]
#   reconcile.py ... --live-fixture tests/fixtures/live-arns.json   (for tests)
#
# Exit 0 only if every invariant holds. Any violation -> exit 1 (fail closed).
# Each check is a pure function (inventory + peers in, violations out) so the
# unit tests can drive them with fixtures, including a deliberately-broken one.
# =============================================================================

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


# ----------------------------------------------------------------------------
# loaders
# ----------------------------------------------------------------------------
def load_json(path):
    return json.loads(Path(path).read_text())


def normalize_impact(value):
    """Lowercase impact token; map FedRAMP class shorthand to its level."""
    if not value:
        return None
    v = str(value).strip().lower()
    v = v.replace("fips-199-", "")
    return {"class c": "moderate", "c": "moderate",
            "class b": "high", "class a": "high"}.get(v, v)


def inventory_native_ids(signal):
    """All native_ids (ARNs/ids) present in the inventory."""
    ids = set()
    for c in signal.get("components", []):
        nid = c.get("native_id")
        if nid:
            ids.add(nid)
    return ids


def inventory_component_ids(signal):
    return {c.get("component_id") for c in signal.get("components", []) if c.get("component_id")}


# ----------------------------------------------------------------------------
# (a) completeness — every live in-boundary resource appears in the inventory
# ----------------------------------------------------------------------------
# The set of services that define the boundary. Enumerated live (deny-by-default):
# anything returned here that is NOT in the inventory fails the gate. Adding a
# service to the boundary means adding it here AND mapping its type in the builder.
# The system's resources are named/aliased with this prefix. The completeness
# invariant enumerates only resources inside this boundary — a raw account sweep
# would include AWS-platform noise (AWS-managed KMS keys, unrelated resources)
# that are not components of THIS system. Drift within the boundary (a new
# system-named resource that is not inventoried) still fails the gate.
SYSTEM_PREFIX = "samaydlette"


def is_state_backend_bucket(name):
    """The Terraform remote-state bucket (<prefix>-tfstate) is management-plane
    infrastructure (bootstrap-provisioned, holds this stack's own state), not a
    per-deploy system resource, so it is excluded from the live completeness
    sweep. Matches the state-backend naming convention, nothing else."""
    return (name or "").endswith("-tfstate")


def enumerate_live_arns(region_primary="us-east-2", region_edge="us-east-1"):
    """Enumerate live in-boundary resource ARNs via the AWS CLI (boto3 is not a
    build dependency), scoped to SYSTEM_PREFIX. Returns a set of ARNs. Raises on
    CLI failure so a broken enumeration fails the gate closed rather than
    silently reporting 'complete'."""
    def cli(args):
        out = subprocess.run(["aws", *args, "--output", "json"],
                             capture_output=True, text=True)
        if out.returncode != 0:
            raise RuntimeError(f"aws {' '.join(args)} failed: {out.stderr.strip()}")
        return json.loads(out.stdout or "null")

    def in_boundary(name):
        return SYSTEM_PREFIX in (name or "").lower()

    arns = set()
    # Lambda (primary region)
    for fn in (cli(["lambda", "list-functions", "--region", region_primary]) or {}).get("Functions", []):
        if in_boundary(fn["FunctionName"]):
            arns.add(fn["FunctionArn"])
    # API Gateway v2 — match the ARN form the inventory carries (Terraform's
    # aws_apigatewayv2_api.arn): arn:aws:apigateway:REGION::/apis/ID
    for api in (cli(["apigatewayv2", "get-apis", "--region", region_primary]) or {}).get("Items", []):
        if in_boundary(api.get("Name")):
            arns.add(f"arn:aws:apigateway:{region_primary}::/apis/{api['ApiId']}")
    # Secrets Manager
    for s in (cli(["secretsmanager", "list-secrets", "--region", region_primary]) or {}).get("SecretList", []):
        if in_boundary(s["Name"]):
            arns.add(s["ARN"])
    # KMS: only customer-managed keys carrying a system-named alias. AWS-managed
    # keys and unaliased/unrelated customer keys are out of boundary.
    sys_key_ids = set()
    for a in (cli(["kms", "list-aliases", "--region", region_primary]) or {}).get("Aliases", []):
        if in_boundary(a.get("AliasName")) and a.get("TargetKeyId"):
            sys_key_ids.add(a["TargetKeyId"])
    for kid in sys_key_ids:
        meta = (cli(["kms", "describe-key", "--key-id", kid, "--region", region_primary]) or {}).get("KeyMetadata", {})
        if meta.get("KeyManager") == "CUSTOMER" and meta.get("Arn"):
            arns.add(meta["Arn"])
    # S3 (global) — the system bucket(s). The Terraform remote-state bucket
    # (<prefix>-tfstate) is excluded: it is management-plane infrastructure that
    # stores this stack's OWN state, like the bootstrap identity plane, and is
    # provisioned and verified by the bootstrap stack rather than the per-deploy
    # inventory. Excluding it keeps the state backend from reading as an
    # un-inventoried system resource; any other system-named bucket (actual
    # system storage) is still swept, so deny-by-default holds.
    for b in (cli(["s3api", "list-buckets"]) or {}).get("Buckets", []):
        if in_boundary(b["Name"]) and not is_state_backend_bucket(b["Name"]):
            arns.add(f"arn:aws:s3:::{b['Name']}")
    # CloudWatch log groups (primary region)
    for lg in (cli(["logs", "describe-log-groups", "--region", region_primary]) or {}).get("logGroups", []):
        if in_boundary(lg["logGroupName"]):
            arns.add(lg["arn"].rstrip(":*"))
    return arns


def check_a_completeness(signal, live_arns):
    """Every live ARN must appear as a native_id in the inventory."""
    have = {nid.rstrip(":*") for nid in inventory_native_ids(signal)}
    violations = []
    for arn in sorted(live_arns):
        a = arn.rstrip(":*")
        # match on exact or arn-prefix (log group arns sometimes carry :*)
        if a not in have and not any(h.startswith(a) or a.startswith(h) for h in have):
            violations.append(f"(a) live resource not in inventory: {arn}")
    return violations


# ----------------------------------------------------------------------------
# (i) classification-tag reconciliation — live AWS resource tags must equal the
# inventory's projected classification (attributes.classification). The build-time
# OPA gate (PR-D Part 1) enforces tag *presence*; this enforces tag *values*
# against the single source of truth, fail closed, verified against live cloud
# state. Only per-deploy resources that carry our classification tags live are
# reconciled; bootstrap/global resources not tagged by the per-deploy stack
# (CloudFront, ACM, IAM — the latter outside the tagging API) are out of scope.
# ----------------------------------------------------------------------------

# inventory classification key -> live AWS tag key.
CLASSIFICATION_TAG_MAP = {
    "data_sensitivity": "DataSensitivity",
    "mission_criticality": "MissionCriticality",
    "internet_reachable": "InternetReachable",
    "agency_scope": "AgencyScope",
    "owner": "OwnerRole",
    "archetype": "Archetype",
}


def enumerate_live_tags(region_primary="us-east-2", region_edge="us-east-1"):
    """Live resource tags via the Resource Groups Tagging API, across both the
    primary region and the edge region (the DNSSEC KSK lives in us-east-1).
    Returns {arn: {tag_key: value}}. Raises on CLI failure so a broken
    enumeration fails the gate closed rather than silently reporting 'no drift'."""
    tags = {}
    for region in (region_primary, region_edge):
        token = None
        while True:
            args = ["resourcegroupstaggingapi", "get-resources",
                    "--region", region, "--output", "json"]
            if token:
                args += ["--pagination-token", token]
            out = subprocess.run(["aws", *args], capture_output=True, text=True)
            if out.returncode != 0:
                raise RuntimeError(f"aws {' '.join(args)} failed: {out.stderr.strip()}")
            resp = json.loads(out.stdout or "null") or {}
            for r in resp.get("ResourceTagMappingList", []):
                arn = r.get("ResourceARN")
                if arn:
                    tags[arn] = {t["Key"]: t["Value"] for t in r.get("Tags", [])}
            token = resp.get("PaginationToken")
            if not token:
                break
    return tags


def _match_live_tags(native_id, live_tags):
    """Find the live tag set for a component's native_id, tolerating the ARN-form
    differences the tagging API and Terraform sometimes disagree on (trailing
    ':*', prefix)."""
    target = (native_id or "").rstrip(":*")
    if not target:
        return None
    for arn, t in live_tags.items():
        a = arn.rstrip(":*")
        if a == target or a.startswith(target) or target.startswith(a):
            return t
    return None


def check_i_classification_tags(signal, live_tags):
    """Every reconciled resource's live classification tags must equal the
    inventory's projected classification. Fail closed on any drift."""
    violations = []
    our_tag_keys = set(CLASSIFICATION_TAG_MAP.values())
    for c in signal.get("components", []):
        cls = (c.get("attributes") or {}).get("classification")
        nid = c.get("native_id")
        if not cls or not nid:
            continue
        live = _match_live_tags(nid, live_tags)
        if live is None or not (our_tag_keys & set(live)):
            # Not a live resource we tag (bootstrap/global/non-cloud) — out of
            # scope for value reconciliation; presence is a separate concern.
            continue
        cid = c.get("component_id")
        for inv_key, tag_key in CLASSIFICATION_TAG_MAP.items():
            want = cls.get(inv_key)
            want = ("true" if want else "false") if inv_key == "internet_reachable" else str(want)
            got = live.get(tag_key)
            if got != want:
                violations.append(
                    f"(i) {cid}: live tag {tag_key}={got!r} != inventory {inv_key}={want!r}")
    return violations


# ----------------------------------------------------------------------------
# (b) referential — SSP components and POA&M assets resolve to inventory entries
# ----------------------------------------------------------------------------
def check_b_referential(signal, ssp, poam):
    violations = []
    comp_ids = inventory_component_ids(signal)
    native = inventory_native_ids(signal)
    known = comp_ids | native

    # SSP system-implementation components: each non-"this-system" component
    # should trace to an inventory entry by title/id/prop.
    si = (ssp.get("system-security-plan", {})
             .get("system-implementation", {}))
    for comp in si.get("components", []):
        title = comp.get("title", "")
        ctype = comp.get("type", "")
        if ctype == "this-system":
            continue
        props = {p.get("name"): p.get("value") for p in comp.get("props", []) or []}
        ref = props.get("inventory-component-id") or props.get("aws-arn") or title
        if ref and ref not in known and not any(ref in k or k in ref for k in known if k):
            # tolerate descriptive titles; only flag explicit id/arn props that miss
            if props.get("inventory-component-id") or props.get("aws-arn"):
                violations.append(f"(b) SSP component does not resolve to inventory: {ref}")

    # POA&M items: any explicit affected-resource prop must resolve.
    for item in (poam.get("plan-of-action-and-milestones", {}).get("poam-items", []) or []):
        for p in item.get("props", []) or []:
            if p.get("name") in ("affected-resource", "inventory-component-id", "aws-arn"):
                ref = p.get("value")
                if ref and ref not in known and not any(ref in k or k in ref for k in known if k):
                    violations.append(f"(b) POA&M asset does not resolve to inventory: {ref}")
    return violations


# ----------------------------------------------------------------------------
# (c) suppression categorization
# ----------------------------------------------------------------------------
def parse_checkov_skips(checkov_yaml_text):
    """Pull the CKV ids under skip-check: from .checkov.yaml (no yaml dep)."""
    skips = []
    in_block = False
    for line in checkov_yaml_text.splitlines():
        s = line.strip()
        if s.startswith("skip-check:"):
            in_block = True
            continue
        if in_block:
            m = re.match(r"-\s*(CKV[_A-Z0-9]+)", s)
            if m:
                skips.append(m.group(1))
            elif s and not s.startswith("#") and not s.startswith("-"):
                in_block = False
    return skips


def check_c_suppressions(checkov_skips, ckv_to_poam, poam_md_text, vdr,
                         false_positive_ckvs):
    """Every suppressed Checkov finding is categorized exactly once and the
    sources agree. Categories:
      risk-accepted  -> CKV maps to a POAM with a non-null poam_ref in the VDR
                        AND the POAM id appears in docs/poam.md
      false-positive -> CKV listed in the False Positives register
      remediated     -> suppression removed (so not in checkov_skips at all)
    """
    violations = []
    vdr_poam_refs = {r.get("poam_ref") for r in vdr.get("risk_accepted", []) if r.get("poam_ref")}
    for ckv in checkov_skips:
        is_fp = ckv in false_positive_ckvs
        poam_id = ckv_to_poam.get(ckv)
        is_ra = poam_id is not None
        if is_fp and is_ra:
            violations.append(f"(c) {ckv} is categorized as BOTH false-positive and risk-accepted")
            continue
        if not is_fp and not is_ra:
            violations.append(f"(c) suppressed {ckv} is uncategorized (not risk-accepted, false-positive, or remediated)")
            continue
        if is_ra:
            if poam_id not in vdr_poam_refs:
                violations.append(f"(c) {ckv} -> {poam_id} but {poam_id} has no non-null poam_ref in the VDR")
            if poam_id not in poam_md_text:
                violations.append(f"(c) {ckv} -> {poam_id} but {poam_id} is absent from docs/poam.md")
    return violations


# ----------------------------------------------------------------------------
# (d) impact level identical; nothing asserts Low
# ----------------------------------------------------------------------------
def extract_impacts(signal, ssp, poam, vdr, dashboard_html):
    impacts = {}
    impacts["signal"] = normalize_impact(
        signal.get("categorization", {}).get("impact_level"))
    impacts["ssp"] = normalize_impact(
        ssp.get("system-security-plan", {})
           .get("system-characteristics", {})
           .get("security-sensitivity-level"))
    poam_props = {p.get("name"): p.get("value")
                  for p in poam.get("plan-of-action-and-milestones", {})
                              .get("metadata", {}).get("props", []) or []}
    impacts["poam"] = normalize_impact(poam_props.get("impact-level"))
    impacts["vdr"] = normalize_impact(vdr.get("impact_level") or
                                      ("class " + vdr.get("class", "")).strip())
    # dashboard: look for an explicit Moderate / Low label
    if dashboard_html is not None:
        if re.search(r"FedRAMP Rev 5 Moderate", dashboard_html):
            impacts["dashboard"] = "moderate"
        elif re.search(r"FIPS-199 Low|FedRAMP Rev 5 Low", dashboard_html):
            impacts["dashboard"] = "low"
    return impacts


def check_d_impact(signal, ssp, poam, vdr, dashboard_html, expected="moderate"):
    violations = []
    impacts = extract_impacts(signal, ssp, poam, vdr, dashboard_html)
    for art, val in impacts.items():
        if val is None:
            violations.append(f"(d) {art} carries no extractable impact level")
        elif val != expected:
            violations.append(f"(d) {art} impact level is {val!r}, expected {expected!r}")
    return violations


# ----------------------------------------------------------------------------
# (e) binding — all artifacts carry the one inventory signal_id
# ----------------------------------------------------------------------------
def _first_prop(props, name):
    for p in props or []:
        if p.get("name") == name:
            return p.get("value")
    return None


def check_e_binding(signal, ssp, poam, vdr):
    violations = []
    sid = signal.get("signal_id")
    if not sid:
        return ["(e) signal has no signal_id"]
    ssp_md = ssp.get("system-security-plan", {}).get("metadata", {})
    ssp_sid = _first_prop(ssp_md.get("props"), "ksi-signal-source")
    poam_md = poam.get("plan-of-action-and-milestones", {}).get("metadata", {})
    poam_sid = _first_prop(poam_md.get("props"), "ksi-signal-id")
    vdr_sid = vdr.get("ksi_signal_id")
    for art, got in (("ssp", ssp_sid), ("poam", poam_sid), ("vdr", vdr_sid)):
        if got != sid:
            violations.append(f"(e) {art} signal_id {got!r} != inventory signal_id {sid!r}")
    return violations


# ----------------------------------------------------------------------------
# (f) publish freshness (staged half; live round-trip is Task 1.5)
# ----------------------------------------------------------------------------
def check_f_freshness(signal, ssp, poam, vdr, expected_commit):
    violations = []
    if not expected_commit:
        return violations  # not enforced outside CI
    commit = signal.get("provenance", {}).get("source", {}).get("commit")
    if commit != expected_commit:
        violations.append(f"(f) signal commit {commit!r} != current {expected_commit!r}")
    if not signal.get("emitted_at"):
        violations.append("(f) signal has no emitted_at")
    return violations


# ----------------------------------------------------------------------------
# (g) POA&M register parity — docs/poam.md <-> oscal-poam.json
# ----------------------------------------------------------------------------
def _formal_poam_ids_in_md(poam_md_text):
    """POA&M IDs that docs/poam.md tracks as FORMAL items: those appearing as a
    section header (### POAM-NNN) or as the first cell of a table row
    (| POAM-NNN | ...). IDs that occur only in prose cross-references (e.g.
    "see POAM-016") are deliberately NOT formal items and are excluded."""
    ids = set()
    for line in poam_md_text.splitlines():
        m = re.match(r"\s*#{1,6}\s*(POAM-\d{3})\b", line) or re.match(r"\s*\|\s*(POAM-\d{3})\b", line)
        if m:
            ids.add(m.group(1))
    return ids


def _all_vdr_findings(vdr):
    """Every finding the VDR carries, across all disposition buckets."""
    return (list(vdr.get("findings", []) or [])
            + list(vdr.get("risk_accepted", []) or [])
            + list(vdr.get("false_positives", []) or []))


def check_h_finding_coverage(vdr, poam):
    """(h) Every VDR finding — open, risk-accepted, or false-positive — must
    carry a poam_ref that resolves to a poam-item in the OSCAL POA&M. This is the
    invariant whose absence let 18 inline-suppressed / tfsec findings publish as
    open with a null poam_ref: a suppressed finding with no POA&M home, and an
    open finding with no remediation item, both fail closed here."""
    violations = []
    poam_ids = {
        p["value"]
        for item in (poam.get("plan-of-action-and-milestones", {}).get("poam-items", []) or [])
        for p in (item.get("props", []) or [])
        if p.get("name") == "poam-id" and p.get("value")
    }
    for f in _all_vdr_findings(vdr):
        ref = f.get("poam_ref")
        tid = f.get("tracking_id", "?")
        disp = f.get("current_disposition") or f.get("final_disposition") or "open"
        if not ref:
            violations.append(f"(h) VDR finding {tid!r} (disposition {disp}) has no poam_ref")
        elif ref not in poam_ids:
            violations.append(f"(h) VDR finding {tid!r} references {ref} which is not a POA&M item")
    return violations


# ----------------------------------------------------------------------------
# (j) POA&M reference validity — narrative cross-references resolve
# ----------------------------------------------------------------------------
# Generators embed POA&M IDs in narrative strings (baseline_configuration,
# SSP statements, VDR dispositions) as traceability pointers. The IDs are
# permanent, so referencing them is safe — but only if they resolve. Retired
# IDs stay referenceable for history without being register items.
RETIRED_POAM_IDS = {"POAM-016"}

_POAM_REF_RE = re.compile(r"POAM-\d{3}")


def check_j_poam_ref_validity(signal, ssp, poam, vdr):
    """(j) Every POAM-NNN string in a generated artifact must be a formal item
    in the OSCAL POA&M register or an explicitly retired ID."""
    poam_ids = {
        p["value"]
        for item in (poam.get("plan-of-action-and-milestones", {}).get("poam-items", []) or [])
        for p in (item.get("props", []) or [])
        if p.get("name") == "poam-id" and p.get("value")
    }
    ok = poam_ids | RETIRED_POAM_IDS
    violations = []
    for name, art in (("signal", signal), ("ssp", ssp), ("poam", poam), ("vdr", vdr)):
        refs = set(_POAM_REF_RE.findall(json.dumps(art)))
        for ref in sorted(refs - ok):
            violations.append(
                f"(j) {name} references {ref}, which is neither a POA&M item nor a retired ID")
    return violations


# ----------------------------------------------------------------------------
# (k) SCuBA bundle binding + derivation (presence-gated)
# ----------------------------------------------------------------------------
def check_k_scuba_binding(signal, ssp, scuba):
    """(k) The published SCuBA bundle must bind to the same inventory
    (ksi_signal_id) and derive from the same SSP (its policy set covers
    exactly the SSP's implemented-requirements control ids). Skipped when no
    bundle is staged."""
    if scuba is None:
        return []
    violations = []
    sid = signal.get("signal_id")
    if scuba.get("ksi_signal_id") != sid:
        violations.append(
            f"(k) scuba bundle ksi_signal_id {scuba.get('ksi_signal_id')!r} "
            f"!= inventory signal_id {sid!r}")
    ssp_ids = {
        r["control-id"]
        for r in ssp.get("system-security-plan", {})
        .get("control-implementation", {})
        .get("implemented-requirements", []) or []
    }
    bundle_ids = {p.get("control") for p in scuba.get("policies", []) or []}
    missing = sorted(ssp_ids - bundle_ids)
    extra = sorted(bundle_ids - ssp_ids)
    if missing:
        violations.append(
            f"(k) scuba bundle missing policies for {len(missing)} SSP "
            f"controls (first: {missing[:5]})")
    if extra:
        violations.append(
            f"(k) scuba bundle carries policies for {len(extra)} controls "
            f"not in the SSP (first: {extra[:5]})")
    return violations


def check_g_poam_parity(poam, poam_md_text):
    """(g) The OSCAL POA&M's item set must exactly equal the formal POA&M items
    in docs/poam.md. Both registers are hand-maintained; without this check they
    drift (a missing OSCAL item hides an open finding from a machine-readable
    consumer — the exact failure mode this gate exists to prevent)."""
    violations = []
    md_ids = _formal_poam_ids_in_md(poam_md_text)
    oscal_ids = {
        p["value"]
        for item in (poam.get("plan-of-action-and-milestones", {}).get("poam-items", []) or [])
        for p in (item.get("props", []) or [])
        if p.get("name") == "poam-id" and p.get("value")
    }
    for missing in sorted(md_ids - oscal_ids):
        violations.append(f"(g) {missing} is a formal item in docs/poam.md but is absent from the OSCAL POA&M")
    for extra in sorted(oscal_ids - md_ids):
        violations.append(f"(g) {extra} is in the OSCAL POA&M but is not a formal item in docs/poam.md")
    return violations


# ----------------------------------------------------------------------------
# runner
# ----------------------------------------------------------------------------
def run_all(signal, ssp, poam, vdr, dashboard_html, checkov_text,
            ckv_to_poam, poam_md_text, false_positive_ckvs,
            live_arns=None, expected_commit=None, live_tags=None, scuba=None):
    violations = []
    violations += check_d_impact(signal, ssp, poam, vdr, dashboard_html)
    violations += check_e_binding(signal, ssp, poam, vdr)
    violations += check_b_referential(signal, ssp, poam)
    violations += check_c_suppressions(parse_checkov_skips(checkov_text),
                                       ckv_to_poam, poam_md_text, vdr,
                                       false_positive_ckvs)
    violations += check_f_freshness(signal, ssp, poam, vdr, expected_commit)
    violations += check_g_poam_parity(poam, poam_md_text)
    violations += check_h_finding_coverage(vdr, poam)
    violations += check_j_poam_ref_validity(signal, ssp, poam, vdr)
    violations += check_k_scuba_binding(signal, ssp, scuba)
    if live_arns is not None:
        violations += check_a_completeness(signal, live_arns)
    if live_tags is not None:
        violations += check_i_classification_tags(signal, live_tags)
    return violations


def _load_ckv_to_poam():
    """Import the CKV->POAM map from the VDR builder (single source)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("_vdr", REPO / "scripts" / "build-vdr-report.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    for attr in ("POAM_BY_CHECK_ID", "CKV_TO_POAM", "CHECKOV_TO_POAM", "SUPPRESSION_POAM"):
        if hasattr(m, attr):
            return getattr(m, attr)
    return {}


def _load_false_positives(text=None):
    """CKV ids recorded in the docs/poam.md False Positives register."""
    if text is None:
        text = (REPO / "docs" / "poam.md").read_text()
    fp = set()
    in_fp = False
    for line in text.splitlines():
        low = line.lower()
        if "false positive" in low and line.lstrip().startswith("#"):
            in_fp = True
            continue
        if in_fp and line.lstrip().startswith("#") and "false positive" not in low:
            in_fp = False
        if in_fp:
            fp.update(re.findall(r"CKV[_A-Z0-9]+", line))
    return fp


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--artifacts-dir", default="infrastructure",
                    help="dir holding ksi-signal.json, oscal-ssp.json, oscal-poam.json, vdr-report.json")
    ap.add_argument("--live", action="store_true", help="enumerate live AWS for invariants (a) completeness and (i) classification tags (CI)")
    ap.add_argument("--live-fixture", default=None, help="JSON array of live ARNs (tests)")
    ap.add_argument("--live-tags-fixture", default=None, help="JSON object {arn: {tag: value}} of live resource tags (tests)")
    ap.add_argument("--expect-commit", default=os.environ.get("GITHUB_SHA"),
                    help="commit the staged artifacts must carry (invariant f)")
    ap.add_argument("--dashboard", default=str(REPO / "website" / "viewer.html"))
    ap.add_argument("--checkov", default=str(REPO / ".checkov.yaml"),
                    help="path to .checkov.yaml (overridable for hermetic tests)")
    ap.add_argument("--poam-md", default=str(REPO / "docs" / "poam.md"),
                    help="path to docs/poam.md (overridable for hermetic tests)")
    args = ap.parse_args()

    d = Path(args.artifacts_dir)
    try:
        signal = load_json(d / "ksi-signal.json")
        ssp = load_json(d / "oscal-ssp.json")
        poam = load_json(d / "oscal-poam.json")
        vdr = load_json(d / "vdr-report.json")
    except FileNotFoundError as e:
        print(f"reconcile: missing artifact: {e}", file=sys.stderr)
        return 2

    # Optional artifact: the SCuBA customer-assessment bundle (invariant k).
    # Presence-gated so pre-wiring checkouts and partial local builds still
    # reconcile; in CI the bundle is built before this gate runs.
    scuba_path = d / "scuba-bundle.json"
    scuba = load_json(scuba_path) if scuba_path.exists() else None

    dashboard_html = Path(args.dashboard).read_text() if Path(args.dashboard).exists() else None
    checkov_text = Path(args.checkov).read_text()
    poam_md_text = Path(args.poam_md).read_text()

    live_arns = None
    live_tags = None
    if args.live_fixture:
        live_arns = set(load_json(args.live_fixture))
    elif args.live:
        live_arns = enumerate_live_arns()
    if args.live_tags_fixture:
        live_tags = load_json(args.live_tags_fixture)
    elif args.live:
        # Rollout-safe: if the deploy role has not yet been granted
        # tag:GetResources, skip invariant (i) with a loud warning rather than
        # failing the whole gate closed. Any OTHER enumeration error still fails
        # closed (a broken read must never read as "no drift"). Once the
        # permission is provisioned, (i) activates automatically.
        try:
            live_tags = enumerate_live_tags()
        except RuntimeError as e:
            msg = str(e)
            if "AccessDenied" in msg or "not authorized" in msg.lower():
                print("::warning::reconcile: tag:GetResources not permitted; invariant (i) "
                      "classification-tag reconciliation skipped until the deploy role is "
                      "granted it (tag:GetResources).", file=sys.stderr)
                live_tags = None
            else:
                raise

    violations = run_all(
        signal, ssp, poam, vdr, dashboard_html, checkov_text,
        _load_ckv_to_poam(), poam_md_text, _load_false_positives(poam_md_text),
        live_arns=live_arns, expected_commit=args.expect_commit, live_tags=live_tags,
        scuba=scuba,
    )

    if violations:
        print(f"RECONCILIATION FAILED — {len(violations)} violation(s):", file=sys.stderr)
        for v in violations:
            print(f"  ✗ {v}", file=sys.stderr)
        return 1
    if live_arns is not None and live_tags is not None:
        checks = "a-j" + (",k" if scuba is not None else "")
    elif live_arns is not None:
        checks = "a-h,j" + (",k" if scuba is not None else "") + " (i deferred: no live tags)"
    else:
        checks = "b-h,j" + (",k" if scuba is not None else "") + " (a,i deferred: no --live)"
    print(f"reconciliation OK — invariants {checks} hold across signal/SSP/POA&M/VDR/dashboard")
    return 0


if __name__ == "__main__":
    sys.exit(main())
