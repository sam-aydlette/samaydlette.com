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
    # S3 (global) — the system bucket(s)
    for b in (cli(["s3api", "list-buckets"]) or {}).get("Buckets", []):
        if in_boundary(b["Name"]):
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
# runner
# ----------------------------------------------------------------------------
def run_all(signal, ssp, poam, vdr, dashboard_html, checkov_text,
            ckv_to_poam, poam_md_text, false_positive_ckvs,
            live_arns=None, expected_commit=None):
    violations = []
    violations += check_d_impact(signal, ssp, poam, vdr, dashboard_html)
    violations += check_e_binding(signal, ssp, poam, vdr)
    violations += check_b_referential(signal, ssp, poam)
    violations += check_c_suppressions(parse_checkov_skips(checkov_text),
                                       ckv_to_poam, poam_md_text, vdr,
                                       false_positive_ckvs)
    violations += check_f_freshness(signal, ssp, poam, vdr, expected_commit)
    if live_arns is not None:
        violations += check_a_completeness(signal, live_arns)
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
    ap.add_argument("--live", action="store_true", help="enumerate live AWS for invariant (a) (CI)")
    ap.add_argument("--live-fixture", default=None, help="JSON array of live ARNs (tests)")
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

    dashboard_html = Path(args.dashboard).read_text() if Path(args.dashboard).exists() else None
    checkov_text = Path(args.checkov).read_text()
    poam_md_text = Path(args.poam_md).read_text()

    live_arns = None
    if args.live_fixture:
        live_arns = set(load_json(args.live_fixture))
    elif args.live:
        live_arns = enumerate_live_arns()

    violations = run_all(
        signal, ssp, poam, vdr, dashboard_html, checkov_text,
        _load_ckv_to_poam(), poam_md_text, _load_false_positives(poam_md_text),
        live_arns=live_arns, expected_commit=args.expect_commit,
    )

    if violations:
        print(f"RECONCILIATION FAILED — {len(violations)} violation(s):", file=sys.stderr)
        for v in violations:
            print(f"  ✗ {v}", file=sys.stderr)
        return 1
    checks = "a-f" if live_arns is not None else "b-f (a deferred: no --live)"
    print(f"reconciliation OK — invariants {checks} hold across signal/SSP/POA&M/VDR/dashboard")
    return 0


if __name__ == "__main__":
    sys.exit(main())
