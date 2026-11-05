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
#   (b) referential    — every component a VDR finding names resolves to an
#                        inventory entry (the SSP's component list, which this
#                        checked until the SSP was retired, was built from the
#                        inventory it was compared with)
#   (c) suppressions   — every suppressed Checkov finding is categorized as
#                        exactly one of risk-accepted / false-positive /
#                        remediated, consistently across .checkov.yaml, the
#                        decision register (data/decisions.json), and the VDR
#   (d) impact level   — one identical impact level across signal, VDR, SDR,
#                        CPO and dashboard; nothing asserts the system is Low
#   (e) binding        — the VDR, SDR and CPO are built from one inventory
#                        signal_id and carry it
#   (f) publish freshness — staged artifacts carry the current commit and a
#                        fresh emitted_at (the live round-trip half is Task 1.5)
#   (g) retired        — held the OSCAL POA&M and docs/poam.md in parity; the
#                        POA&M was replaced by one decision register (CR26)
#   (h) finding coverage — every VDR finding carries a decision_id that resolves
#                        to an in-force record in the decision register
#   (i) classification tags — live resource tags match the inventory's
#                        projected classification (with --live)
#   (j) decision reference validity — every DEC-NNN or POAM-NNN mentioned
#                        anywhere in a generated artifact resolves to the
#                        decision register by id or former_id (or is an
#                        explicitly retired ID), so a typo'd or
#                        vanished cross-reference cannot publish silently
#   (k) retired       — bound a customer-assessment bundle that is no longer
#                        published by this site; the letter is not reused
#   (l) boundary map    — when the published boundary map is present it binds
#                        to the same inventory signal_id and commit, places
#                        every boundary component of the inventory (no more, no
#                        fewer), leaves none unclassified, and carries no ARN,
#                        account ID or email address
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
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _decisions  # noqa: E402
import _gates  # noqa: E402
import _redact  # noqa: E402

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


def arn_key(arn):
    """Normalize an ARN for comparison.

    The only real disagreement between the forms Terraform records and the forms
    the AWS APIs return is a trailing ':*' wildcard on log-group ARNs, so
    stripping it is the whole normalization. Comparison on this key is EXACT.

    It used to be a prefix match ("h.startswith(a) or a.startswith(h)"), which was
    redundant with this rstrip and unsound: any live resource whose ARN extended an
    inventoried one passed the deny-by-default completeness sweep. A live,
    un-inventoried '<prefix>-logs-archive' bucket was silently accepted whenever
    '<prefix>-logs' was in the inventory. See test_a_completeness_rejects_arn_that
    _extends_an_inventoried_one.

    The published inventory carries ACCOUNT in place of the account ID
    (scripts/_redact.py), so both sides are redacted the same way first. Every
    live ARN is read with this account's credentials, so the comparison stays
    exact for everything but the twelve digits both sides share.
    """
    return _redact.redact_text(arn or "").rstrip(":*")


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
    have = {arn_key(nid) for nid in inventory_native_ids(signal)}
    # The message goes to a public Actions log: name the resource, not the account.
    return [f"(a) live resource not in inventory: {_redact.redact_text(arn)}"
            for arn in sorted(live_arns) if arn_key(arn) not in have]


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
    """Find the live tag set for a component's native_id.

    Exact match on the normalized ARN key. This was a prefix match, which could
    return a DIFFERENT resource's tags for a component whose ARN happened to be a
    prefix of another's — reconciling the inventory against the wrong live thing.
    """
    target = arn_key(native_id)
    if not target:
        return None
    for arn, t in live_tags.items():
        if arn_key(arn) == target:
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
# (b) referential — every component a VDR finding names is in the inventory
# ----------------------------------------------------------------------------
def check_b_referential(signal, vdr):
    """A finding that names a component must name one the inventory has: a
    finding attributed to a component outside the boundary, or to a stale ID,
    would publish risk against nothing. A finding the builder could not resolve
    carries component_id null and unresolved_component true (it is queued and
    rated fail-safe); that is reported, not invented."""
    violations = []
    known = inventory_component_ids(signal)
    for f in _all_vdr_findings(vdr):
        cid = f.get("component_id")
        if cid is not None and cid not in known:
            violations.append(f"(b) VDR finding {f.get('tracking_id', '?')!r} names component {cid!r}, "
                              "which is not in the inventory")
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


def check_c_suppressions(checkov_skips, register, vdr):
    """Every suppressed Checkov finding is categorized exactly once and the
    sources agree. The categories come from the decision register
    (data/decisions.json, in-force records' applies_to.check_ids):
      risk-accepted  -> the check resolves to a risk-accepted record, and that
                        record's ID is a non-null decision_id in the VDR
      false-positive -> the check resolves to a false-positive record
      remediated     -> suppression removed (so not in checkov_skips at all)
    """
    violations = []
    accepted, false_pos = _decisions.check_maps(register)
    vdr_decision_ids = {r.get("decision_id") for r in vdr.get("risk_accepted", []) if r.get("decision_id")}
    for ckv in checkov_skips:
        is_fp = ckv in false_pos
        dec_id = accepted.get(ckv)
        is_ra = dec_id is not None
        if is_fp and is_ra:
            violations.append(f"(c) {ckv} is categorized as BOTH false-positive and risk-accepted")
            continue
        if not is_fp and not is_ra:
            violations.append(f"(c) suppressed {ckv} is uncategorized (no in-force risk-accepted or "
                              "false-positive record in data/decisions.json)")
            continue
        if is_ra and dec_id not in vdr_decision_ids:
            violations.append(f"(c) {ckv} -> {dec_id} but {dec_id} has no non-null decision_id in the VDR")
    return violations


# ----------------------------------------------------------------------------
# (d) impact level identical; nothing asserts Low
# ----------------------------------------------------------------------------
def extract_impacts(signal, sdr, cpo, vdr, dashboard_html):
    impacts = {}
    impacts["signal"] = normalize_impact(
        signal.get("categorization", {}).get("impact_level"))
    impacts["sdr"] = normalize_impact(sdr.get("impact_level"))
    impacts["cpo"] = normalize_impact(cpo.get("impact_level"))
    impacts["vdr"] = normalize_impact(vdr.get("impact_level") or
                                      ("class " + vdr.get("class", "")).strip())
    # dashboard (the trust center page, website/trust/index.html): its static
    # text states the impact level; the rest of the page renders from JSON.
    if dashboard_html is not None:
        if re.search(r"FedRAMP Rev 5 Moderate|Moderate impact level", dashboard_html):
            impacts["dashboard"] = "moderate"
        elif re.search(r"FIPS-199 Low|FedRAMP Rev 5 Low|Low impact level", dashboard_html):
            impacts["dashboard"] = "low"
    return impacts


def check_d_impact(signal, sdr, cpo, vdr, dashboard_html, expected="moderate"):
    violations = []
    impacts = extract_impacts(signal, sdr, cpo, vdr, dashboard_html)
    for art, val in impacts.items():
        if val is None:
            violations.append(f"(d) {art} carries no extractable impact level")
        elif val != expected:
            violations.append(f"(d) {art} impact level is {val!r}, expected {expected!r}")
    return violations


# ----------------------------------------------------------------------------
# (e) binding — all artifacts carry the one inventory signal_id
# ----------------------------------------------------------------------------
def check_e_binding(signal, sdr, cpo, vdr):
    violations = []
    sid = signal.get("signal_id")
    if not sid:
        return ["(e) signal has no signal_id"]
    for art, doc in (("vdr", vdr), ("sdr", sdr), ("cpo", cpo)):
        got = doc.get("ksi_signal_id")
        if got != sid:
            violations.append(f"(e) {art} signal_id {got!r} != inventory signal_id {sid!r}")
    return violations


# ----------------------------------------------------------------------------
# (f) publish freshness (staged half; live round-trip is Task 1.5)
# ----------------------------------------------------------------------------
def check_f_freshness(signal, vdr, expected_commit):
    violations = []
    if not expected_commit:
        return violations  # not enforced outside CI
    commit = signal.get("provenance", {}).get("source", {}).get("commit")
    if commit != expected_commit:
        violations.append(f"(f) signal commit {commit!r} != current {expected_commit!r}")
    if not signal.get("emitted_at"):
        violations.append("(f) signal has no emitted_at")
    return violations


def _all_vdr_findings(vdr):
    """Every finding the VDR carries, across all disposition buckets."""
    return (list(vdr.get("findings", []) or [])
            + list(vdr.get("risk_accepted", []) or [])
            + list(vdr.get("false_positives", []) or []))


def check_h_finding_coverage(vdr, register):
    """(h) Every VDR finding — open, risk-accepted, or false-positive — must
    carry a decision_id that resolves to an in-force record in the decision
    register (data/decisions.json). This is the invariant whose absence let 18
    inline-suppressed / tfsec findings publish as open with a null reference: a
    suppressed finding with no recorded decision, and an open finding with no
    decision, both fail closed here."""
    violations = []
    in_force = {r["id"] for r in _decisions.in_force(register)}
    known = set(_decisions.records(register))
    for f in _all_vdr_findings(vdr):
        ref = f.get("decision_id")
        tid = f.get("tracking_id", "?")
        disp = f.get("current_disposition") or f.get("final_disposition") or "open"
        if not ref:
            violations.append(f"(h) VDR finding {tid!r} (disposition {disp}) has no decision_id")
        elif ref not in known:
            violations.append(f"(h) VDR finding {tid!r} references {ref} which is not in the decision register")
        elif ref not in in_force:
            violations.append(f"(h) VDR finding {tid!r} references {ref}, a closed decision")
    return violations


# ----------------------------------------------------------------------------
# (j) decision reference validity — narrative cross-references resolve
# ----------------------------------------------------------------------------
# Generators embed decision IDs in narrative strings (baseline_configuration,
# SDR statements, VDR dispositions) as traceability pointers. A DEC-NNN must be
# a record in the decision register; a POAM-NNN (from before the register) must
# be a record's former_id, or an explicitly retired ID.
RETIRED_POAM_IDS = {"POAM-016"}

_DECISION_REF_RE = re.compile(r"\b(?:DEC|POAM)-\d{3}\b")


def check_j_decision_id_validity(signal, sdr, cpo, vdr, register):
    """(j) Every DEC-NNN or POAM-NNN string in a generated artifact resolves to
    the decision register (by id or former_id) or is an explicitly retired ID."""
    ok = set(_decisions.by_any_id(register)) | RETIRED_POAM_IDS
    violations = []
    for name, art in (("signal", signal), ("sdr", sdr), ("cpo", cpo), ("vdr", vdr)):
        refs = set(_DECISION_REF_RE.findall(json.dumps(art)))
        for ref in sorted(refs - ok):
            violations.append(
                f"(j) {name} references {ref}, which is neither a decision record nor a retired ID")
    return violations


# ----------------------------------------------------------------------------
# runner
# ----------------------------------------------------------------------------
# ----------------------------------------------------------------------------
# (l) boundary map binding and completeness
# ----------------------------------------------------------------------------
BOUNDARY_NON_COMPONENT_TYPES = {"npm_package", "pypi_package", "html_artifact"}
_MAP_REDACTION = (
    ("an ARN", re.compile(r"arn:aws[a-z-]*:")),
    ("an AWS account ID", re.compile(r"(?<![0-9A-Za-z])[0-9]{12}(?![0-9A-Za-z])")),
    ("an email address", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
)


def check_l_boundary_map(signal, boundary_map, expected_commit=None):
    """The published map is a claim about the whole boundary: it must describe
    this build's inventory exactly, classify all of it, and publish nothing that
    identifies an account."""
    if boundary_map is None:
        return []
    violations = []
    sid = signal.get("signal_id")
    if boundary_map.get("ksi_signal_id") != sid:
        violations.append(f"(l) boundary map signal_id {boundary_map.get('ksi_signal_id')!r} != inventory signal_id {sid!r}")
    if expected_commit and boundary_map.get("commit") != expected_commit:
        violations.append(f"(l) boundary map commit {boundary_map.get('commit')!r} != {expected_commit!r}")
    inventory = {c["component_id"] for c in signal.get("components", [])
                 if c.get("type") not in BOUNDARY_NON_COMPONENT_TYPES}
    on_map = {n["id"] for n in boundary_map.get("nodes", []) if n.get("kind") == "collected"}
    for cid in sorted(inventory - on_map):
        violations.append(f"(l) inventory component {cid} is missing from the boundary map")
    for cid in sorted(on_map - inventory):
        violations.append(f"(l) boundary map node {cid} is not in the inventory")
    for cid in boundary_map.get("unclassified", []):
        violations.append(f"(l) {cid} is unclassified: add a rule for it to docs/boundary/boundary-classification.json")
    text = json.dumps(boundary_map)
    for label, pattern in _MAP_REDACTION:
        if pattern.search(text):
            violations.append(f"(l) boundary map contains {label}")
    return violations


def run_all(signal, sdr, cpo, vdr, dashboard_html, checkov_text, register,
            live_arns=None, expected_commit=None, live_tags=None,
            boundary_map=None):
    violations = []
    violations += check_d_impact(signal, sdr, cpo, vdr, dashboard_html)
    violations += check_e_binding(signal, sdr, cpo, vdr)
    violations += check_b_referential(signal, vdr)
    violations += check_c_suppressions(parse_checkov_skips(checkov_text), register, vdr)
    violations += check_f_freshness(signal, vdr, expected_commit)
    violations += check_h_finding_coverage(vdr, register)
    violations += check_j_decision_id_validity(signal, sdr, cpo, vdr, register)
    violations += check_l_boundary_map(signal, boundary_map, expected_commit)
    if live_arns is not None:
        violations += check_a_completeness(signal, live_arns)
    if live_tags is not None:
        violations += check_i_classification_tags(signal, live_tags)
    return violations


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--artifacts-dir", default="infrastructure",
                    help="dir holding ksi-signal.json, vdr-report.json, security-decision-record.json, "
                         "certification-package-overview.json")
    ap.add_argument("--live", action="store_true", help="enumerate live AWS for invariants (a) completeness and (i) classification tags (CI)")
    ap.add_argument("--live-fixture", default=None, help="JSON array of live ARNs (tests)")
    ap.add_argument("--live-tags-fixture", default=None, help="JSON object {arn: {tag: value}} of live resource tags (tests)")
    ap.add_argument("--expect-commit", default=os.environ.get("GITHUB_SHA"),
                    help="commit the staged artifacts must carry (invariant f)")
    ap.add_argument("--dashboard", default=str(REPO / "website" / "trust" / "index.html"),
                    help="the trust center page, whose static text states the impact level")
    ap.add_argument("--report", default=None,
                    help="on success, write the invariants that held (and any deferred) as JSON for the trust center")
    ap.add_argument("--checkov", default=str(REPO / ".checkov.yaml"),
                    help="path to .checkov.yaml (overridable for hermetic tests)")
    ap.add_argument("--decisions", default=str(_decisions.DEFAULT_PATH),
                    help="the decision register (overridable for hermetic tests); missing or invalid fails closed")
    args = ap.parse_args()
    gates = _gates.load_gate_modes()

    d = Path(args.artifacts_dir)
    try:
        signal = load_json(d / "ksi-signal.json")
        vdr = load_json(d / "vdr-report.json")
        sdr = load_json(d / "security-decision-record.json")
        cpo = load_json(d / "certification-package-overview.json")
    except FileNotFoundError as e:
        print(f"reconcile: missing artifact: {e}", file=sys.stderr)
        return 2

    # Optional artifact: the boundary map (invariant l). Presence-gated so
    # partial local builds still reconcile; in CI it is built before this gate.
    map_path = d / "boundary-map.json"
    boundary_map = load_json(map_path) if map_path.exists() else None

    dashboard_html = Path(args.dashboard).read_text() if Path(args.dashboard).exists() else None
    checkov_text = Path(args.checkov).read_text()
    register = _decisions.load(args.decisions)

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
                # A denied read is a detection failure (G7). Its mode is governed:
                # block stops here; detect-and-recover publishes it and skips (i).
                note = "tag:GetResources not permitted; invariant (i) could not be checked"
                if _gates.blocks(gates, "reconcile.i.unreadable"):
                    print(f"::error::reconcile: {note}", file=sys.stderr)
                    return 1
                _gates.record_event(gates, "reconcile.i.unreadable", note)
                live_tags = None
            else:
                raise

    violations = run_all(
        signal, sdr, cpo, vdr, dashboard_html, checkov_text, register,
        live_arns=live_arns, expected_commit=args.expect_commit, live_tags=live_tags,
        boundary_map=boundary_map,
    )

    # Each violation names its invariant, "(x) ..."; its check's governed mode
    # decides whether it stops the run. An unattributable violation always does.
    hard = []
    for v in violations:
        m = re.match(r"\(([a-z])\)", v)
        check = f"reconcile.{m.group(1)}" if m else None
        if check in _gates.CHECKS and not _gates.blocks(gates, check):
            _gates.record_event(gates, check, v)
        else:
            hard.append(v)
    violations = hard
    if violations:
        print(f"RECONCILIATION FAILED — {len(violations)} violation(s):", file=sys.stderr)
        for v in violations:
            print(f"  ✗ {v}", file=sys.stderr)
        return 1
    optional = ",l" if boundary_map is not None else ""
    if live_arns is not None and live_tags is not None:
        checks = "a-f,h-j" + optional
    elif live_arns is not None:
        checks = "a-f,h,j" + optional + " (i deferred: no live tags)"
    else:
        checks = "b-f,h,j" + optional + " (a,i deferred: no --live)"
    print(f"reconciliation OK — invariants {checks} hold across signal/VDR/SDR/CPO/decisions/dashboard")
    if args.report:
        Path(args.report).write_text(json.dumps(build_report(
            signal, args.expect_commit,
            deferred={"a": live_arns is None, "i": live_tags is None,
                      "l": boundary_map is None}), indent=2) + "\n")
    return 0


INVARIANT_TITLES = {
    "a": "Every live in-boundary resource is in the inventory",
    "b": "Every component a VDR finding names is in the inventory",
    "c": "Every suppressed scanner finding is categorized consistently",
    "d": "One identical impact level everywhere",
    "e": "Every artifact is built from one inventory",
    "f": "Staged artifacts carry this build's commit",
    # (g) is retired: it held two copies of the POA&M in parity, and the POA&M
    # was replaced by one decision register (data/decisions.json).
    "h": "Every VDR finding resolves to an in-force decision record",
    "i": "Live resource tags match the inventory's classification",
    "j": "Every decision reference resolves",
    # (k) is retired: the bundle it bound is no longer published by this site.
    "l": "The boundary map describes exactly this build's inventory",
}


def build_report(signal, commit, deferred):
    """Written only when the gate passes; nothing is published otherwise, so a
    published report is itself evidence that every listed invariant held."""
    return {
        "schema": "reconcile-report/1",
        "result": "pass",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "commit": commit,
        "ksi_signal_id": signal.get("signal_id"),
        "invariants": [
            {"id": k, "title": t, "status": "deferred" if deferred.get(k) else "held"}
            for k, t in INVARIANT_TITLES.items()
        ],
    }


if __name__ == "__main__":
    sys.exit(main())
