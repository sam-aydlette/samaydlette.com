"""The corroboration sections beyond the boundary map.

Each section has the same shape:

    {"status": "agrees" | "differs" | "not_checked", "compared": int,
     "findings": [...], "source": str, "note": str}

The facts come from TAP (The Analogy Platform) or straight from the upstream
source the section names; the pipeline's own code never produces them. Each
judge below is a pure function over those facts, so each one is unit-tested
with a known-bad fixture (tests/test_corroborate_checks.py).

A section is `not_checked` when its source could not answer, and never
`agrees` by default: a check that compared nothing is not agreement.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

REPOSITORY = "sam-aydlette/samaydlette.com"
ISSUER = "https://token.actions.githubusercontent.com"
WORKFLOWS = {
    "deploy": ".github/workflows/deploy-with-opa.yml",
    "nightly": ".github/workflows/evidence-nightly.yml",
}


def expected_identity(signer: str) -> str:
    """The certificate identity of one publishing workflow, pinned to main."""
    return f"https://github.com/{REPOSITORY}/{WORKFLOWS[signer]}@refs/heads/main"


def section(findings: list[dict[str, Any]], compared: int, unchecked: list[dict[str, Any]] | None = None,
            *, source: str, note: str = "") -> dict[str, Any]:
    """Differences make a section `differs`; otherwise anything unchecked, or nothing
    compared at all, makes it `not_checked`."""
    unchecked = unchecked or []
    if findings:
        status = "differs"
    elif unchecked or compared == 0:
        status = "not_checked"
    else:
        status = "agrees"
    out = {"status": status, "compared": compared, "findings": findings, "source": source, "note": note}
    if unchecked:
        out["not_checked"] = unchecked
    return out


def not_checked(source: str, why: str) -> dict[str, Any]:
    return {"status": "not_checked", "compared": 0, "findings": [], "source": source, "note": why}


# ---------------------------------------------------------------------------
# 1. signatures
# ---------------------------------------------------------------------------

def signed_artifacts(freshness: dict[str, Any]) -> list[dict[str, Any]]:
    """Every artifact the governed freshness config says is signed with a Sigstore
    bundle or an in-toto attestation, with the workflows that may have signed it:
    those its `published_by` names. An artifact both workflows publish carries
    whichever signed it last. The operator-run report is left out (it would be
    checking itself), and so is the runtime signal (a KMS signature, checked in
    runtime_signing_key)."""
    out = []
    for a in freshness.get("artifacts", []):
        signers = [s for s in WORKFLOWS if s in a.get("published_by", [])]
        if not a.get("signed") or a.get("cadence") not in WORKFLOWS or not signers:
            continue
        p = a["path"]
        if p.endswith(".intoto.jsonl"):
            out.append({"artifact": p, "kind": "dsse", "subject": p[: -len(".intoto.jsonl")], "signers": signers})
        elif a.get("signature"):
            out.append({"artifact": p, "kind": "bundle", "bundle": a["signature"], "signers": signers})
    return out


def judge_signatures(facts: list[dict[str, Any]], artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    """Every signed artifact verifies against the Sigstore trust root, under the
    identity of a workflow that publishes it; an attestation's subject is the
    published artifact, byte for byte."""
    by_name = {f["artifact"]: f for f in facts}
    findings, unchecked = [], []
    compared = 0
    for a in artifacts:
        f = by_name.get(a["artifact"])
        name = a["artifact"].rsplit("/", 1)[-1]
        if f is None or f.get("fetch_error"):
            unchecked.append({"artifact": name, "why": (f or {}).get("fetch_error") or "not fetched"})
            continue
        compared += 1
        want = [expected_identity(s) for s in a["signers"]]
        if f.get("verified") is not True:
            findings.append({"artifact": name, "problem": "signature does not verify",
                             "detail": f.get("failure_code") or "unknown failure"})
            continue
        if f.get("signed_by") not in want:
            findings.append({"artifact": name, "problem": "signed by an unexpected identity",
                             "expected": " or ".join(want), "observed": f.get("signed_by")})
        if f.get("issuer") != ISSUER:
            findings.append({"artifact": name, "problem": "issued by an unexpected OIDC issuer",
                             "expected": ISSUER, "observed": f.get("issuer")})
        cert = f.get("cert") or {}
        if cert.get("ref") != "refs/heads/main":
            findings.append({"artifact": name, "problem": "signed from a ref other than main", "observed": cert.get("ref")})
        if a["kind"] == "dsse":
            want_digest = f.get("subject_sha256")
            subjects = f.get("subjects") or []
            if not want_digest or want_digest not in {s.get("sha256") for s in subjects}:
                findings.append({"artifact": name, "problem": "attestation subject is not the published artifact",
                                 "expected": want_digest, "observed": sorted(s.get("sha256") or "" for s in subjects)})
    return section(findings, compared, unchecked,
                   source="TAP sigstore_core (sigstore-python, production trust root)",
                   note="Re-verifies each published signature with a verifier that is not the deploy's cosign, "
                        "pinned to the identities of the workflows that publish the artifact.")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# 2. provenance
# ---------------------------------------------------------------------------

RUN_URI = re.compile(r"^https://github\.com/(?P<repo>[^/]+/[^/]+)/actions/runs/(?P<run>[0-9]+)/attempts/(?P<attempt>[0-9]+)$")


def judge_provenance(facts: list[dict[str, Any]], runs: list[dict[str, Any]], workflows: dict[str, str],
                     run_window: int) -> dict[str, Any]:
    """Each workflow run named in a signing certificate is one GitHub recorded: the
    same workflow, on main, from the same commit, triggered as the certificate says,
    and successful. Run IDs are used to match, never published."""
    by_run = {str(r["run_id"]): r for r in runs}
    seen: dict[str, dict[str, Any]] = {}
    for f in facts:
        cert = f.get("cert") or {}
        m = RUN_URI.match(str(cert.get("run_uri") or ""))
        if f.get("verified") is True and m:
            seen.setdefault(m.group("run"), {**cert, "repo": m.group("repo"), "artifacts": []})["artifacts"].append(
                f["artifact"].rsplit("/", 1)[-1])
    findings, unchecked, checked = [], [], []
    compared = 0
    for run_id, cert in seen.items():
        label = {"workflow": cert.get("workflow_path"), "commit": cert.get("commit"), "artifacts": len(cert["artifacts"])}
        r = by_run.get(run_id)
        if r is None:
            unchecked.append({**label, "why": f"the run is older than the {run_window} most recent runs TAP collected"})
            continue
        compared += 1
        checked.append(label)
        problems = []
        if cert["repo"] != REPOSITORY:
            problems.append("certificate names another repository")
        if workflows.get(str(r.get("workflow_id"))) != cert.get("workflow_path"):
            problems.append("GitHub records the run under a different workflow")
        if r.get("head_sha") != cert.get("commit"):
            problems.append("GitHub records the run at a different commit")
        if r.get("head_branch") != "main":
            problems.append("the run was not on main")
        if r.get("event") != cert.get("event"):
            problems.append("the run was triggered differently from what the certificate says")
        if r.get("conclusion") != "success":
            problems.append(f"the run concluded {r.get('conclusion') or 'without a result'}")
        if problems:
            findings.append({**label, "problems": problems})
    out = section(findings, compared, unchecked, source="TAP github_core (GitHub Actions run records)",
                  note="Matches each signing run to GitHub's own record of it. Commits are published; run IDs are not.")
    out["runs_checked"] = sorted(checked, key=lambda x: (x["workflow"] or "", x["commit"] or ""))
    return out


# ---------------------------------------------------------------------------
# 3. live_configuration
# ---------------------------------------------------------------------------

def _components(signal: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["component_id"]: c for c in signal.get("components", [])}


def _policy_passed(signal: dict[str, Any]) -> set[str]:
    """Components the deploy's own policy evaluation (terraform.compliance) passed."""
    out = set()
    for v in signal.get("validations", []):
        if (v.get("policy") or {}).get("id") == "terraform.compliance" and v.get("result") == "pass":
            out.update(v.get("component_refs") or [])
    return out


def _baseline(c: dict[str, Any]) -> str:
    return str((c.get("attributes") or {}).get("baseline_configuration") or "")


def live_claims(signal: dict[str, Any], tag_config: dict[str, Any]) -> list[dict[str, Any]]:
    """The properties the published artifacts claim about live AWS resources, each with
    the claim it comes from. A property is listed only where something published
    claims it."""
    comps = _components(signal)
    passed = _policy_passed(signal)
    claims: list[dict[str, Any]] = []

    def add(cid: str, prop: str, expect: Any, cite: str) -> None:
        claims.append({"component": cid, "property": prop, "expected": expect, "claim": cite})

    for cid, c in sorted(comps.items()):
        if not cid.startswith("aws::"):
            continue
        base, tf_type = _baseline(c), (c.get("attributes") or {}).get("tf_type")
        cite = f"ksi-signal.json {cid} baseline_configuration"
        if cid in passed:
            pcite = "terraform.compliance pass in ksi-signal.json"
            if tf_type == "aws_s3_bucket":
                for prop in ("versioning", "encryption", "public_access_blocked"):
                    add(cid, prop, True, pcite + " (infrastructure/policy/s3.rego)")
            if tf_type in set(tag_config.get("governance_tag_types", [])):
                add(cid, "tags_present", sorted(tag_config.get("required_tags", [])),
                    pcite + " (infrastructure/policy/tagging.rego required_tags)")
            if tf_type in set(tag_config.get("taggable_types", [])):
                add(cid, "classification_tags_present", sorted(tag_config.get("required_classification_tags", [])),
                    pcite + " (infrastructure/policy/tagging.rego required_classification_tags)")
        if c.get("type") == "object_store" and re.search(r"public access block", base, re.I) and cid not in passed:
            add(cid, "public_access_blocked", True, cite)
        if c.get("type") == "object_store" and re.search(r"\bversioning\b", base, re.I) and cid not in passed:
            add(cid, "versioning", True, cite)
        if c.get("type") == "object_store" and re.search(r"\bOAC\b", base):
            add(cid, "served_through_oac", True, cite)
        m = re.search(r"(\d+)-day retention", base)
        if c.get("type") == "log_group" and m:
            add(cid, "retention_in_days", int(m.group(1)), cite)
        if c.get("type") == "identity_provider" and re.search(r"MFA ON", base):
            add(cid, "mfa_configuration", "ON", cite)
        if c.get("type") == "audit_log_trail" and re.search(r"management-event capture", base):
            add(cid, "is_logging", True, cite)
        m = re.search(r"Trust policy bound to ([a-z0-9.-]+\.amazonaws\.com)", base)
        if c.get("type") == "iam_role" and m:
            add(cid, "trusted_services", [m.group(1)], cite)
        if c.get("type") == "iam_role" and re.search(r"GitHub OIDC provider.*no AWS service principal", base):
            add(cid, "trusted_services", [], cite)
            add(cid, "trusts_wildcard_principal", False, cite)
        if c.get("type") == "iam_group" and re.search(r"authenticate with MFA", base):
            add(cid, "members_have_mfa", True, cite)
    return claims


# What the published artifacts claim but TAP does not read, so nothing here is
# presented as checked.
LIVE_NOT_COVERED = [
    "CloudFront HTTP-to-HTTPS redirect and TLS minimum (infrastructure/policy/cloudfront.rego): aws_core does not collect viewer protocol policy or the TLS security policy",
    "S3 bucket policies (deny non-TLS, CloudTrail and log delivery grants): aws_core does not collect bucket policies",
    "KMS module validation, DNSSEC signing, API Gateway throttling and access logging, SNS and SQS encryption, DynamoDB recovery: not collected by aws_core",
    "IAM inline policy bodies (hashed in the inventory): not compared",
]


def judge_live(claims: list[dict[str, Any]], live: dict[str, dict[str, Any]],
               group_members: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Compare each claim with the value TAP read from AWS. `live` is keyed by
    component_id (the boundary comparison already matched TAP's resources to the
    inventory by ARN). An empty field means the collector did not read it: not
    checked, never a pass or a failure."""
    findings, unchecked = [], []
    compared = 0
    for cl in claims:
        cid, prop, want = cl["component"], cl["property"], cl["expected"]
        f = live.get(cid)
        base = {"component": cid, "property": prop, "claim": cl["claim"]}
        if f is None and prop != "members_have_mfa":
            unchecked.append({**base, "why": "TAP did not observe this resource"})
            continue
        if prop == "members_have_mfa":
            members = group_members.get(cid)
            if members is None:
                unchecked.append({**base, "why": "group membership was not read"})
                continue
            # MFA is required of human members, i.e. those with a console password.
            # Machine members authenticate with access keys and have no password.
            # Member names are not published (some are email addresses).
            if any("console" not in u for u in members):
                unchecked.append({**base, "why": "console sign-in was not read for every member"})
                continue
            compared += 1
            humans = [u for u in members if u["console"]]
            without = sum(1 for u in humans if u.get("mfa_enabled") is not True)
            if without:
                findings.append({**base, "expected": "every member with a console password has an MFA device",
                                 "observed": f"{without} of {len(humans)} console member(s) have no MFA device"})
            continue
        if prop in ("tags_present", "classification_tags_present"):
            tags = f.get("tags")
            if not isinstance(tags, dict):
                unchecked.append({**base, "why": "TAP did not read tags"})
                continue
            compared += 1
            missing = [t for t in want if t not in tags]
            if missing:
                findings.append({**base, "expected": want, "observed": f"missing {', '.join(missing)}"})
            continue
        observed = f.get(prop)
        if prop == "versioning":
            if not observed:
                unchecked.append({**base, "why": "aws_core leaves s3_bucket.versioning empty (field declared, not populated)"})
                continue
            ok = str(observed).lower() == "enabled"
        elif prop == "encryption":
            if not observed:
                unchecked.append({**base, "why": "aws_core leaves s3_bucket.encryption empty (field declared, not populated)"})
                continue
            ok = True
        elif prop == "trusted_services":
            if observed is None:
                unchecked.append({**base, "why": "TAP did not read the trust policy"})
                continue
            ok = sorted(observed) == sorted(want)
        else:
            if observed is None or observed == "":
                unchecked.append({**base, "why": f"TAP did not read {prop}"})
                continue
            ok = observed == want
        compared += 1
        if not ok:
            findings.append({**base, "expected": want, "observed": observed})
    out = section(findings, compared, unchecked, source="TAP aws_core (AWS APIs, read-only role)",
                  note="Compares what the published artifacts claim about live resources with what AWS reports. "
                       "Only claimed properties are compared.")
    out["not_covered"] = LIVE_NOT_COVERED
    return out


def live_values(tap: dict[str, Any], matched: dict[str, str], signal: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """TAP's fields per inventory component, plus the derived `served_through_oac`
    (a CloudFront origin reaching the bucket through Origin Access Control)."""
    by_id = {e["id"]: e for e in tap.get("entities", [])}
    out = {cid: dict(by_id[eid]["fields"]) for eid, cid in matched.items() if eid in by_id}
    dists = [e for e in tap.get("entities", []) if e["type"] == "cloudfront_distribution"]
    comps = _components(signal)
    for cid, f in out.items():
        if comps.get(cid, {}).get("type") != "object_store":
            continue
        name = str(f.get("name") or "")
        access = [v for d in dists for k, v in (d["fields"].get("origin_access") or {}).items() if name and name in k]
        f["served_through_oac"] = all(v == "oac" for v in access) if access else None
    return out


# ---------------------------------------------------------------------------
# 4. runtime_signing_key
# ---------------------------------------------------------------------------

def der_sha256_of_pem(pem: str) -> str:
    import base64
    body = "".join(ln for ln in pem.strip().splitlines() if not ln.startswith("-----"))
    return sha256_hex(base64.b64decode(body))


def judge_signing_key(kms_der_sha256: str | None, published_pem: str | None, pinned: dict[str, Any],
                      runtime: dict[str, Any] | None) -> dict[str, Any]:
    """The key KMS holds is the key the site publishes and the repository pins, and
    the runtime signal verifies under it."""
    src = "AWS KMS GetPublicKey with TAP's read-only credential; published PEM; pinned key record"
    if not kms_der_sha256:
        return not_checked(src, "KMS public key was not read")
    findings = []
    compared = 0
    if published_pem:
        compared += 1
        if der_sha256_of_pem(published_pem) != kms_der_sha256:
            findings.append({"problem": "the published runtime-signing-pubkey.pem is not the key KMS holds"})
    pinned_pem = pinned.get("public_key_pem")
    if pinned_pem:
        compared += 1
        if der_sha256_of_pem(pinned_pem) != kms_der_sha256:
            findings.append({"problem": "the key pinned in infrastructure/keys/runtime-signing-key.json is not the key KMS holds"})
    if runtime is not None:
        compared += 1
        if not runtime.get("verified"):
            findings.append({"problem": "the published runtime signal does not verify under the KMS key",
                             "detail": runtime.get("reason")})
        elif not runtime.get("fresh"):
            findings.append({"problem": "the runtime signal verifies but is stale", "detail": runtime.get("reason")})
    out = section(findings, compared, source=src,
                  note="Reads the public half of the runtime signing key from KMS, compares it with the published and "
                       "pinned copies, and verifies the runtime signal with the builder's own verification code.")
    out["key_sha256"] = kms_der_sha256
    if runtime is not None:
        out["runtime_signal_emitted_at"] = runtime.get("emitted_at")
    return out


# ---------------------------------------------------------------------------
# 5. vulnerabilities
# ---------------------------------------------------------------------------

def judge_vulnerabilities(observability: str | None, alerts: list[dict[str, Any]] | None,
                          vdr: dict[str, Any]) -> dict[str, Any]:
    """Every open Dependabot alert GitHub holds is a finding or a disposition in the VDR."""
    src = "TAP github_core (Dependabot alerts) against the published VDR"
    if observability != "observed" or alerts is None:
        return not_checked(src, f"Dependabot alerts were not readable by TAP's GitHub credential ({observability or 'unknown'}).")
    known: set[str] = set()
    for key in ("findings", "risk_accepted"):
        for f in vdr.get(key, []) or []:
            for k in ("cve", "ghsa", "tool_id", "advisory"):
                if f.get(k):
                    known.add(str(f[k]).upper())
            for a in f.get("aliases", []) or []:
                known.add(str(a).upper())
    findings = []
    open_alerts = [a for a in alerts if a.get("state") == "open"]
    for a in open_alerts:
        ids = {str(x).upper() for x in (a.get("cve_id"), a.get("ghsa_id")) if x}
        if not ids & known:
            findings.append({"advisory": a.get("cve_id") or a.get("ghsa_id"), "package": a.get("package_name"),
                             "problem": "open on GitHub, absent from the VDR"})
    out = section(findings, len(open_alerts), source=src,
                  note="Open alerts only; dismissed and fixed alerts are not compared.")
    if not open_alerts:
        out["status"] = "agrees"  # GitHub readable and reports nothing open: a real comparison
    return out


# ---------------------------------------------------------------------------
# 6. ksi_catalog
# ---------------------------------------------------------------------------

def ksi_ids(rules: dict[str, Any]) -> set[str]:
    """The KSI IDs in FedRAMP's consolidated rules (KSI.<family>.indicators...)."""
    out: set[str] = set()

    def walk(o: Any) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                if isinstance(k, str) and re.fullmatch(r"KSI-[A-Z]{3}-[A-Z]{3}", k):
                    out.add(k)
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(rules.get("KSI", {}))
    return out


def judge_ksi_catalog(signal: dict[str, Any], upstream: dict[str, Any] | None, upstream_commit: str | None,
                      pinned_commit: str) -> dict[str, Any]:
    src = "FedRAMP/rules at upstream HEAD, read directly (TAP's KSI catalog collector fails the current schema)"
    if upstream is None:
        return not_checked(src, "FedRAMP/rules could not be read")
    up = ksi_ids(upstream)
    if not up:
        return not_checked(src, "no KSI IDs found in the upstream rules (has the file's shape changed?)")
    claimed = {k["id"] for k in signal.get("ksis", [])}
    findings = [{"ksi": k, "problem": "claimed by the site, not in FedRAMP's current rules"} for k in sorted(claimed - up)]
    out = section(findings, len(claimed), source=src,
                  note="Every KSI the signal claims exists in FedRAMP's current rules. Unclaimed upstream KSIs are "
                       "reported for information.")
    out["upstream_commit"] = upstream_commit
    out["pinned_commit"] = pinned_commit
    out["upstream_not_claimed"] = sorted(up - claimed)
    return out


# ---------------------------------------------------------------------------

SECTION_ORDER = ("boundary", "signatures", "provenance", "live_configuration", "runtime_signing_key",
                 "vulnerabilities", "ksi_catalog")


def overall(checks: dict[str, dict[str, Any]]) -> str:
    """`agrees` only when every section agrees; `differs` if any differs;
    otherwise `incomplete`."""
    missing = [s for s in SECTION_ORDER if s not in checks]
    statuses = [checks[s]["status"] for s in SECTION_ORDER if s in checks]
    if "differs" in statuses:
        return "differs"
    if missing or "not_checked" in statuses:
        return "incomplete"
    return "agrees"


def canonical(o: Any) -> str:
    return json.dumps(o, sort_keys=True, separators=(",", ":"))
