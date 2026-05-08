#!/usr/bin/env python3
# =============================================================================
# DEPLOY-TIME KSI SIGNAL EMITTER
# =============================================================================
# Produces ksi-signal.json — a FedRAMP 20x-style KSI validation signal extended
# with normalized component identifiers, as proposed in
# https://samaydlette.com/pages/article-27.html.
#
# Inputs (joined into one signal):
#   - terraform output -json            → ARNs of deployed AWS resources
#   - terraform show -json              → full state, used for resource discovery
#   - lambda/package-lock.json          → npm packages inside the compliance Lambda
#   - ../website/**/*.html              → static HTML artifacts (sha256-hashed)
#   - validations.json                  → OPA results from scripts/terraform-plan.sh
#   - GITHUB_* env vars                 → SLSA-style build provenance (when in CI)
#
# Output:
#   - ksi-signal.json — conforms to schemas/ksi-signal.schema.json
#
# Run from the infrastructure/ directory:
#   python3 ../scripts/build-ksi-signal.py
# =============================================================================

import hashlib
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# =============================================================================
# CONSTANTS
# =============================================================================
# These are the cross-CSP normalization decisions called out explicitly in the
# accompanying research paper. Adding a new CSP means extending TYPE_BY_TF_TYPE
# (and possibly the schema's component.type enum) — the join keys themselves
# (PURL for software, native ARN/ID for cloud, sha256 for static content)
# don't need to change.
# =============================================================================

SIGNAL_VERSION = "1.0.0"
SYSTEM_ID = "urn:samaydlette:website-prod"
CSP = "aws"

# Maps Terraform resource types to the normalized component.type vocabulary in
# the schema. Resource types that aren't a "component" in the portfolio sense
# (IAM bindings, bucket-attached config like versioning/encryption, log groups)
# are absent on purpose — their effect is folded into attributes on the parent
# component, not represented as separate components.
TYPE_BY_TF_TYPE = {
    "aws_s3_bucket": "object_store",
    "aws_cloudfront_distribution": "cdn_distribution",
    "aws_lambda_function": "function",
}

# Resource types that fold into a parent component as attributes. The mapping
# value is the parent component's normalized type — used to find the parent.
ATTRIBUTE_PARENTS = {
    "aws_s3_bucket_versioning": "object_store",
    "aws_s3_bucket_server_side_encryption_configuration": "object_store",
    "aws_s3_bucket_public_access_block": "object_store",
    "aws_s3_bucket_policy": "object_store",
    "aws_cloudfront_response_headers_policy": "cdn_distribution",
}

# =============================================================================
# MAS (Minimum Assessment Scope) attributes per component type
# =============================================================================
# Per FedRAMP 20x rule MAS-CSO-FLO, every information resource must declare a
# FIPS 199 security category and an information-flow summary. The defaults
# below are the system-specific assignments for samaydlette.com; another system
# would override these with its own categorization.
#
# Categorization rationale: this is a public static site with no PII, so
# confidentiality is LOW everywhere. Integrity is MODERATE because defacement
# is the highest-impact realistic threat. Availability is LOW because a
# personal site can tolerate downtime within the declared 21-day RTO.
# High-water mark across the system: MODERATE (driven by integrity).
# =============================================================================

MAS_DEFAULTS = {
    "object_store": {
        "security_category": {"confidentiality": "low", "integrity": "moderate", "availability": "low"},
        "information_flow": [
            {"direction": "inbound", "counterparty": "cdn_distribution", "channel": "aws-internal-tls", "data_class": "public-content"},
            {"direction": "outbound", "counterparty": "cdn_distribution", "channel": "aws-internal-tls", "data_class": "public-content"},
            {"direction": "inbound", "counterparty": "github-actions", "channel": "tls-1.2", "data_class": "public-content"},
        ],
    },
    "cdn_distribution": {
        "security_category": {"confidentiality": "low", "integrity": "moderate", "availability": "low"},
        "information_flow": [
            {"direction": "inbound", "counterparty": "public-internet", "channel": "tls-1.2", "data_class": "public-content"},
            {"direction": "outbound", "counterparty": "public-internet", "channel": "tls-1.2", "data_class": "public-content"},
            {"direction": "inbound", "counterparty": "object_store", "channel": "aws-internal-tls", "data_class": "public-content"},
        ],
    },
    "function": {
        "security_category": {"confidentiality": "low", "integrity": "moderate", "availability": "low"},
        "information_flow": [
            {"direction": "inbound", "counterparty": "eventbridge", "channel": "aws-internal-tls", "data_class": "configuration"},
            {"direction": "outbound", "counterparty": "aws-service-api", "channel": "aws-internal-tls", "data_class": "configuration"},
            {"direction": "outbound", "counterparty": "object_store", "channel": "aws-internal-tls", "data_class": "audit"},
        ],
    },
    "npm_package": {
        "security_category": {"confidentiality": "not-applicable", "integrity": "moderate", "availability": "not-applicable"},
        "information_flow": [],
    },
    "html_artifact": {
        "security_category": {"confidentiality": "low", "integrity": "moderate", "availability": "low"},
        "information_flow": [
            {"direction": "outbound", "counterparty": "object_store", "channel": "aws-internal-tls", "data_class": "public-content"},
        ],
    },
}

# =============================================================================
# IIW (Integrated Inventory Workbook) attributes per component type
# =============================================================================
# Stamped onto component.attributes so the canonical inventory carries the
# fields the FedRAMP IIW (SSP Appendix M) requires. The build-iiw.py projector
# reads these to emit an IIW-compatible CSV.
# =============================================================================

IIW_DEFAULTS = {
    "object_store": {
        "function": "Origin storage for static site content and /.well-known/ artifacts",
        "diagram_label": "S3 origin bucket",
        "public": False,
        "baseline_configuration": "AWS S3 default + bucket policy enforcing OAC + public access block",
        "iiw_asset_type": "Object Storage (S3 bucket)",
    },
    "cdn_distribution": {
        "function": "Public content delivery (TLS 1.2+, OAC to origin)",
        "diagram_label": "CloudFront distribution",
        "public": True,
        "baseline_configuration": "AWS CloudFront default + custom security headers policy",
        "iiw_asset_type": "Content Delivery Network (CloudFront distribution)",
    },
    "function": {
        "function": "Daily runtime KSI emitter; revalidates live AWS configuration",
        "diagram_label": "Lambda — runtime KSI emitter",
        "public": False,
        "baseline_configuration": "AWS Lambda default + IAM scope (read 3 S3 config APIs, 1 CF distribution; write 1 S3 key)",
        "iiw_asset_type": "Compute Function (Lambda)",
    },
    "npm_package": {
        "function": "Lambda runtime dependency",
        "diagram_label": "Open-source policy and signing tooling running inside CI",
        "public": False,
        "baseline_configuration": "package-lock.json integrity hash; Dependabot-monitored",
        "iiw_asset_type": "Software Package (npm)",
    },
    "html_artifact": {
        "function": "Public site content",
        "diagram_label": "S3 origin bucket (content)",
        "public": True,
        "baseline_configuration": "Static HTML served via CloudFront; SHA-256 content-addressed in canonical inventory",
        "iiw_asset_type": "Static Content Artifact",
    },
}


def apply_iiw_defaults(component):
    """Stamp IIW-mapped attribute keys onto a component per its type.

    These attributes carry the fields the FedRAMP Integrated Inventory
    Workbook (Appendix M) requires. They live in component.attributes
    because the schema treats attributes as free-form (additionalProperties),
    and projecting into IIW shape is a downstream concern that does not
    require a schema change.
    """
    defaults = IIW_DEFAULTS.get(component["type"])
    if defaults is None:
        return
    component.setdefault("attributes", {})
    for key, value in defaults.items():
        component["attributes"].setdefault(key, value)


def apply_mas_defaults(component):
    """Stamp security_category and information_flow onto a component per its type.

    The schema requires both fields on every component. The defaults table
    above is the system-level categorization decision; passing through here
    makes that decision explicit and auditable rather than implicit.
    """
    defaults = MAS_DEFAULTS.get(component["type"])
    if defaults is None:
        # Unknown type: assign conservative not-applicable / empty so the
        # signal still validates against the schema. The schema's enum on
        # component.type will catch genuinely unknown types upstream.
        component["security_category"] = {
            "confidentiality": "not-applicable",
            "integrity": "not-applicable",
            "availability": "not-applicable",
        }
        component["information_flow"] = []
        return
    component["security_category"] = dict(defaults["security_category"])
    component["information_flow"] = [dict(f) for f in defaults["information_flow"]]


# =============================================================================
# HELPERS
# =============================================================================


def run_terraform(args):
    """Run a terraform subcommand and return parsed JSON, or None on failure."""
    try:
        result = subprocess.run(
            ["terraform", *args],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(result.stdout)
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"warning: terraform {' '.join(args)} failed: {exc}", file=sys.stderr)
        return None


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def component_id_for_cloud(tf_resource_name, normalized_type):
    return f"{CSP}::{normalized_type}::{tf_resource_name}"


def component_id_for_npm(name, version):
    return f"npm::{name}@{version}"


def component_id_for_html(rel_path):
    return f"html::{rel_path}"


# =============================================================================
# COMPONENT BUILDERS
# =============================================================================


def build_cloud_components(tf_state, tf_outputs):
    """Walk Terraform state into normalized cloud components.

    Resources with their own slot in the schema's type enum become components.
    Resources in ATTRIBUTE_PARENTS get folded into the parent's attributes so
    a portfolio consumer sees one bucket with encryption/versioning/etc., not
    five separate things to reconcile.
    """
    components_by_id = {}
    state_resources = []

    if tf_state and "values" in tf_state:
        root = tf_state["values"].get("root_module", {})
        state_resources = root.get("resources", [])
        # Recurse into child modules if any exist (this repo has none today).
        for child in root.get("child_modules", []) or []:
            state_resources.extend(child.get("resources", []))

    # First pass: create the primary components.
    for r in state_resources:
        tf_type = r.get("type")
        tf_name = r.get("name")
        if tf_type not in TYPE_BY_TF_TYPE:
            continue
        normalized = TYPE_BY_TF_TYPE[tf_type]
        cid = component_id_for_cloud(tf_name, normalized)
        values = r.get("values", {}) or {}

        attrs = {
            "tf_address": r.get("address"),
            "tf_type": tf_type,
            "tf_name": tf_name,
        }
        # Pull a few common, non-sensitive identifying attributes if present.
        for key in ("region", "runtime", "function_name", "id", "domain_name"):
            if key in values and values[key] is not None:
                attrs[key] = values[key]

        # Prefer the ARN exposed via terraform output (canonical, post-apply).
        native_id = None
        if normalized == "object_store":
            native_id = (tf_outputs or {}).get("s3_bucket_arn", {}).get("value") or values.get("arn")
        elif normalized == "cdn_distribution":
            native_id = (tf_outputs or {}).get("cloudfront_distribution_arn", {}).get("value") or values.get("arn")
        elif normalized == "function":
            native_id = (tf_outputs or {}).get("lambda_function_arn", {}).get("value") or values.get("arn")

        component = {
            "component_id": cid,
            "type": normalized,
            "attributes": attrs,
        }
        if native_id:
            component["native_id"] = native_id
        apply_mas_defaults(component)
        apply_iiw_defaults(component)
        components_by_id[cid] = component

    # Second pass: fold attribute resources into their parent.
    for r in state_resources:
        tf_type = r.get("type")
        if tf_type not in ATTRIBUTE_PARENTS:
            continue
        parent_type = ATTRIBUTE_PARENTS[tf_type]
        # Find the matching parent. For this single-system site, name-matching
        # the bucket reference / distribution reference is sufficient; in a
        # larger system the parent reference would need explicit traversal.
        for cid, comp in components_by_id.items():
            if comp["type"] != parent_type:
                continue
            short_attr_key = tf_type.replace(f"aws_{parent_type.split('_')[0]}_", "")
            comp.setdefault("attributes", {}).setdefault("config", {})[short_attr_key] = (
                r.get("values", {})
            )
            break

    return list(components_by_id.values())


def build_npm_components(lock_path):
    """Read package-lock.json (lockfileVersion 3) and emit npm components."""
    if not lock_path.exists():
        return []
    try:
        lock = json.loads(lock_path.read_text())
    except json.JSONDecodeError:
        print(f"warning: could not parse {lock_path}", file=sys.stderr)
        return []
    components = []
    for path, info in (lock.get("packages") or {}).items():
        if path == "":
            # The root package is the Lambda itself, not a dependency.
            continue
        name = info.get("name") or path.split("node_modules/", 1)[-1]
        version = info.get("version")
        if not name or not version:
            continue
        purl = f"pkg:npm/{name}@{version}"
        component = {
            "component_id": component_id_for_npm(name, version),
            "type": "npm_package",
            "global_id": {"purl": purl},
            "attributes": {
                "name": name,
                "version": version,
                "lockfile_path": path,
                "integrity": info.get("integrity"),
            },
        }
        apply_mas_defaults(component)
        apply_iiw_defaults(component)
        components.append(component)
    return components


def build_html_components(website_root):
    """Hash every HTML file under the website/ tree as an html_artifact."""
    if not website_root.is_dir():
        return []
    components = []
    for html_path in sorted(website_root.rglob("*.html")):
        rel = html_path.relative_to(website_root).as_posix()
        digest = sha256_file(html_path)
        component = {
            "component_id": component_id_for_html(rel),
            "type": "html_artifact",
            "global_id": {"sha256": digest},
            "attributes": {
                "path": rel,
                "size_bytes": html_path.stat().st_size,
            },
        }
        apply_mas_defaults(component)
        apply_iiw_defaults(component)
        components.append(component)
    return components


# =============================================================================
# VALIDATION JOINER
# =============================================================================


def build_validations(validations_doc, components):
    """Convert OPA results into schema-conformant validations[].

    Each result names the components it evaluated via component_refs. That join
    field is the entire point of the article-27 proposal: the validation result
    is no longer a per-system black box but composes across CSPs because every
    consumer can match on component_refs.
    """
    component_ids = {c["component_id"] for c in components}
    by_html_path = {
        c["attributes"]["path"]: c["component_id"]
        for c in components
        if c["type"] == "html_artifact"
    }
    by_cloud_name = {}
    for c in components:
        if c["type"] in {"object_store", "cdn_distribution", "function"}:
            tf_name = c.get("attributes", {}).get("tf_name")
            if tf_name:
                by_cloud_name[(c["type"], tf_name)] = c["component_id"]

    validations = []
    skipped = 0
    for idx, result in enumerate(validations_doc.get("results") or []):
        kind = result.get("kind")
        compliant = result.get("compliant")
        violations = result.get("violations") or []
        policy_version = result.get("policy_version") or "unknown"
        refs = []

        if kind == "infrastructure":
            tf_type = result.get("resource_type")
            tf_name = result.get("resource_name")
            normalized = TYPE_BY_TF_TYPE.get(tf_type)
            if normalized:
                cid = by_cloud_name.get((normalized, tf_name))
                if cid:
                    refs = [cid]
            # Resources outside the schema's component vocabulary (IAM, log
            # groups, attribute-only resources) are intentionally skipped.
            if not refs:
                skipped += 1
                continue
        elif kind == "accessibility":
            file_path = result.get("file_path") or ""
            # file_path is relative to the directory terraform-plan.sh ran in
            # (infrastructure/), pointing at ../website/<rel>. Normalize.
            normalized_path = file_path.split("website/", 1)[-1] if "website/" in file_path else file_path
            cid = by_html_path.get(normalized_path)
            if cid:
                refs = [cid]
            if not refs:
                skipped += 1
                continue
        else:
            skipped += 1
            continue

        # Sanity: refs must exist in this signal's components.
        refs = [r for r in refs if r in component_ids]
        if not refs:
            skipped += 1
            continue

        validations.append({
            "validation_id": f"v-{idx:04d}",
            "policy": {
                "id": "terraform.compliance",
                "version": policy_version,
            },
            "result": "pass" if compliant else "fail",
            "component_refs": refs,
            "violations": violations,
        })

    if skipped:
        print(f"info: skipped {skipped} OPA results that did not map to schema component types", file=sys.stderr)
    return validations


# =============================================================================
# PROVENANCE
# =============================================================================


def build_provenance():
    """Read GITHUB_* env vars when running in Actions; fall back to local."""
    repo = os.environ.get("GITHUB_REPOSITORY")
    workflow = os.environ.get("GITHUB_WORKFLOW")
    run_id = os.environ.get("GITHUB_RUN_ID")
    sha = os.environ.get("GITHUB_SHA")
    ref = os.environ.get("GITHUB_REF")

    if repo and workflow and sha:
        builder_id = f"https://github.com/{repo}/.github/workflows/{workflow}"
        provenance = {
            "builder": {
                "id": builder_id,
                "run_id": run_id or "unknown",
                "version": "github-actions",
            },
            "source": {
                "repository": f"https://github.com/{repo}",
                "commit": sha,
                "ref": ref or "unknown",
            },
        }
        # When the CI deploy is going to sign this signal, pre-populate the
        # attestation reference *before* signing so the cosign signature
        # covers it. The bundle itself is published as a sidecar at this URL.
        # KSI_SIGN=1 is set by the CI step that runs cosign sign-blob; absent
        # locally so unsigned signals don't claim a bundle they don't have.
        if os.environ.get("KSI_SIGN") == "1":
            provenance["attestation"] = {
                "format": "sigstore-bundle",
                "url": "https://samaydlette.com/.well-known/ksi-signal.bundle",
                "verification": {
                    "tool": "cosign",
                    "certificate_identity_regexp": f"https://github.com/{repo}/.github/workflows/.+",
                    "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
                },
            }
        return provenance

    # Local fallback. Try git for the commit; the rest is best-effort.
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        commit = "0000000"
    return {
        "builder": {
            "id": "local",
            "run_id": "local",
            "version": "local",
        },
        "source": {
            "repository": "https://github.com/sam-aydlette/samaydlette.com",
            "commit": commit,
            "ref": "local",
        },
    }


# =============================================================================
# MAIN
# =============================================================================


def main():
    cwd = Path.cwd()
    repo_root = cwd.parent
    website_root = repo_root / "website"
    lambda_lock = cwd / "lambda" / "package-lock.json"
    validations_path = cwd / "validations.json"
    schema_id = "https://samaydlette.com/.well-known/ksi-signal.schema.json"
    output_path = cwd / "ksi-signal.json"

    tf_outputs = run_terraform(["output", "-json"]) or {}
    tf_state = run_terraform(["show", "-json"]) or {}

    components = []
    components.extend(build_cloud_components(tf_state, tf_outputs))
    components.extend(build_npm_components(lambda_lock))
    components.extend(build_html_components(website_root))

    if validations_path.exists():
        validations_doc = json.loads(validations_path.read_text())
    else:
        print(f"warning: {validations_path} not found; emitting empty validations[]", file=sys.stderr)
        validations_doc = {"results": []}

    validations = build_validations(validations_doc, components)

    signal = {
        "$schema": schema_id,
        "signal_version": SIGNAL_VERSION,
        "signal_id": str(uuid.uuid4()),
        "emitted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "emitter": "deploy",
        "csp": CSP,
        "system_id": SYSTEM_ID,
        "provenance": build_provenance(),
        "components": components,
        "validations": validations,
        "ownership": {
            "system_owner": "Sam Aydlette",
            "application_owner": "Sam Aydlette",
            "operator_contact": "sam.aydlette@gmail.com",
        },
        "disclosure": {
            "authorization_status": "self-attested-proof-of-concept",
            "fedramp_certified": False,
            "remarks": (
                "This system is not FedRAMP-authorized. The artifacts published "
                "at /.well-known/ are self-attested by the operator and "
                "demonstrate an architectural pattern aligned with FedRAMP "
                "NTC-0009 (machine-readable authorization data, text-based "
                "equivalents, the five Balance Improvement Releases folding "
                "into default requirements). See "
                "https://samaydlette.com/research/the-plumbing.html for "
                "context and limitations."
            ),
            "related_artifacts": {
                "oscal_ssp": "https://samaydlette.com/.well-known/oscal-ssp.json",
                "oscal_poam": "https://samaydlette.com/.well-known/oscal-poam.json",
                "vdr_report": "https://samaydlette.com/.well-known/vdr-report.json",
                "iiw_csv": "https://samaydlette.com/.well-known/iiw.csv",
                "runtime_signal": "https://samaydlette.com/.well-known/ksi-signal-runtime.json",
                "boundary_diagram": "https://samaydlette.com/research/authorization-boundary.html",
                "research_paper": "https://samaydlette.com/research/the-plumbing.html",
            },
        },
    }

    output_path.write_text(json.dumps(signal, indent=2) + "\n")
    print(
        f"Wrote {output_path} "
        f"({len(components)} components, {len(validations)} validations)"
    )


if __name__ == "__main__":
    main()
