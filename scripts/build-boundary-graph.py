#!/usr/bin/env python3
# =============================================================================
# BOUNDARY MAP BUILDER
# =============================================================================
# Builds the authorization-boundary map the trust center draws, on every deploy,
# from what the pipeline already knows is true:
#
#   nodes  = the canonical inventory's cloud and external-service components
#            (ksi-signal.json), placed into zones and groups by the operator's
#            classification (docs/boundary/boundary-classification.json), plus
#            the classification's declared nodes (actors outside the boundary,
#            services not yet inventoried);
#   edges  = a reference graph over Terraform state for both stacks: whenever a
#            resource's configuration names another component (by ARN, id or
#            name, including inside policy documents), the two are connected.
#            That is what makes blast radius and exposure paths computable;
#   flows  = the classification's data-flow table, resolved against real nodes.
#
# Nothing here is drawn by hand. The map carries no ARNs, account IDs or email
# addresses (fail closed), because it is published and committed nowhere else.
# A component no rule places is reported as unclassified; the reconciliation gate
# fails the deploy on it (invariant l), so a new resource is classified in the
# same change that adds it.
#
#   build-boundary-graph.py --ksi-signal ksi-signal.json \
#       --classification ../docs/boundary/boundary-classification.json \
#       --state tfstate-main.json --state tfstate-bootstrap.json \
#       --offering ../data/cds/offering.json --vdr vdr-report.json \
#       --trust-root-plan trust-root-plan.json --output boundary-map.json
# =============================================================================

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "samaydlette-boundary-map/1"

# The inventory's package and content components are not boundary resources.
NON_BOUNDARY_TYPES = {"npm_package", "pypi_package", "html_artifact"}

# Classification axes that are public by design (docs/policies/resource-tagging-standard.md).
PUBLIC_CLASSIFICATION = ("archetype", "data_sensitivity", "mission_criticality", "internet_reachable")
CLASSIFICATION_TAGS = ("DataSensitivity", "MissionCriticality", "InternetReachable", "AgencyScope", "OwnerRole", "Archetype")

REDACTION_CHECKS = {
    "ARN": re.compile(r"arn:aws[a-z-]*:"),
    "AWS account ID": re.compile(r"(?<![0-9A-Za-z])[0-9]{12}(?![0-9A-Za-z])"),
    "email address": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
}

# Resources that exist to connect two components. When one of these names
# several components, they are linked to each other. Anything else that is not
# itself a component (a policy-document data source, an uninventoried role) is
# ignored: it would link everything it merely mentions, and blast radius would
# stop meaning anything.
CONNECTOR_TYPES = {
    "aws_lambda_permission",
    "aws_lambda_event_source_mapping",
    "aws_cloudwatch_event_target",
    "aws_apigatewayv2_integration",
    "aws_apigatewayv2_stage",
    "aws_apigatewayv2_authorizer",
    "aws_cognito_user_pool_client",
    "aws_cognito_user_pool_domain",
    "aws_s3_bucket_policy",
    "aws_s3_bucket_logging",
    "aws_s3_bucket_notification",
    "aws_sns_topic_policy",
    "aws_sns_topic_subscription",
    "aws_cloudwatch_log_resource_policy",
    "aws_route53_query_log",
    "aws_route53_record",
    "aws_iam_role_policy_attachment",
    "aws_kms_alias",
}

# A name two components share (an EventBridge rule and the Lambda it invokes are
# both called "samaydlette-com-opa-compliance") identifies neither on its own.
# Where the attribute holding it says what kind of thing it names, that settles
# it: an event target's "rule" is a rule, a permission's "function_name" a function.
REFERENCE_TYPE_HINTS = {
    "rule": "event_schedule",
    "function_name": "function",
    "user_pool_id": "identity_provider",
    "zone_id": "dns_zone",
    "hosted_zone_id": "dns_zone",
    "bucket": "object_store",
    "role": "iam_role",
    "role_name": "iam_role",
    "api_id": "api_gateway",
    "certificate_arn": "tls_certificate",
    "acm_certificate_arn": "tls_certificate",
}

# Values too generic to identify a resource by exact match.
MIN_IDENTITY_LEN = 6
# Policy documents and similar blobs are scanned for ARNs; skip anything larger
# (Lambda packages' hashes and archives are not references).
MAX_SCAN_LEN = 200_000


# -----------------------------------------------------------------------------
# Terraform state (either `terraform show -json` output or a raw v4 state file)
# -----------------------------------------------------------------------------
def state_resources(state: dict[str, Any]) -> Iterable[dict[str, Any]]:
    """Yield {address, type, mode, values} for every resource instance."""
    if "values" in state:  # terraform show -json
        def walk(module: dict[str, Any]) -> Iterable[dict[str, Any]]:
            for r in module.get("resources", []):
                yield {"address": r["address"], "type": r["type"], "mode": r.get("mode", "managed"), "values": r.get("values") or {}}
            for child in module.get("child_modules", []):
                yield from walk(child)
        yield from walk(state.get("values", {}).get("root_module", {}))
        return
    for r in state.get("resources", []):  # raw v4 state
        prefix = "data." if r.get("mode") == "data" else ""
        for inst in r.get("instances", []):
            key = inst.get("index_key")
            suffix = "" if key is None else (f"[{key}]" if isinstance(key, int) else f'["{key}"]')
            yield {
                "address": f"{prefix}{r['type']}.{r['name']}{suffix}",
                "type": r["type"],
                "mode": r.get("mode", "managed"),
                "values": inst.get("attributes") or {},
            }


def keyed_strings(value: Any, key: str | None = None) -> Iterable[tuple[str | None, str]]:
    """Every string in a resource's values, with the attribute name it sits under."""
    if isinstance(value, str):
        if len(value) <= MAX_SCAN_LEN:
            yield key, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from keyed_strings(v, k)
    elif isinstance(value, list):
        for v in value:
            yield from keyed_strings(v, key)


def url_tail(value: str) -> str | None:
    """The last path segment of an https URL: a Cognito issuer URL ends in its pool id."""
    if not value.startswith("https://"):
        return None
    tail = value.rstrip("/").rsplit("/", 1)[-1]
    return tail if len(tail) >= MIN_IDENTITY_LEN else None


# -----------------------------------------------------------------------------
# Classification
# -----------------------------------------------------------------------------
def group_for(component_id: str, groups: list[dict[str, Any]]) -> dict[str, Any] | None:
    for g in groups:
        if any(fnmatch.fnmatchcase(component_id, pattern) for pattern in g.get("match", [])):
            return g
    return None


def display_name(
    component: dict[str, Any],
    resource_values: dict[str, Any] | None = None,
    kms_aliases: dict[str, str] | None = None,
) -> str:
    """A public, human name: the resource's own name, never its ARN or an opaque id."""
    attrs = component.get("attributes") or {}
    values = resource_values or {}
    ctype = component.get("type")
    if ctype == "kms_key":
        alias = (kms_aliases or {}).get(str(values.get("key_id") or values.get("id") or ""))
        if alias:
            return alias.removeprefix("alias/")
    if ctype == "cdn_distribution" and values.get("aliases"):
        return f"{sorted(values['aliases'])[0]} (CloudFront)"
    if ctype == "tls_certificate" and values.get("domain"):
        return f"{values['domain']} (ACM)"
    if ctype == "dns_zone" and values.get("name"):
        return f"{str(values['name']).rstrip('.')} (Route 53)"
    for key in ("name", "function_name", "policy_name"):
        if isinstance(attrs.get(key), str) and attrs[key]:
            return attrs[key]
    # Terraform's own name for the resource beats an opaque service id (an API
    # Gateway id, a Cognito pool id).
    name = (resource_values or {}).get("name")
    if isinstance(name, str) and name and not name.startswith("arn:"):
        return name
    native = str(component.get("native_id") or "")
    if native.startswith("arn:"):
        resource = native.split(":", 5)[-1]
        if resource.startswith("log-group:"):
            return resource[len("log-group:"):].removesuffix(":*")
        return resource.split("/")[-1].split(":")[-1]
    if native.startswith("iam-role-policy::"):
        return native.split("/")[-1]
    return component["component_id"].split("::")[-1]


# -----------------------------------------------------------------------------
# Build
# -----------------------------------------------------------------------------
def build(
    signal: dict[str, Any],
    classification: dict[str, Any],
    states: list[dict[str, Any]],
    offering: dict[str, Any],
    vdr: dict[str, Any] | None,
    trust_root_plan: dict[str, Any] | None,
    commit: str,
    now: str,
) -> dict[str, Any]:
    groups = classification["groups"]

    components = [c for c in signal.get("components", []) if c.get("type") not in NON_BOUNDARY_TYPES]

    # Terraform resources by stack-qualified address, to reach each component's
    # configuration (tags, references).
    resources: list[dict[str, Any]] = []
    for st in states:
        resources.extend(state_resources(st))
    by_address: dict[str, dict[str, Any]] = {}
    for r in resources:
        by_address.setdefault(r["address"], r)
    managed_by_arn = {str(r["values"]["arn"]): r for r in resources
                      if r["mode"] == "managed" and isinstance(r["values"].get("arn"), str)}
    kms_aliases = {
        str(r["values"].get("target_key_id")): str(r["values"].get("name"))
        for r in resources
        if r["type"] == "aws_kms_alias" and r["values"].get("target_key_id") and r["values"].get("name")
    }

    # Findings per component (the VDR resolves each finding's component).
    findings: dict[str, dict[str, int]] = {}
    for f in (vdr or {}).get("findings", []) + (vdr or {}).get("risk_accepted", []):
        cid = f.get("component_id")
        if not cid:
            continue
        agg = findings.setdefault(cid, {"total": 0, "open": 0, "blocking": 0, "kev": 0})
        agg["total"] += 1
        if (f.get("current_disposition") or "open") == "open":
            agg["open"] += 1
        agg["blocking"] += bool(f.get("is_blocking"))
        agg["kev"] += bool(f.get("is_kev"))

    pending_addresses = {c["address"] for c in (trust_root_plan or {}).get("changes", [])}

    nodes: list[dict[str, Any]] = []
    owners: dict[str, set[str]] = {}  # exact identifier -> the components it names
    component_type: dict[str, str] = {}
    arn_index: list[tuple[str, str]] = []  # (ARN, component_id) for substring matches in documents
    resource_component: dict[str, str] = {}  # terraform address -> component_id
    unclassified: list[str] = []

    for c in components:
        cid = c["component_id"]
        attrs = c.get("attributes") or {}
        g = group_for(cid, groups)
        if g is None:
            unclassified.append(cid)
        tf_address = str(attrs.get("tf_address") or "")
        res = by_address.get(tf_address) if tf_address else None
        if res is not None:
            resource_component[tf_address] = cid
        # A resource one stack manages and another reads (the CloudFront
        # distribution: managed by the bootstrap stack, a data source in the
        # application stack) is described fully only by the managed instance.
        managed = managed_by_arn.get(str(c.get("native_id") or ""))
        if managed is not None and (res is None or res["mode"] != "managed"):
            resource_component[managed["address"]] = cid
            res = managed
        component_type[cid] = str(c.get("type") or "")

        flags: list[str] = []
        tags = (res or {}).get("values", {}).get("tags_all") if res else None
        if res is not None and res["mode"] == "managed" and "tags_all" in res["values"]:
            if not tags:
                flags.append("untagged")
            elif not all(k in tags for k in CLASSIFICATION_TAGS):
                flags.append("classification tags incomplete")
        if tf_address and tf_address in pending_addresses:
            flags.append("change pending apply")

        cls = attrs.get("classification") or {}
        node: dict[str, Any] = {
            "id": cid,
            "name": display_name(c, (res or {}).get("values"), kms_aliases),
            "type": c.get("type"),
            "kind": "collected",
            "group": g["key"] if g else "unclassified",
            "zone": g["zone"] if g else "unclassified",
            "classification": {k: cls[k] for k in PUBLIC_CLASSIFICATION if k in cls},
        }
        if attrs.get("function"):
            node["function"] = attrs["function"]
        if attrs.get("region"):
            node["region"] = attrs["region"]
        if attrs.get("managed_by") == "bootstrap" or attrs.get("tf_module") == "bootstrap":
            node["managed_by"] = "operator-applied bootstrap stack"
        if flags:
            node["flags"] = flags
        if cid in findings:
            node["findings"] = findings[cid]
        nodes.append(node)

        candidates = [c.get("native_id"), attrs.get("id"), attrs.get("name"), attrs.get("function_name")]
        if res is not None:
            candidates += [res["values"].get(k) for k in ("arn", "id", "name", "bucket")]
            if c.get("type") == "cdn_distribution":
                # DNS alias records name the distribution by its domain.
                candidates.append(res["values"].get("domain_name"))
        for value in candidates:
            if isinstance(value, str) and len(value) >= MIN_IDENTITY_LEN:
                owners.setdefault(value, set()).add(cid)
        native = str(c.get("native_id") or "")
        if native.startswith("arn:") and len(native) > 20:
            arn_index.append((native, cid))

    for d in classification.get("declared", []):
        nodes.append({
            "id": f"declared:{d['key']}",
            "name": d["label"],
            "type": d["kind"],
            "kind": d["kind"],
            "group": f"declared-{d['zone']}",
            "zone": d["zone"],
            "why": d.get("why"),
        })

    # A bucket, a DNS zone and a certificate can all be called "samaydlette.com";
    # a shared name is evidence of a reference only where a type hint settles it.
    identity = {v: next(iter(cs)) for v, cs in owners.items() if len(cs) == 1}
    shared = {v: cs for v, cs in owners.items() if len(cs) > 1}

    def resolve_value(key: str | None, value: str) -> str | None:
        hit = identity.get(value)
        if hit:
            return hit
        want = REFERENCE_TYPE_HINTS.get(key or "")
        if want and value in shared:
            typed = [cid for cid in shared[value] if component_type.get(cid) == want]
            if len(typed) == 1:
                return typed[0]
        tail = url_tail(value)
        return identity.get(tail) if tail else None

    # --- Reference graph --------------------------------------------------------
    edges: dict[tuple[str, str], set[str]] = {}

    def link(a: str, b: str, via: str) -> None:
        if a != b:
            edges.setdefault((a, b), set()).add(via)

    for r in resources:
        refs: set[str] = set()
        for key, s in keyed_strings(r["values"]):
            hit = resolve_value(key, s)
            if hit:
                refs.add(hit)
                continue
            if "arn:" in s:
                for arn, cid in arn_index:
                    if arn in s:
                        refs.add(cid)
        owner = resource_component.get(r["address"])
        if owner:
            for ref in refs:
                link(owner, ref, r["type"])
        elif r["mode"] == "managed" and r["type"] in CONNECTOR_TYPES:
            # A connecting resource (an event target, a permission, a policy
            # attachment) links the components it names to one another.
            ordered = sorted(refs)
            for i, a in enumerate(ordered):
                for b in ordered[i + 1:]:
                    link(a, b, r["type"])

    node_ids = {n["id"] for n in nodes}

    # --- Flows ------------------------------------------------------------------
    def resolve(ref: dict[str, str]) -> list[str]:
        if "declared" in ref:
            nid = f"declared:{ref['declared']}"
            return [nid] if nid in node_ids else []
        return sorted(n["id"] for n in nodes if n["kind"] == "collected" and fnmatch.fnmatchcase(n["id"], ref["component"]))

    flows = []
    for f in classification.get("flows", []):
        hops_by_step = [resolve(ref) for ref in f["path"]]
        unmatched = [ref.get("component") or ref.get("declared") for ref, hop in zip(f["path"], hops_by_step, strict=True) if not hop]
        hops = [[a, b] for i in range(len(hops_by_step) - 1) for a in hops_by_step[i] for b in hops_by_step[i + 1]]
        flows.append({
            "id": f["id"], "label": f["label"], "protocol": f.get("protocol"), "auth": f.get("auth"),
            "encryption": f.get("encryption"), "data": f.get("data"), "note": f.get("note"),
            "hops": hops, "unmatched_endpoints": unmatched,
        })

    group_list = [{"key": g["key"], "label": g["label"], "zone": g["zone"]} for g in groups
                  if any(n["group"] == g["key"] for n in nodes)]
    for zone_key in sorted({n["zone"] for n in nodes if n["kind"] != "collected"}):
        group_list.append({"key": f"declared-{zone_key}", "label": "Actors" if zone_key == "outside" else "Declared, not inventoried", "zone": zone_key})
    if unclassified:
        group_list.append({"key": "unclassified", "label": "Unclassified: no rule places these", "zone": "unclassified"})
    zone_list = [z for z in classification["zones"] if any(n["zone"] == z["key"] for n in nodes) or z["key"] == "leveraged"]
    if unclassified:
        zone_list.append({"key": "unclassified", "label": "Unclassified"})

    all_flags = [f for n in nodes for f in n.get("flags", [])]
    health = {
        "unclassified": len(unclassified),
        "untagged": all_flags.count("untagged"),
        "classification_tags_incomplete": all_flags.count("classification tags incomplete"),
        # Every pending change counts, not only those that land on a node: a
        # resource the inventory does not model (a group's inline policy) is
        # still a trust-root change awaiting the operator's apply.
        "pending_trust_root_changes": len(pending_addresses),
        "declared_not_inventoried": sum(1 for n in nodes if n["kind"] == "not_inventoried"),
        "flows_with_unmatched_endpoint": sum(1 for f in flows if f["unmatched_endpoints"]),
    }

    return {
        "schema": SCHEMA,
        "generated_at": now,
        "commit": commit,
        "ksi_signal_id": signal.get("signal_id"),
        "source": {
            "inventory": "/.well-known/ksi-signal.json",
            "classification": "docs/boundary/boundary-classification.json",
            "terraform_states": len(states),
            "trust_root_plan": (trust_root_plan or {}).get("status", "not provided"),
        },
        "health": health,
        "trust_root_changes": [
            {"address": c["address"], "actions": c.get("actions", []),
             "component": resource_component.get(c["address"])}
            for c in sorted((trust_root_plan or {}).get("changes", []), key=lambda c: c["address"])
        ],
        "unclassified": unclassified,
        "zones": zone_list,
        "groups": group_list,
        "nodes": sorted(nodes, key=lambda n: (n["zone"], n["group"], n["name"])),
        "edges": [{"source": a, "target": b, "via": sorted(v)} for (a, b), v in sorted(edges.items())
                  if a in node_ids and b in node_ids],
        "flows": flows,
        "leveraged": classification.get("leveraged"),
        "fips_modules": offering.get("cryptographic_modules", []),
    }


def check_redaction(text: str) -> None:
    for label, pattern in REDACTION_CHECKS.items():
        m = pattern.search(text)
        if m:
            start = max(0, m.start() - 40)
            sys.exit(f"build-boundary-graph: refusing to write, found an {label} near: …{text[start:m.end() + 10]}…")


def main() -> None:
    ap = argparse.ArgumentParser(description="Build the boundary map from the inventory, the classification and Terraform state.")
    ap.add_argument("--ksi-signal", default="ksi-signal.json")
    ap.add_argument("--classification", default="../docs/boundary/boundary-classification.json")
    ap.add_argument("--state", action="append", default=[], help="terraform show -json output or raw state (repeatable)")
    ap.add_argument("--offering", default="../data/cds/offering.json")
    ap.add_argument("--vdr", default="vdr-report.json")
    ap.add_argument("--trust-root-plan", default="trust-root-plan.json")
    ap.add_argument("--commit", default="")
    ap.add_argument("--output", default="boundary-map.json")
    a = ap.parse_args()

    def load(path: str, required: bool = True) -> dict[str, Any] | None:
        p = Path(path)
        if not p.exists():
            if required:
                sys.exit(f"build-boundary-graph: missing input {path}")
            return None
        return json.loads(p.read_text())

    states = [s for s in (load(p, required=False) for p in a.state) if s]
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    graph = build(
        load(a.ksi_signal) or {}, load(a.classification) or {}, states,
        load(a.offering, required=False) or {}, load(a.vdr, required=False),
        load(a.trust_root_plan, required=False), a.commit, now,
    )
    text = json.dumps(graph, indent=1, ensure_ascii=False) + "\n"
    check_redaction(text)
    Path(a.output).write_text(text)
    h = graph["health"]
    print(f"boundary map: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges, {len(graph['flows'])} flows; "
          f"{h['unclassified']} unclassified, {h['untagged']} untagged, "
          f"{h['flows_with_unmatched_endpoint']} flow(s) with an unmatched endpoint")


if __name__ == "__main__":
    main()
