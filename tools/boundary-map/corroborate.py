#!/usr/bin/env python3
"""Corroborate the published boundary map with an independent collection by RAMPART on TAP.

LOCAL-ONLY, like tools/essay: it needs a running TAP session (The Analogy Platform,
github.com/unified-systems-com/tap) with the aws_core collector configured against
this account's read-only role, so it never runs in CI.

The published map (/.well-known/boundary-map.json) is built by the deploy from the
canonical inventory, which comes from Terraform state. Anything that state does not
know about cannot be on the map. TAP collects the same account straight from the AWS
APIs, so comparing the two catches what the pipeline cannot see about itself: a
resource created outside Terraform, one Terraform stopped tracking, or tags that
drifted after the deploy.

What it does:
  1. Optionally (--collect) runs TAP's aws_core collector and waits for it.
  2. Reads TAP's latest successful collection back from the TAP database (read-only),
     keeping only the entities that run actually observed.
  3. Fetches the published inventory and map (or reads local copies) and matches TAP's
     resources to inventory components by ARN.
  4. Writes docs/boundary/corroboration.json: what agrees, what only the map has, what
     only TAP sees (inside the system, or managed by AWS itself), tag differences on the
     classification axes, and relationships TAP observed that the map does not draw.
     It fails closed: if any ARN, 12-digit account ID or email address is left in the
     output, nothing is written.

Commit the report; the next deploy signs and publishes it at
/.well-known/boundary-corroboration.json and the trust center reports its result and age.

Usage (from the repo root, with the TAP session up):

    python3 tools/boundary-map/corroborate.py --collect
    python3 tools/boundary-map/corroborate.py --tap-container tap_rampart-web-1
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "docs" / "boundary" / "corroboration.json"
SCHEMA = "rampart-corroboration/1"
SITE = "https://samaydlette.com/.well-known"
COLLECTOR = "aws_core:boto3"

# Inventory component type -> the aws_core entity type that covers it, and the field
# holding the identifier that matches the component's native_id.
COVERAGE = {
    "function": ("lambda", "function_arn"),
    "iam_role": ("iam_role", "role_arn"),
    "oidc_provider": ("iam_oidc_provider", "provider_arn"),
    "event_schedule": ("eventbridge_rule", "rule_arn"),
    "log_group": ("cloudwatch_log_group", "log_group_arn"),
    "tls_certificate": ("acm_certificate", "certificate_arn"),
    "cdn_distribution": ("cloudfront_distribution", "distribution_arn"),
    "object_store": ("s3_bucket", "bucket_arn"),
    "dns_zone": ("route53_zone", "hosted_zone_id"),
    "api_gateway": ("apigateway_http_api", "api_arn"),
    "identity_provider": ("cognito_user_pool", "pool_arn"),
    "kms_key": ("kms_key", "key_arn"),
    "message_queue": ("sqs_queue", "queue_arn"),
    "audit_log_trail": ("cloudtrail_trail", "trail_arn"),
    "secrets_manager": ("secrets_manager_secret", "secret_arn"),
    "kv_table": ("dynamodb_table", "table_arn"),
}
ID_FIELD = {t: f for t, f in COVERAGE.values()}

# The governed classification tags (docs/policies/resource-tagging-standard.md),
# compared between the live resource and the inventory.
CLASSIFICATION_TAGS = {
    "DataSensitivity": "data_sensitivity",
    "MissionCriticality": "mission_criticality",
    "InternetReachable": "internet_reachable",
    "Archetype": "archetype",
}

REDACTION_CHECKS = {
    "ARN": re.compile(r"arn:aws[a-z-]*:"),
    "AWS account ID": re.compile(r"(?<![0-9A-Za-z])[0-9]{12}(?![0-9A-Za-z])"),
    "email address": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
}

# Runs inside the TAP web container (manage.py shell). Read-only: it reads the latest
# successful aws_core job and the entities and edges that job observed.
READ_TAP = r'''
import json
from django.apps import apps
from tap_grid.models import Edge, BaseModel, BatchEvent
from tap_cares.models import Collector, CollectionJob
T = {m.ENTITY_TYPE: m for m in apps.get_models()
     if issubclass(m, BaseModel) and getattr(m, "ENTITY_TYPE", "").startswith("aws_core__")}
c = Collector.objects.get(collector_registry="%(collector)s")
last = (CollectionJob.objects
        .filter(entity__in=Edge.objects.filter(from_entity=c.entity, edge_type="HAS_COLLECTION_JOB").values("to_entity"),
                status="SUCCESSFUL", run_mode="full")
        .order_by("-finished_at").first())
batches = list(Edge.objects.filter(from_entity=last.entity, edge_type="PRODUCED_BATCH").values_list("to_entity_id", flat=True))
seen = set(BatchEvent.objects.filter(batch__entity_id__in=batches, event_type__in=["create", "update"])
           .values_list("entity_id", flat=True))
out = {"finished_at": last.finished_at.isoformat(), "entities": [], "edges": []}
ids = set()
for et, M in sorted(T.items()):
    if et in ("aws_core__aws_az", "aws_core__aws_region", "aws_core__aws_account"):
        continue
    for r in M.objects.all():
        if r.entity_id not in seen:
            continue  # held from an earlier run, not observed by the latest one
        ids.add(r.entity_id)
        out["entities"].append({"id": str(r.entity_id), "type": et.replace("aws_core__aws_", ""),
            "fields": {f.name: getattr(r, f.name) for f in M._meta.concrete_fields
                       if f.name not in ("id", "batch_id", "flip_map", "entity", "configuration", "email")}})
for e in Edge.objects.filter(from_entity_id__in=ids, to_entity_id__in=ids):
    if e.entity_id in seen:
        out["edges"].append({"type": e.edge_type, "from": str(e.from_entity_id), "to": str(e.to_entity_id)})
print("@@TAP@@" + json.dumps(out, default=str))
'''

# Runs inside the TAP web container: one aws_core run, awaited.
COLLECT_TAP = r'''
from tap_auth.actors import BOOTLOADER, acting_as, get_builtin_actor
from tap_cares.models import Collector
from tap_cares.services import fire_collector_and_await
c = Collector.objects.get(collector_registry="%(collector)s")
with acting_as(get_builtin_actor(BOOTLOADER)):
    ok, job = fire_collector_and_await(c, manual_run_source="samaydlette-corroborate", timeout_seconds=300)
print("@@COLLECT@@", ok, job.status)
'''


def tap_shell(container: str, code: str) -> str:
    """Run Python in the TAP container's Django shell and return stdout."""
    proc = subprocess.run(
        ["podman", "exec", "-i", container, "sh", "-c", "cd /app && /app/.venv/bin/python manage.py shell 2>/dev/null"],
        input=code, capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        sys.exit(f"corroborate: TAP shell failed in {container} (exit {proc.returncode})")
    return proc.stdout


def tap_version(container: str) -> str:
    out = subprocess.run(["podman", "exec", container, "/app/.venv/bin/python", "-c",
                          "import importlib.metadata as m; print(m.version('tap-plugin-aws-core'))"],
                         capture_output=True, text=True, timeout=60)
    return out.stdout.strip() or "unknown"


def read_tap(container: str) -> dict[str, Any]:
    out = tap_shell(container, READ_TAP % {"collector": COLLECTOR})
    line = next((ln for ln in out.splitlines() if ln.startswith("@@TAP@@")), None)
    if line is None:
        sys.exit("corroborate: TAP returned no collection (has aws_core run successfully?)")
    return json.loads(line[len("@@TAP@@"):])


def collect(container: str) -> None:
    out = tap_shell(container, COLLECT_TAP % {"collector": COLLECTOR})
    if "@@COLLECT@@ True" not in out:
        sys.exit("corroborate: the aws_core collection did not finish successfully")


def fetch_json(src: str) -> Any:
    if src.startswith("https://"):
        with urllib.request.urlopen(urllib.request.Request(src, headers={"Cache-Control": "no-cache"}), timeout=30) as r:  # noqa: S310
            return json.loads(r.read().decode())
    return json.loads(Path(src).read_text())


# ---------------------------------------------------------------------------

def normalize_id(tap_type: str, value: Any) -> str:
    """TAP's identifier in the inventory's native_id form."""
    v = str(value or "")
    if tap_type == "cloudwatch_log_group":
        return v[:-2] if v.endswith(":*") else v
    if tap_type == "route53_zone":
        return "arn:aws:route53:::hostedzone/" + v.rsplit("/", 1)[-1]
    return v


def public_name(value: str) -> str:
    """A resource's name without the account, region or partition parts of its ARN."""
    v = re.sub(r"^arn:aws[a-z-]*:[^:]*:[^:]*:[0-9]*:", "", value)
    return v.split("/", 1)[-1] if v.startswith(("role/", "table/", "key/", "trail/", "rule/")) else v


def managed_name(entity: dict[str, Any], ident: str) -> str:
    """AWS-managed keys are named by the service they protect, not by key id."""
    if entity["type"] == "kms_key":
        m = re.search(r"protects my (\w+)", str(entity["fields"].get("description") or ""))
        return f"AWS-managed default key ({m.group(1)})" if m else "AWS-managed key"
    return public_name(ident)


def provider_managed(entity: dict[str, Any]) -> bool:
    """AWS's own resources in the account (service-linked roles, AWS-managed keys)."""
    f = entity["fields"]
    if entity["type"] == "iam_role" and "/aws-service-role/" in str(f.get("role_arn", "")):
        return True
    return entity["type"] == "kms_key" and f.get("key_manager") == "AWS"


def compare(tap: dict[str, Any], signal: dict[str, Any], bmap: dict[str, Any], now: datetime,
            tap_version_: str = "unknown") -> dict[str, Any]:
    if bmap.get("ksi_signal_id") != signal.get("signal_id"):
        sys.exit("corroborate: the published map and inventory are bound to different signals; retry after the deploy settles")

    in_scope = [c for c in signal.get("components", []) if c.get("type") in COVERAGE]
    by_native = {c["native_id"]: c for c in in_scope if c.get("native_id")}
    map_ids = {n["id"] for n in bmap.get("nodes", [])}

    matched: dict[str, str] = {}  # tap entity id -> component_id
    tap_only, managed, tag_diffs = [], [], []
    for e in tap.get("entities", []):
        field = ID_FIELD.get(e["type"])
        if field is None:
            continue
        ident = normalize_id(e["type"], e["fields"].get(field))
        comp = by_native.get(ident)
        if comp is not None:
            matched[e["id"]] = comp["component_id"]
            cls = (comp.get("attributes") or {}).get("classification") or {}
            tags = e["fields"].get("tags") or {}
            for tag, axis in CLASSIFICATION_TAGS.items():
                if tag in tags and axis in cls and str(cls[axis]).lower() != str(tags[tag]).lower():
                    tag_diffs.append({"component": comp["component_id"], "tag": tag,
                                      "inventory": str(cls[axis]).lower(), "live": str(tags[tag]).lower()})
        elif provider_managed(e):
            managed.append({"type": e["type"], "name": managed_name(e, ident)})
        else:
            tap_only.append({"type": e["type"], "name": public_name(ident),
                             "why": "TAP observed it in the account, but the inventory has no component for it, so the map cannot show it."})

    agree = sorted(set(matched.values()))
    type_of = {c["component_id"]: c["type"] for c in in_scope}
    covered_ids = set(type_of)
    map_only = [{"component": cid, "type": type_of[cid],
                 "why": "On the map, but TAP did not observe it: deleted outside Terraform, or not visible to the read-only role."}
                for cid in sorted(covered_ids - set(agree))]
    not_covered: dict[str, int] = {}
    for c in signal.get("components", []):
        if c["component_id"].startswith("aws::") and c.get("type") not in COVERAGE:
            not_covered[c["type"]] = not_covered.get(c["type"], 0) + 1

    map_pairs = {frozenset((ed["source"], ed["target"])) for ed in bmap.get("edges", [])}
    tap_edges, tap_only_edges = 0, []
    for ed in tap.get("edges", []):
        a, b = matched.get(ed["from"]), matched.get(ed["to"])
        if not a or not b or a == b:
            continue
        tap_edges += 1
        if frozenset((a, b)) not in map_pairs and a in map_ids and b in map_ids:
            tap_only_edges.append({"from": a, "to": b, "relationship": ed["type"].split("__")[0].lower().replace("_", " ")})

    findings = len(tap_only) + len(map_only) + len(tag_diffs) + len(tap_only_edges)
    return {
        "schema": SCHEMA,
        "checked_at": now.isoformat(timespec="seconds"),
        "result": "agrees" if findings == 0 else "differs",
        "corroborated_by": {"name": "RAMPART on TAP (The Analogy Platform)", "url": "https://github.com/unified-systems-com/tap",
                            "collector": COLLECTOR, "collector_version": tap_version_, "collected_at": tap.get("finished_at")},
        "compared_against": {"ksi_signal_id": signal.get("signal_id"), "map_commit": bmap.get("commit"),
                             "map_generated_at": bmap.get("generated_at")},
        "summary": {"in_scope": len(covered_ids), "agree": len(agree), "map_only": len(map_only),
                    "tap_only": len(tap_only), "tag_differences": len(tag_diffs),
                    "relationships_compared": tap_edges, "relationships_tap_only": len(tap_only_edges),
                    "provider_managed": len(managed)},
        "agree": agree,
        "map_only": map_only,
        "tap_only": sorted(tap_only, key=lambda x: (x["type"], x["name"])),
        "tag_differences": tag_diffs,
        "relationships_tap_only": tap_only_edges,
        "provider_managed": sorted(managed, key=lambda x: (x["type"], x["name"])),
        "not_covered_by_tap": dict(sorted(not_covered.items())),
        "scope_note": "Compared: the resource types TAP's aws_core collector covers. Types it does not collect "
                      "(listed in not_covered_by_tap) rest on the deploy's own reconciliation gate.",
    }


def check_redaction(text: str) -> None:
    for label, pattern in REDACTION_CHECKS.items():
        m = pattern.search(text)
        if m:
            start = max(0, m.start() - 40)
            sys.exit(f"corroborate: refusing to write, found an {label} near: …{text[start:m.end() + 10]}…")


def main() -> None:
    ap = argparse.ArgumentParser(description="Corroborate the published boundary map with RAMPART on TAP.")
    ap.add_argument("--tap-container", default="tap_rampart-web-1")
    ap.add_argument("--collect", action="store_true", help="run TAP's aws_core collector first")
    ap.add_argument("--signal", default=f"{SITE}/ksi-signal.json")
    ap.add_argument("--map", default=f"{SITE}/boundary-map.json")
    ap.add_argument("--output", default=str(OUT))
    a = ap.parse_args()

    if a.collect:
        print("corroborate: running TAP's aws_core collector…", file=sys.stderr)
        collect(a.tap_container)
    report = compare(read_tap(a.tap_container), fetch_json(a.signal), fetch_json(a.map),
                     datetime.now(timezone.utc), tap_version(a.tap_container))
    text = json.dumps(report, indent=2) + "\n"
    check_redaction(text)
    Path(a.output).write_text(text)
    s = report["summary"]
    print(f"corroborate: {report['result']}: {s['agree']} of {s['in_scope']} components agree; "
          f"{s['tap_only']} only TAP sees, {s['map_only']} only the map has, {s['tag_differences']} tag difference(s), "
          f"{s['relationships_tap_only']} relationship(s) only TAP observed. Wrote {a.output}")


if __name__ == "__main__":
    main()
