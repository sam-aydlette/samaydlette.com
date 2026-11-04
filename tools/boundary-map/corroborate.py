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
    python3 tools/boundary-map/corroborate.py --tap-container tap_corroborate-web-1
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
sys.path.insert(0, str(Path(__file__).resolve().parent))
import corroborate_checks as checks  # noqa: E402
OUT = REPO / "docs" / "boundary" / "corroboration.json"
SCHEMA = "rampart-corroboration/2"
SITE = "https://samaydlette.com/.well-known"
COLLECTOR = "aws_core:boto3"
GITHUB_COLLECTOR = "github_core:github_core"
REGION = "us-east-2"
RUNTIME_KEY = "alias/samaydlette-com-runtime-signing"
FRESHNESS = REPO / "infrastructure" / "schemas" / "freshness-config.json"
PINNED_KEY = REPO / "infrastructure" / "keys" / "runtime-signing-key.json"
RULES_SOURCES = REPO / "infrastructure" / "schemas" / "fedramp-rules" / "SOURCES.json"
UPSTREAM_RULES = "https://raw.githubusercontent.com/FedRAMP/rules/{commit}/fedramp-consolidated-rules.json"
UPSTREAM_HEAD = "https://api.github.com/repos/FedRAMP/rules/commits/main"
GITHUB_RUN_WINDOW = 10  # github_core's initial_run_limit

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

# Runs inside the TAP web container (manage.py shell). Read-only: it returns the latest
# successful aws_core job's batch events, plus the aws_core entities and the edges
# between them. observed() then keeps what that job actually saw. The filtering runs
# here, not in the container, so it is unit-tested.
READ_TAP = r'''
import json
from collections import defaultdict
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
events = defaultdict(list)
for eid, kind in BatchEvent.objects.filter(batch__entity_id__in=batches).values_list("entity_id", "event_type"):
    events[str(eid)].append(kind)
out = {"finished_at": last.finished_at.isoformat(), "events": events, "entities": [], "edges": []}
ids = set()
for et, M in sorted(T.items()):
    if et in ("aws_core__aws_az", "aws_core__aws_region", "aws_core__aws_account"):
        continue
    for r in M.objects.all():
        ids.add(r.entity_id)
        out["entities"].append({"id": str(r.entity_id), "type": et.replace("aws_core__aws_", ""),
            "fields": {f.name: getattr(r, f.name) for f in M._meta.concrete_fields
                       if f.name not in ("id", "batch_id", "flip_map", "entity", "configuration", "email")}})
for e in Edge.objects.filter(from_entity_id__in=ids, to_entity_id__in=ids):
    out["edges"].append({"id": str(e.entity_id), "type": e.edge_type, "from": str(e.from_entity_id), "to": str(e.to_entity_id)})
print("@@TAP@@" + json.dumps(out, default=str))
'''

# Batch events that mean "this run observed it". aws_core before 0.8 recorded
# relationships as create/update; 0.8 and later record them as link.
ENTITY_EVENTS = {"create", "update"}
EDGE_EVENTS = {"create", "update", "link"}


def observed(raw: dict[str, Any]) -> dict[str, Any]:
    """The entities and relationships the latest run observed, not ones held from earlier runs."""
    ev = raw.get("events") or {}
    seen = {e["id"] for e in raw.get("entities", []) if ENTITY_EVENTS & set(ev.get(e["id"], []))}
    return {"finished_at": raw.get("finished_at"),
            "entities": [e for e in raw.get("entities", []) if e["id"] in seen],
            "edges": [e for e in raw.get("edges", [])
                      if EDGE_EVENTS & set(ev.get(e["id"], [])) and e["from"] in seen and e["to"] in seen]}


def assert_comparable(report: dict[str, Any], bmap: dict[str, Any]) -> None:
    """Refuse a report that would read as agreement while comparing nothing."""
    s = report["summary"]
    if not s.get("agree") and not s.get("tap_only") and not s.get("provider_managed"):
        sys.exit("corroborate: TAP's collection observed nothing; refusing to write a report")
    if bmap.get("edges") and not s.get("relationships_compared"):
        sys.exit("corroborate: the map draws relationships but no relationship was compared "
                 "(has TAP's batch-event shape changed?); refusing to write a report")


# Runs inside the TAP web container with plain Python (no Django): the facts for the
# signatures, runtime_signing_key and live_configuration sections. Input on stdin is
# JSON; output is one @@FACTS@@ line. It verifies with TAP's sigstore_core (the
# sigstore-python verifier and production trust root) and reads AWS with TAP's own
# read-only credential. It returns facts only; corroborate_checks.py judges them.
READ_FACTS = r"""
import base64, hashlib, json, sys
req = json.load(sys.stdin)
out = {"signatures": [], "kms_der_sha256": None, "kms_error": None, "groups": {}}
from tap_plugin.sigstore_core import verify as v
OIDS = {"1.3.6.1.4.1.57264.1.13": "commit", "1.3.6.1.4.1.57264.1.14": "ref", "1.3.6.1.4.1.57264.1.20": "event",
        "1.3.6.1.4.1.57264.1.21": "run_uri", "1.3.6.1.4.1.57264.1.23": "environment"}
def der_utf8(raw):
    # The v2 Fulcio extensions are DER UTF8String: tag 0x0c, then a length.
    if raw[:1] != b"\x0c":
        return raw.decode()
    n, i = raw[1], 2
    if n & 0x80:
        k = n & 0x7f; n = int.from_bytes(raw[2:2 + k], "big"); i = 2 + k
    return raw[i:i + n].decode()
def cert_facts(bundle):
    out = {}
    for e in bundle.signing_certificate.extensions:
        name = OIDS.get(e.oid.dotted_string)
        if name:
            out[name] = der_utf8(getattr(e.value, "value", b""))
    return out
for a in req["artifacts"]:
    f = {"artifact": a["artifact"]}
    try:
        pol = v.GitHubWorkflowPolicy(oidc_issuer=req["issuer"], github_repository=req["repository"],
                                     workflow_identity_uri=a["identity"])
        if a["kind"] == "dsse":
            r = v.verify_dsse_bundle(base64.b64decode(a["bundle_b64"]).strip(), policy=pol)
            f["subject_sha256"] = hashlib.sha256(base64.b64decode(a["subject_b64"])).hexdigest()
            stmt = json.loads(r.payload) if r.payload else {}
            f["subjects"] = [{"name": s.get("name"), "sha256": (s.get("digest") or {}).get("sha256")}
                             for s in stmt.get("subject", [])]
        else:
            r = v.verify_bundle(base64.b64decode(a["body_b64"]), base64.b64decode(a["bundle_b64"]), policy=pol)
        f.update(verified=r.signature_verified, failure_code=r.failure_code or None, signed_by=r.signed_by or None,
                 issuer=r.signing_issuer or None, rekor_log_index=r.rekor_log_index or None)
        if r.parsed_bundle is not None:
            f["cert"] = cert_facts(r.parsed_bundle)
            f["cert"]["workflow_path"] = (r.signed_by or "").split(req["repository"] + "/", 1)[-1].split("@", 1)[0] or None
    except Exception as exc:
        f.update(verified=False, failure_code=type(exc).__name__)
    out["signatures"].append(f)
import boto3
cred = json.load(open("/run/tap-secrets/aws_core/boto_collector.secret.json"))["data"]
s = boto3.Session(aws_access_key_id=cred["access_key_id"], aws_secret_access_key=cred["secret_access_key"],
                  region_name=req["region"])
try:
    der = s.client("kms").get_public_key(KeyId=req["kms_key"])["PublicKey"]
    out["kms_der_sha256"] = hashlib.sha256(der).hexdigest()
    out["kms_pem"] = "-----BEGIN PUBLIC KEY-----\n" + "\n".join(
        base64.b64encode(der).decode()[i:i + 64] for i in range(0, len(base64.b64encode(der)), 64)) + "\n-----END PUBLIC KEY-----\n"
except Exception as exc:
    out["kms_error"] = type(exc).__name__
iam = s.client("iam")
for cid, name in req["groups"].items():
    try:
        members = []
        for u in iam.get_group(GroupName=name)["Users"]:
            try:
                iam.get_login_profile(UserName=u["UserName"])
                console = True
            except iam.exceptions.NoSuchEntityException:
                console = False
            members.append({"console": console,
                            "mfa_enabled": bool(iam.list_mfa_devices(UserName=u["UserName"])["MFADevices"])})
        out["groups"][cid] = members
    except Exception as exc:
        out["groups"][cid] = None
print("@@FACTS@@" + json.dumps(out))
"""

# Runs inside the TAP web container (manage.py shell). Read-only: github_core's
# workflow runs, workflows, the repository's Dependabot observability and alerts.
READ_GITHUB = r"""
import json
from django.apps import apps
M = {m.ENTITY_TYPE: m for m in apps.get_models() if getattr(m, "ENTITY_TYPE", "").startswith("github_core__")}
repo = M["github_core__github_repository"].objects.filter(full_name="%(repository)s").first()
out = {"runs": [], "workflows": {}, "dependabot_observability": getattr(repo, "dependabot_observability", None),
       "alerts": []}
for r in M["github_core__github_actions_run"].objects.filter(full_name="%(repository)s"):
    out["runs"].append({"run_id": str(r.run_id), "workflow_id": str((r.configuration or {}).get("workflow_id")),
                        "event": r.event, "conclusion": r.conclusion, "head_sha": r.head_sha, "head_branch": r.head_branch})
for w in M["github_core__github_workflow"].objects.filter(full_name="%(repository)s"):
    out["workflows"][str(w.workflow_id)] = w.path
for a in M["github_core__dependabot_alert"].objects.filter(full_name="%(repository)s"):
    out["alerts"].append({"state": a.state, "cve_id": a.cve_id, "ghsa_id": a.ghsa_id, "package_name": a.package_name})
print("@@GITHUB@@" + json.dumps(out, default=str))
"""

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
    # The package was renamed from tap-plugin-aws-core to aws-core-tap (aws_core 0.6+).
    code = ("import importlib.metadata as m\n"
            "for n in ('aws-core-tap', 'tap-plugin-aws-core'):\n"
            "    try:\n        print(m.version(n)); break\n"
            "    except m.PackageNotFoundError:\n        pass\n")
    out = subprocess.run(["podman", "exec", container, "/app/.venv/bin/python", "-c", code],
                         capture_output=True, text=True, timeout=60)
    return out.stdout.strip() or "unknown"


def read_tap(container: str) -> dict[str, Any]:
    out = tap_shell(container, READ_TAP % {"collector": COLLECTOR})
    line = next((ln for ln in out.splitlines() if ln.startswith("@@TAP@@")), None)
    if line is None:
        sys.exit("corroborate: TAP returned no collection (has aws_core run successfully?)")
    return observed(json.loads(line[len("@@TAP@@"):]))


def collect(container: str, collector: str = COLLECTOR) -> None:
    out = tap_shell(container, COLLECT_TAP % {"collector": collector})
    if "@@COLLECT@@ True" not in out:
        sys.exit(f"corroborate: the {collector} collection did not finish successfully")


def _marked(out: str, mark: str, what: str) -> Any:
    line = next((ln for ln in out.splitlines() if ln.startswith(mark)), None)
    if line is None:
        sys.exit(f"corroborate: TAP returned no {what}")
    return json.loads(line[len(mark):])


def read_facts(container: str, req: dict[str, Any]) -> dict[str, Any]:
    """Signature verification, the KMS key and group MFA, read inside the TAP container."""
    proc = subprocess.run(["podman", "exec", "-i", container, "/app/.venv/bin/python", "-c", READ_FACTS],
                          input=json.dumps(req), capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        sys.exit(f"corroborate: TAP fact read failed in {container} (exit {proc.returncode})")
    return _marked(proc.stdout, "@@FACTS@@", "verification facts")


def read_github(container: str) -> dict[str, Any]:
    return _marked(tap_shell(container, READ_GITHUB % {"repository": checks.REPOSITORY}), "@@GITHUB@@", "GitHub records")


def fetch_bytes(url: str) -> bytes:
    with urllib.request.urlopen(urllib.request.Request(url, headers={"Cache-Control": "no-cache"}), timeout=60) as r:  # noqa: S310
        return r.read()


def matched_components(tap: dict[str, Any], signal: dict[str, Any]) -> dict[str, str]:
    """{TAP entity id: component_id}, matched by ARN as in compare()."""
    by_native = {c["native_id"]: c["component_id"] for c in signal.get("components", [])
                 if c.get("type") in COVERAGE and c.get("native_id")}
    out = {}
    for e in tap.get("entities", []):
        field = ID_FIELD.get(e["type"])
        cid = by_native.get(normalize_id(e["type"], e["fields"].get(field))) if field else None
        if cid:
            out[e["id"]] = cid
    return out


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


def boundary_section(report: dict[str, Any]) -> dict[str, Any]:
    """The existing boundary comparison, in the section shape."""
    s = report["summary"]
    findings = ([{"kind": "tap_only", **x} for x in report["tap_only"]]
                + [{"kind": "map_only", **x} for x in report["map_only"]]
                + [{"kind": "tag_difference", **x} for x in report["tag_differences"]]
                + [{"kind": "relationship_tap_only", **x} for x in report["relationships_tap_only"]])
    return checks.section(findings, s["in_scope"] + s["relationships_compared"],
                          source="TAP aws_core (AWS APIs, read-only role) against the published map",
                          note="Resources, classification tags and relationships; detail in the top-level keys.")


def assemble(report: dict[str, Any], sections: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Add the sections to the boundary report; the overall result covers them all."""
    allc = {"boundary": boundary_section(report), **sections}
    report["checks"] = {k: allc[k] for k in checks.SECTION_ORDER if k in allc}
    report["boundary_result"] = report["result"]
    report["result"] = checks.overall(report["checks"])
    return report


def _vdr_builder() -> Any:
    import importlib.util
    spec = importlib.util.spec_from_file_location("vdr_builder", REPO / "scripts" / "build-vdr-report.py")
    m = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(m)  # type: ignore[union-attr]
    return m


def verify_runtime_with(kms_pem: str, runtime_path: Path, workdir: Path) -> dict[str, Any]:
    """The runtime signal checked by the builder's own code, against the key KMS holds
    (not the pinned copy, which is what is being corroborated)."""
    import hashlib
    keydoc = workdir / "kms-key.json"
    keydoc.write_text(json.dumps({"public_key_pem": kms_pem,
                                  "public_key_sha256": hashlib.sha256(kms_pem.encode("ascii")).hexdigest()}))
    return _vdr_builder().load_runtime_signal(runtime_path, pubkey_path=keydoc)


def gather(container: str, signal: dict[str, Any], tap: dict[str, Any], workdir: Path) -> dict[str, dict[str, Any]]:
    """Every section beyond the boundary map. Each reads its facts from TAP or from
    the upstream source it names, never from the pipeline's own outputs."""
    freshness = json.loads(FRESHNESS.read_text())
    arts = checks.signed_artifacts(freshness)
    req: dict[str, Any] = {"issuer": checks.ISSUER, "repository": checks.REPOSITORY, "region": REGION,
                           "kms_key": RUNTIME_KEY, "artifacts": [],
                           "groups": {c["component_id"]: str(c["native_id"]).rsplit("/", 1)[-1]
                                      for c in signal.get("components", []) if c.get("type") == "iam_group"}}
    fetch_errors = []
    import base64

    def site(path: str) -> bytes:
        return fetch_bytes("https://samaydlette.com/" + path)

    for a in arts:
        try:
            item = {"artifact": a["artifact"], "kind": a["kind"], "identity": checks.expected_identity(a["cadence"])}
            if a["kind"] == "dsse":
                item["bundle_b64"] = base64.b64encode(site(a["artifact"])).decode()
                item["subject_b64"] = base64.b64encode(site(a["subject"])).decode()
            else:
                item["body_b64"] = base64.b64encode(site(a["artifact"])).decode()
                item["bundle_b64"] = base64.b64encode(site(a["bundle"])).decode()
            req["artifacts"].append(item)
        except OSError as exc:
            fetch_errors.append({"artifact": a["artifact"], "fetch_error": f"could not fetch ({type(exc).__name__})"})
    facts = read_facts(container, req)
    sig_facts = facts["signatures"] + fetch_errors
    out: dict[str, dict[str, Any]] = {"signatures": checks.judge_signatures(sig_facts, arts)}

    gh = read_github(container)
    out["provenance"] = checks.judge_provenance(sig_facts, gh["runs"], gh["workflows"], GITHUB_RUN_WINDOW)

    tag_cfg = json.loads((REPO / "infrastructure" / "policy" / "config" / "data.json").read_text())["gate"]
    live = checks.live_values(tap, matched_components(tap, signal), signal)
    out["live_configuration"] = checks.judge_live(checks.live_claims(signal, tag_cfg), live, facts["groups"])

    runtime = None
    published_pem = None
    if facts.get("kms_pem"):
        try:
            rt = workdir / "ksi-signal-runtime.json"
            rt.write_bytes(site(".well-known/ksi-signal-runtime.json"))
            runtime = verify_runtime_with(facts["kms_pem"], rt, workdir)
            published_pem = site(".well-known/runtime-signing-pubkey.pem").decode("ascii")
        except OSError:
            runtime = runtime or {"verified": False, "reason": "runtime signal could not be fetched"}
    out["runtime_signing_key"] = checks.judge_signing_key(facts.get("kms_der_sha256"), published_pem,
                                                          json.loads(PINNED_KEY.read_text()), runtime)

    vdr = json.loads(site(".well-known/vdr-report.json"))
    out["vulnerabilities"] = checks.judge_vulnerabilities(gh.get("dependabot_observability"), gh.get("alerts"), vdr)

    pinned = json.loads(RULES_SOURCES.read_text())["commit"]
    try:
        head = json.loads(fetch_bytes(UPSTREAM_HEAD))["sha"]
        if not re.fullmatch(r"[0-9a-f]{40}", str(head)):  # it goes into a URL path
            raise ValueError("upstream HEAD is not a commit SHA")
        upstream = json.loads(fetch_bytes(UPSTREAM_RULES.format(commit=head)))
    except (OSError, KeyError, ValueError):
        head, upstream = None, None
    out["ksi_catalog"] = checks.judge_ksi_catalog(signal, upstream, head, pinned)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Corroborate the published evidence with RAMPART on TAP.")
    ap.add_argument("--tap-container", default="tap_corroborate-web-1")
    ap.add_argument("--collect", action="store_true", help="run TAP's aws_core and github_core collectors first")
    ap.add_argument("--signal", default=f"{SITE}/ksi-signal.json")
    ap.add_argument("--map", default=f"{SITE}/boundary-map.json")
    ap.add_argument("--output", default=str(OUT))
    a = ap.parse_args()

    if a.collect:
        for c in (COLLECTOR, GITHUB_COLLECTOR):
            print(f"corroborate: running TAP's {c} collector…", file=sys.stderr)
            collect(a.tap_container, c)
    bmap = fetch_json(a.map)
    signal = fetch_json(a.signal)
    tap = read_tap(a.tap_container)
    report = compare(tap, signal, bmap, datetime.now(timezone.utc), tap_version(a.tap_container))
    assert_comparable(report, bmap)
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        report = assemble(report, gather(a.tap_container, signal, tap, Path(td)))
    text = json.dumps(report, indent=2) + "\n"
    check_redaction(text)
    Path(a.output).write_text(text)
    s = report["summary"]
    print(f"corroborate: {report['result']}: boundary {report['boundary_result']} ({s['agree']} of {s['in_scope']} "
          f"components agree). Sections: "
          + ", ".join(f"{k} {v['status']}" for k, v in report["checks"].items()) + f". Wrote {a.output}")


if __name__ == "__main__":
    main()
