"""The boundary map is built from the inventory, the classification and Terraform state.

Pure-function tests over a synthetic three-component system. Account numbers use the
AWS documentation example (this repo is public).
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("bbg", REPO / "scripts" / "build-boundary-graph.py")
assert spec and spec.loader
bbg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bbg)

ACCOUNT = "123456789012"
FN_ARN = f"arn:aws:lambda:us-east-2:{ACCOUNT}:function:app"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/app-role"
BUCKET_ARN = "arn:aws:s3:::app-bucket"
RULE_ARN = f"arn:aws:events:us-east-2:{ACCOUNT}:rule/app-schedule"

SIGNAL = {
    "signal_id": "sig-1",
    "components": [
        {"component_id": "aws::function::app", "type": "function", "native_id": FN_ARN,
         "attributes": {"tf_address": "aws_lambda_function.app", "function_name": "app", "region": "us-east-2",
                        "classification": {"archetype": "app-tier", "internet_reachable": True, "owner": "x"}}},
        {"component_id": "aws::iam_role::app", "type": "iam_role", "native_id": ROLE_ARN,
         "attributes": {"tf_address": "aws_iam_role.app"}},
        {"component_id": "aws::object_store::data", "type": "object_store", "native_id": BUCKET_ARN,
         "attributes": {"tf_address": "aws_s3_bucket.data"}},
        {"component_id": "aws::event_schedule::app", "type": "event_schedule", "native_id": RULE_ARN,
         "attributes": {"tf_address": "aws_cloudwatch_event_rule.app"}},
        {"component_id": "pkg:npm/left-pad", "type": "npm_package", "native_id": "x"},
    ],
}
TAGS = {k: "x" for k in ("DataSensitivity", "MissionCriticality", "InternetReachable", "AgencyScope", "OwnerRole", "Archetype")}
STATE = {"values": {"root_module": {"resources": [
    {"address": "aws_lambda_function.app", "type": "aws_lambda_function", "mode": "managed",
     "values": {"arn": FN_ARN, "function_name": "app", "role": ROLE_ARN, "tags_all": TAGS}},
    {"address": "aws_iam_role.app", "type": "aws_iam_role", "mode": "managed",
     "values": {"arn": ROLE_ARN, "name": "app-role", "tags_all": {},
                "inline_policy": [{"policy": json.dumps({"Statement": [{"Resource": f"{BUCKET_ARN}/*"}]})}]}},
    {"address": "aws_s3_bucket.data", "type": "aws_s3_bucket", "mode": "managed",
     "values": {"arn": BUCKET_ARN, "bucket": "app-bucket", "tags_all": TAGS}},
    {"address": "aws_cloudwatch_event_rule.app", "type": "aws_cloudwatch_event_rule", "mode": "managed",
     "values": {"arn": RULE_ARN, "name": "app-schedule", "tags_all": TAGS}},
    # A connector: links the schedule to the function it invokes.
    {"address": "aws_cloudwatch_event_target.app", "type": "aws_cloudwatch_event_target", "mode": "managed",
     "values": {"rule": "app-schedule", "arn": FN_ARN}},
    # Not a connector and not a component: must not link what it mentions.
    {"address": "data.aws_iam_policy_document.x", "type": "aws_iam_policy_document", "mode": "data",
     "values": {"json": json.dumps({"Resource": [FN_ARN, BUCKET_ARN]})}},
]}}}
CLASSIFICATION = {
    "zones": [{"key": "system", "label": "System", "boundary": True}, {"key": "outside", "label": "Outside"}],
    "groups": [
        {"key": "app", "zone": "system", "label": "App", "match": ["aws::function::*", "aws::iam_role::*", "aws::event_schedule::*"]},
    ],
    "declared": [{"key": "users", "label": "Users", "zone": "outside", "kind": "actor", "why": "They use it."}],
    "flows": [
        {"id": "A", "label": "Users → app", "path": [{"declared": "users"}, {"component": "aws::function::*"}]},
        {"id": "B", "label": "App → missing", "path": [{"component": "aws::function::app"}, {"component": "aws::queue::gone"}]},
    ],
}
VDR = {"findings": [{"component_id": "aws::function::app", "is_blocking": True, "current_disposition": "open"}]}


def build(**overrides):
    args = dict(signal=SIGNAL, classification=CLASSIFICATION, states=[STATE], offering={}, vdr=VDR,
                trust_root_plan={"status": "changes_pending", "changes": [{"address": "aws_iam_role.app", "actions": ["update"]}]},
                commit="c", now="2026-09-28T00:00:00+00:00")
    args.update(overrides)
    return bbg.build(**args)


def node(graph, cid):
    return next(n for n in graph["nodes"] if n["id"] == cid)


def edge_pairs(graph):
    return {(e["source"], e["target"]) for e in graph["edges"]}


def test_nodes_are_boundary_components_plus_declared_nodes():
    ids = {n["id"] for n in build()["nodes"]}
    assert "pkg:npm/left-pad" not in ids
    assert {"aws::function::app", "aws::object_store::data", "declared:users"} <= ids


def test_a_component_no_rule_places_is_unclassified():
    g = build()
    assert g["unclassified"] == ["aws::object_store::data"]
    assert node(g, "aws::object_store::data")["zone"] == "unclassified"
    assert g["health"]["unclassified"] == 1


def test_edges_follow_references_including_inside_policy_documents():
    pairs = edge_pairs(build())
    assert ("aws::function::app", "aws::iam_role::app") in pairs  # the function's role attribute
    assert ("aws::iam_role::app", "aws::object_store::data") in pairs  # a bucket ARN inside the inline policy


def test_connectors_link_what_they_name_and_nothing_else_does():
    pairs = edge_pairs(build())
    assert ("aws::event_schedule::app", "aws::function::app") in pairs  # via the event target
    # the policy-document data source mentions both, but is not a connector
    assert ("aws::function::app", "aws::object_store::data") not in pairs


def test_flows_resolve_against_real_nodes_and_report_unmatched_endpoints():
    flows = {f["id"]: f for f in build()["flows"]}
    assert flows["A"]["hops"] == [["declared:users", "aws::function::app"]]
    assert flows["B"]["unmatched_endpoints"] == ["aws::queue::gone"]


def test_flags_findings_and_public_classification_only():
    g = build()
    role = node(g, "aws::iam_role::app")
    assert "untagged" in role["flags"] and "change pending apply" in role["flags"]
    fn = node(g, "aws::function::app")
    assert fn["findings"] == {"total": 1, "open": 1, "blocking": 1, "kev": 0}
    assert fn["classification"] == {"archetype": "app-tier", "internet_reachable": True}  # no owner


def test_published_map_carries_no_arn_or_account_id():
    text = json.dumps(build())
    assert "arn:aws" not in text and ACCOUNT not in text
    with pytest.raises(SystemExit):
        bbg.check_redaction(json.dumps({"x": ROLE_ARN}))


def test_shared_names_are_not_evidence_of_a_reference():
    # Two components that share a name (a bucket and a zone both called
    # "shared-name") must not be linked through a resource that mentions it.
    signal = {"components": [
        {"component_id": "aws::object_store::a", "type": "object_store", "native_id": "arn:aws:s3:::shared-name",
         "attributes": {"tf_address": "aws_s3_bucket.a", "name": "shared-name"}},
        {"component_id": "aws::dns_zone::b", "type": "dns_zone", "native_id": "zone-b",
         "attributes": {"tf_address": "aws_route53_zone.b", "name": "shared-name"}},
        {"component_id": "aws::tls_certificate::c", "type": "tls_certificate", "native_id": "cert-c",
         "attributes": {"tf_address": "aws_acm_certificate.c"}},
    ]}
    state = {"values": {"root_module": {"resources": [
        {"address": "aws_acm_certificate.c", "type": "aws_acm_certificate", "mode": "managed", "values": {"domain_name": "shared-name"}},
    ]}}}
    g = build(signal=signal, states=[state], vdr=None, trust_root_plan=None)
    assert not any(e["source"] == "aws::tls_certificate::c" for e in g["edges"])


def test_every_pending_trust_root_change_counts_even_off_the_map():
    # A group's inline policy is not an inventory component, so no node carries
    # its flag; it is still a pending trust-root change and must be counted.
    plan = {"status": "changes_pending", "changes": [
        {"address": "aws_iam_role.app", "actions": ["update"]},
        {"address": "aws_iam_group_policy.operators", "actions": ["create"]},
    ]}
    g = build(trust_root_plan=plan)
    assert g["health"]["pending_trust_root_changes"] == 2
    assert g["trust_root_changes"] == [
        {"address": "aws_iam_group_policy.operators", "actions": ["create"], "component": None},
        {"address": "aws_iam_role.app", "actions": ["update"], "component": "aws::iam_role::app"},
    ]
