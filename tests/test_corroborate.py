"""The independent corroboration (RAMPART on TAP) compares like with like, and leaks nothing.

Pure-function tests over a synthetic TAP collection and inventory. Account
numbers use the AWS documentation example (this repo is public).
"""

from __future__ import annotations

import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("corr", REPO / "tools" / "boundary-map" / "corroborate.py")
assert spec and spec.loader
corr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corr)

A = "123456789012"
NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
CLS = {"data_sensitivity": "internal", "mission_criticality": "moderate", "internet_reachable": False, "archetype": "app-tier"}

SIGNAL = {"signal_id": "sig", "components": [
    {"component_id": "aws::function::app", "type": "function", "native_id": f"arn:aws:lambda:us-east-2:{A}:function:app",
     "attributes": {"classification": CLS}},
    {"component_id": "aws::log_group::app", "type": "log_group", "native_id": f"arn:aws:logs:us-east-2:{A}:log-group:/aws/lambda/app",
     "attributes": {"classification": CLS}},
    {"component_id": "aws::dns_zone::site", "type": "dns_zone", "native_id": "arn:aws:route53:::hostedzone/ZABC"},
    {"component_id": "aws::object_store::gone", "type": "object_store", "native_id": "arn:aws:s3:::gone"},
    {"component_id": "aws::notification_topic::alerts", "type": "notification_topic", "native_id": f"arn:aws:sns:us-east-2:{A}:alerts"},
]}
MAP = {"ksi_signal_id": "sig", "commit": "c", "generated_at": "2026-10-01T00:00:00+00:00",
       "nodes": [{"id": c["component_id"]} for c in SIGNAL["components"]],
       "edges": [{"source": "aws::function::app", "target": "aws::log_group::app"}]}
TAP = {"finished_at": "2026-10-01T11:00:00+00:00", "entities": [
    {"id": "1", "type": "lambda", "fields": {"function_arn": f"arn:aws:lambda:us-east-2:{A}:function:app",
                                             "tags": {"Archetype": "app-tier", "DataSensitivity": "cui"}}},
    {"id": "2", "type": "cloudwatch_log_group", "fields": {"log_group_arn": f"arn:aws:logs:us-east-2:{A}:log-group:/aws/lambda/app:*"}},
    {"id": "3", "type": "route53_zone", "fields": {"hosted_zone_id": "/hostedzone/ZABC"}},
    {"id": "4", "type": "dynamodb_table", "fields": {"table_arn": f"arn:aws:dynamodb:us-east-2:{A}:table/lock"}},
    {"id": "5", "type": "iam_role", "fields": {"role_arn": f"arn:aws:iam::{A}:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport"}},
    {"id": "6", "type": "kms_key", "fields": {"key_arn": f"arn:aws:kms:us-east-2:{A}:key/abc", "key_manager": "AWS",
                                              "description": "Default key that protects my Lambda functions when no other key is defined"}},
], "edges": [
    {"type": "WRITES_LOGS__aws_core", "from": "1", "to": "2"},     # on the map
    {"type": "ROUTES_TRAFFIC__aws_core", "from": "3", "to": "1"},  # not on the map
]}


def run(**over):
    args = dict(tap=TAP, signal=SIGNAL, bmap=MAP, now=NOW)
    args.update(over)
    return corr.compare(**args)


def test_identifiers_match_across_tap_and_inventory_forms():
    r = run()
    # log group ":*" and the bare hosted-zone id are normalised to the inventory's ARN form
    assert r["agree"] == ["aws::dns_zone::site", "aws::function::app", "aws::log_group::app"]


def test_each_kind_of_difference_is_reported():
    r = run()
    assert r["result"] == "differs"
    assert [m["component"] for m in r["map_only"]] == ["aws::object_store::gone"]
    assert r["tap_only"] == [{"type": "dynamodb_table", "name": "lock", "why": r["tap_only"][0]["why"]}]
    assert r["tag_differences"] == [{"component": "aws::function::app", "tag": "DataSensitivity", "inventory": "internal", "live": "cui"}]
    assert r["relationships_tap_only"] == [{"from": "aws::dns_zone::site", "to": "aws::function::app", "relationship": "routes traffic"}]


def test_aws_managed_resources_are_not_findings():
    r = run()
    assert {m["name"] for m in r["provider_managed"]} == {
        "aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport", "AWS-managed default key (Lambda)"}
    assert r["summary"]["provider_managed"] == 2


def test_types_tap_does_not_collect_are_out_of_scope_not_missing():
    r = run()
    assert r["not_covered_by_tap"] == {"notification_topic": 1}
    assert "aws::notification_topic::alerts" not in [m["component"] for m in r["map_only"]]


def test_a_map_bound_to_another_inventory_is_refused():
    with pytest.raises(SystemExit):
        run(bmap={**MAP, "ksi_signal_id": "other"})


def test_the_report_carries_no_arn_account_or_email():
    corr.check_redaction(json.dumps(run()))
    with pytest.raises(SystemExit):
        corr.check_redaction(json.dumps({"x": f"arn:aws:s3:::b {A}"}))


def test_the_committed_report_is_safe_to_publish():
    path = REPO / "docs" / "boundary" / "corroboration.json"
    if not path.exists():
        pytest.skip("no corroboration report committed")
    text = path.read_text()
    corr.check_redaction(text)
    doc = json.loads(text)
    assert doc["schema"] == corr.SCHEMA and doc["checked_at"] and doc["corroborated_by"]["collected_at"]
