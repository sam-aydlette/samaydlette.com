"""The evidence-alerting path and the DLQ are in the canonical inventory.

The inventory builder silently skipped any Terraform type it had no mapping
for, so the SNS topic that pages the operator, the three evidence alarms and
the compliance dead-letter queue were missing from the SSP, the IIW and the
VDR. These tests pin that they are inventoried, that the three for_each alarms
stay three components, and that each one's derived classification equals the
tags Terraform applies (reconciliation invariant (i) compares the two live).
"""
import importlib.util
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ksi", REPO / "scripts" / "build-ksi-signal.py")
ksi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ksi)

NEW_TYPES = {"notification_topic", "metric_alarm", "message_queue"}


def _alarm(key):
    return {"type": "aws_cloudwatch_metric_alarm", "name": "evidence", "index": key,
            "address": f'aws_cloudwatch_metric_alarm.evidence["{key}"]',
            "values": {"arn": f"arn:aws:cloudwatch:us-east-2:1:alarm:samaydlette-com-evidence-watchdog-{key}"}}


def _components():
    state = {"values": {"root_module": {"resources": [
        {"type": "aws_sns_topic", "name": "evidence_alerts", "index": 0,
         "address": "aws_sns_topic.evidence_alerts[0]",
         "values": {"arn": "arn:aws:sns:us-east-2:1:samaydlette-com-evidence-alerts"}},
        {"type": "aws_sns_topic_policy", "name": "evidence_alerts", "index": 0,
         "values": {"policy": "{}"}},
        _alarm("vdr-age"), _alarm("runtime-age"), _alarm("nightly-failed"),
        {"type": "aws_sqs_queue", "name": "compliance_dlq", "index": 0,
         "address": "aws_sqs_queue.compliance_dlq[0]",
         "values": {"arn": "arn:aws:sqs:us-east-2:1:samaydlette-com-opa-compliance-dlq"}},
        {"type": "aws_lambda_function", "name": "opa_compliance", "index": 0,
         "values": {"arn": "arn:aws:lambda:us-east-2:1:function:opa"}},
    ]}}}
    return ksi.build_cloud_components(state, {})


def _profile(name):
    """The tag profile local.cls.<name> in infrastructure/main.tf."""
    main = (REPO / "infrastructure" / "main.tf").read_text()
    body = re.search(rf"\b{name} = \{{([^}}]*)\}}", main).group(1)
    return dict(re.findall(r'(\w+) = "([^"]*)"', body))


def _matches(classification, profile):
    return (classification["data_sensitivity"] == profile["DataSensitivity"]
            and classification["mission_criticality"] == profile["MissionCriticality"]
            and classification["internet_reachable"] is (profile["InternetReachable"] == "true")
            and classification["archetype"] == profile["Archetype"])


def test_the_topic_alarms_and_dlq_are_inventoried():
    types = [c["type"] for c in _components()]
    assert types.count("notification_topic") == 1
    assert types.count("metric_alarm") == 3
    assert types.count("message_queue") == 1


def test_for_each_alarms_keep_distinct_ids_and_count_ids_do_not_change():
    comps = {c["component_id"]: c for c in _components()}
    for key in ("vdr-age", "runtime-age", "nightly-failed"):
        c = comps[f"aws::metric_alarm::evidence[{key}]"]
        assert c["attributes"]["tf_index"] == key
        assert c["attributes"]["tf_name"] == "evidence"
    # count-indexed resources keep their historical id (no index in it).
    assert "aws::function::opa_compliance" in comps
    assert "aws::notification_topic::evidence_alerts" in comps


def test_the_topic_policy_folds_into_the_topic():
    (topic,) = [c for c in _components() if c["type"] == "notification_topic"]
    assert "aws_sns_topic_policy" in json.dumps(topic["attributes"].get("config", {}))


def test_derived_classification_equals_the_terraform_tags():
    """watchdog.tf tags the topic and alarms local.cls.security_tooling; main.tf
    tags the DLQ local.cls.security_tooling_internal. Invariant (i) fails the
    deploy if the derived classification disagrees with those live tags."""
    tooling, tooling_internal = _profile("security_tooling"), _profile("security_tooling_internal")
    for c in _components():
        cls = c["attributes"]["classification"]
        if c["type"] in ("notification_topic", "metric_alarm"):
            assert _matches(cls, tooling), (c["component_id"], cls)
        if c["type"] == "message_queue":
            assert _matches(cls, tooling_internal), (c["component_id"], cls)
    tf = (REPO / "infrastructure" / "watchdog.tf").read_text()
    for block in ('resource "aws_sns_topic" "evidence_alerts"', 'resource "aws_cloudwatch_metric_alarm" "evidence"'):
        body = tf[tf.index(block):]
        assert "merge(local.cls.security_tooling," in body[:body.index("\n}\n")]


def test_every_new_type_is_defined_everywhere_a_type_must_be():
    schema = json.loads((REPO / "infrastructure" / "schemas" / "ksi-signal.schema.json").read_text())

    def enums(o):
        if isinstance(o, dict):
            if isinstance(o.get("enum"), list) and "object_store" in o["enum"]:
                yield set(o["enum"])
            for v in o.values():
                yield from enums(v)
        elif isinstance(o, list):
            for v in o:
                yield from enums(v)

    (enum,) = list(enums(schema))  # exactly one component-type enum
    for t in NEW_TYPES:
        assert t in enum, t
        assert t in ksi.CFN_TYPE_BY_NORMALIZED
        assert t in ksi.MAS_DEFAULTS
        assert t in ksi.IIW_DEFAULTS
        assert t in ksi.CLASSIFICATION_DEFAULTS
    assert set(ksi.TYPE_BY_TF_TYPE.values()) <= set(ksi.CFN_TYPE_BY_NORMALIZED)


def test_opa_requires_tags_on_the_new_types():
    data = json.loads((REPO / "infrastructure" / "policy" / "config" / "data.json").read_text())["gate"]
    for tf_type in ("aws_sns_topic", "aws_cloudwatch_metric_alarm", "aws_sqs_queue"):
        assert tf_type in data["governance_tag_types"]
        assert tf_type in data["taggable_types"]
