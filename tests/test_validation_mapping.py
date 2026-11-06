"""Plan results become validations of the right component (FRC-CSX-VVK).

scripts/build-ksi-signal.py joins the deploy gate's per-resource results
(validations.json) to inventory components. A KSI counts a deploy-time method
only when some validation names one of its components, so the join decides
whether a KSI's plan check is visible at all. These tests pin it: the exact
plan address wins over the shared Terraform name, an ambiguous name or
address credits nobody, API stages and routes fold into their API, and only
types some policy rule actually evaluates are credited (a "pass" from a type
no rule looks at would be a method that does not exist).
"""

import importlib.util
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ksi_vm", REPO / "scripts" / "build-ksi-signal.py")
ksi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ksi)

POLICY = REPO / "infrastructure" / "policy"


def comp(cid, typ, tf_name, address=None):
    attrs = {"tf_name": tf_name}
    if address:
        attrs["tf_address"] = address
    return {"component_id": cid, "type": typ, "attributes": attrs}


def result(tf_type, name, address=None, compliant=True, violations=None):
    r = {"kind": "infrastructure", "resource_type": tf_type, "resource_name": name,
         "compliant": compliant, "violations": violations or [], "policy_version": "2.0"}
    if address:
        r["address"] = address
    return r


def refs(doc, components):
    return [v["component_refs"] for v in ksi.build_validations({"results": doc}, components)]


def test_address_join_credits_the_exact_instance():
    components = [
        comp("alarm::a", "metric_alarm", "evidence", 'aws_cloudwatch_metric_alarm.evidence["a"]'),
        comp("alarm::b", "metric_alarm", "evidence", 'aws_cloudwatch_metric_alarm.evidence["b"]'),
    ]
    got = refs([result("aws_cloudwatch_metric_alarm", "evidence", 'aws_cloudwatch_metric_alarm.evidence["b"]')],
               components)
    assert got == [["alarm::b"]]


def test_shared_name_without_address_credits_nobody():
    components = [
        comp("alarm::a", "metric_alarm", "evidence", 'aws_cloudwatch_metric_alarm.evidence["a"]'),
        comp("alarm::b", "metric_alarm", "evidence", 'aws_cloudwatch_metric_alarm.evidence["b"]'),
    ]
    assert refs([result("aws_cloudwatch_metric_alarm", "evidence")], components) == []


def test_duplicate_address_credits_nobody():
    components = [
        comp("role::main", "iam_role", "deploy", "aws_iam_role.deploy"),
        comp("role::boot", "iam_role", "deploy", "aws_iam_role.deploy"),
    ]
    assert refs([result("aws_iam_role", "deploy", "aws_iam_role.deploy")], components) == []


def test_unique_name_joins_without_address():
    components = [comp("role::lambda", "iam_role", "lambda_opa")]
    assert refs([result("aws_iam_role", "lambda_opa")], components) == [["role::lambda"]]


def test_iam_and_service_types_are_credited():
    components = [
        comp("pol", "iam_policy", "lambda_opa"), comp("lg", "log_group", "opa"),
        comp("key", "kms_key", "at_rest"), comp("pool", "identity_provider", "silk"),
        comp("topic", "notification_topic", "alerts"), comp("q", "message_queue", "dlq"),
        comp("rule", "event_schedule", "nightly"), comp("trail", "audit_log_trail", "management"),
    ]
    doc = [
        result("aws_iam_role_policy", "lambda_opa"), result("aws_cloudwatch_log_group", "opa"),
        result("aws_kms_key", "at_rest"), result("aws_cognito_user_pool", "silk"),
        result("aws_sns_topic", "alerts"), result("aws_sqs_queue", "dlq"),
        result("aws_cloudwatch_event_rule", "nightly"), result("aws_cloudtrail", "management"),
    ]
    assert sorted(r[0] for r in refs(doc, components)) == sorted(c["component_id"] for c in components)


def test_api_stage_and_route_fold_into_the_api():
    components = [comp("api", "api_gateway", "silk_reeling")]
    doc = [result("aws_apigatewayv2_stage", "silk_reeling"),
           result("aws_apigatewayv2_route", "silk_reeling_api", compliant=False,
                  violations=[{"id": "apigw_route_unauthorized"}])]
    got = ksi.build_validations({"results": doc}, components)
    assert [v["component_refs"] for v in got] == [["api"], ["api"]]
    assert got[1]["result"] == "fail"


def test_child_with_two_candidate_parents_credits_nobody():
    components = [comp("api1", "api_gateway", "one"), comp("api2", "api_gateway", "two")]
    assert refs([result("aws_apigatewayv2_route", "three")], components) == []


def test_type_without_a_rule_is_not_credited():
    components = [comp("zone", "dns_zone", "website")]
    assert refs([result("aws_route53_zone", "website")], components) == []


def _rego_sources():
    return "\n".join(p.read_text() for p in POLICY.glob("*.rego") if not p.name.endswith("_test.rego"))


def test_every_plan_validated_type_has_a_rule():
    """Each credited type maps to a Terraform type some rule names (or that the
    tagging rule covers), so a pass means a rule looked at it."""
    src = _rego_sources()
    taggable = set(json.loads((POLICY / "config" / "data.json").read_text())["gate"]["taggable_types"])
    for typ in ksi.PLAN_VALIDATED_TYPES:
        tf_types = [t for t, n in ksi.TYPE_BY_TF_TYPE.items() if n == typ]
        assert tf_types, typ
        assert any(re.search(rf'"{re.escape(t)}"', src) or t in taggable for t in tf_types), (
            f"{typ}: no rule evaluates any of {tf_types}"
        )
    for child in ksi.PLAN_VALIDATED_CHILD_TYPES:
        assert f'"{child}"' in src


def test_function_component_carries_code_hash():
    state = {"values": {"root_module": {"resources": [{
        "address": "aws_lambda_function.opa_compliance", "mode": "managed",
        "type": "aws_lambda_function", "name": "opa_compliance",
        "values": {"function_name": "x-opa", "arn": "arn:aws:lambda:us-east-2:123456789012:function:x-opa",
                   "source_code_hash": "abc=", "code_sha256": "abc=", "tags": {}},
    }]}}}
    comps = ksi.build_cloud_components(state, {})
    fn = [c for c in comps if c["type"] == "function"]
    assert fn and fn[0]["attributes"]["code_sha256"] == "abc="


def test_npm_components_name_the_function_they_ship_in(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "x"},
        "node_modules/left-pad": {"version": "1.3.0", "integrity": "sha512-AAAA"},
    }}))
    comps = ksi.build_npm_components(lock, deployed_in="aws::function::opa_compliance")
    assert comps and all(c["attributes"]["deployed_in"] == "aws::function::opa_compliance" for c in comps)
    assert all("deployed_in" not in c["attributes"] for c in ksi.build_npm_components(lock))
