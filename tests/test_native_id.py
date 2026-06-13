# Task 1 acceptance: per-Lambda native_id.
# Two Lambdas in one Terraform state must each carry their OWN ARN as native_id;
# the shared `lambda_function_arn` output must never override per-resource
# identity, and the "Not created" sentinel must never become a native_id.

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ksi", REPO / "scripts" / "build-ksi-signal.py")
ksi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ksi)

ARN_A = "arn:aws:lambda:us-east-1:111111111111:function:opa-compliance"
ARN_B = "arn:aws:lambda:us-east-1:111111111111:function:silk-reeling"


def _state(two_lambdas=True):
    resources = [
        {"address": "aws_lambda_function.opa_compliance", "type": "aws_lambda_function",
         "name": "opa_compliance", "values": {"arn": ARN_A, "function_name": "opa-compliance"}},
    ]
    if two_lambdas:
        resources.append(
            {"address": "aws_lambda_function.silk_reeling", "type": "aws_lambda_function",
             "name": "silk_reeling", "values": {"arn": ARN_B, "function_name": "silk-reeling"}})
    return {"values": {"root_module": {"resources": resources}}}


def _native_ids(components):
    return [c.get("native_id") for c in components if c.get("native_id")]


def test_each_lambda_gets_its_own_arn():
    # tf_outputs carries ONE of the two ARNs — must not be applied to both.
    comps = ksi.build_cloud_components(_state(), {"lambda_function_arn": {"value": ARN_A}})
    funcs = {c["attributes"]["tf_name"]: c.get("native_id") for c in comps if c.get("type") == "function"}
    assert funcs["opa_compliance"] == ARN_A
    assert funcs["silk_reeling"] == ARN_B
    ids = _native_ids(comps)
    assert len(ids) == len(set(ids)), f"duplicate native_id: {ids}"


def test_not_created_sentinel_never_becomes_native_id():
    comps = ksi.build_cloud_components(_state(), {"lambda_function_arn": {"value": "Not created"}})
    assert "Not created" not in _native_ids(comps)
    funcs = {c["attributes"]["tf_name"]: c.get("native_id") for c in comps if c.get("type") == "function"}
    assert funcs["opa_compliance"] == ARN_A
    assert funcs["silk_reeling"] == ARN_B


def test_sentinel_fallback_yields_no_native_id_rather_than_garbage():
    # A Lambda whose state block has no arn AND whose output is a sentinel must
    # not get "Not created" as its identity.
    state = {"values": {"root_module": {"resources": [
        {"address": "aws_lambda_function.x", "type": "aws_lambda_function",
         "name": "x", "values": {"function_name": "x"}}]}}}
    comps = ksi.build_cloud_components(state, {"lambda_function_arn": {"value": "Not created"}})
    assert "Not created" not in _native_ids(comps)
