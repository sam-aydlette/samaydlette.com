"""PR-0: governed resource-level tagging standard.

Pins the invariants of the asset-classification layer the VDR PAIN classifier
derives CR/IR/AR, IRV, and m from. See docs/policies/resource-tagging-standard.md.
"""
import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ksi", REPO / "scripts" / "build-ksi-signal.py")
ksi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ksi)


def _state():
    """TF state exercising the components whose classification matters most:
    both Lambdas (same type, different reachability), both buckets, the edges."""
    return {"values": {"root_module": {"resources": [
        {"type": "aws_lambda_function", "name": "silk_reeling",
         "values": {"function_name": "silk-reeling", "arn": "arn:aws:lambda:us-east-2:1:function:silk-reeling"}},
        {"type": "aws_lambda_function", "name": "opa_compliance",
         "values": {"function_name": "opa", "arn": "arn:aws:lambda:us-east-2:1:function:opa"}},
        {"type": "aws_s3_bucket", "name": "logs", "values": {"bucket": "samaydlette-com-logs"}},
        {"type": "aws_s3_bucket", "name": "website", "values": {"bucket": "samaydlette.com"}},
        {"type": "aws_cloudfront_distribution", "name": "website",
         "values": {"id": "E1", "arn": "arn:aws:cloudfront::1:distribution/E1"}},
        {"type": "aws_apigatewayv2_api", "name": "silk_reeling",
         "values": {"id": "api1", "arn": "arn:aws:apigateway:us-east-2::/apis/api1"}},
        {"type": "aws_cognito_user_pool", "name": "silk_reeling",
         "values": {"id": "pool1", "arn": "arn:aws:cognito-idp:us-east-2:1:userpool/pool1"}},
    ]}}}


def _by_tf_name():
    comps = ksi.build_cloud_components(_state(), {})
    return {(c["type"], c["attributes"].get("tf_name")): c["attributes"]["classification"] for c in comps}


def test_every_component_carries_all_six_tags():
    required = {"data_sensitivity", "mission_criticality", "internet_reachable",
                "agency_scope", "owner", "archetype"}
    for cls in _by_tf_name().values():
        assert required <= set(cls), f"missing tags: {required - set(cls)}"


def test_two_lambdas_get_distinct_reachability():
    """The core defect the per-resource override fixes: the public app Lambda and
    the internal compliance Lambda share the 'function' type but must not share
    reachability — a type-only model sent both down one path."""
    cls = _by_tf_name()
    assert cls[("function", "silk_reeling")]["internet_reachable"] is True
    assert cls[("function", "opa_compliance")]["internet_reachable"] is False
    assert cls[("function", "opa_compliance")]["archetype"] == "security-tooling"


def test_resource_override_does_not_bleed_onto_same_named_siblings():
    """Many Silk Reeling resources share tf_name 'silk_reeling' (Lambda, API,
    Cognito pool). The per-resource override is keyed by (type, tf_name), so the
    Lambda's reachability override must not leak onto the Cognito pool or API."""
    cls = _by_tf_name()
    # The Cognito pool keeps its identity-secrets archetype, not the Lambda's app-tier.
    assert cls[("identity_provider", "silk_reeling")]["archetype"] == "identity-secrets"
    # The API Gateway keeps its public-edge archetype.
    assert cls[("api_gateway", "silk_reeling")]["archetype"] == "public-edge"


def test_data_sensitivity_does_not_drift_from_fips199_confidentiality():
    """data_sensitivity must stay consistent with the MAS FIPS-199 confidentiality
    category so the two cannot diverge: low/not-applicable -> public, moderate -> internal."""
    comps = ksi.build_cloud_components(_state(), {})
    allowed = {"low": {"public"}, "not-applicable": {"public"},
               "moderate": {"internal"}, "high": {"pii", "cui"}}
    for c in comps:
        conf = c["security_category"]["confidentiality"]
        ds = c["attributes"]["classification"]["data_sensitivity"]
        assert ds in allowed[conf], f"{c['component_id']}: conf={conf} but data_sensitivity={ds}"


def test_agency_scope_hardwired_single():
    """Single operator, no agency data: m is always 0, so every resource is single-scope."""
    for cls in _by_tf_name().values():
        assert cls["agency_scope"] == "single"


def test_owner_is_a_role_not_a_personal_identifier():
    """The public repo must never carry a personal identifier; owner is a role label."""
    for cls in _by_tf_name().values():
        assert "@" not in cls["owner"]
        assert cls["owner"] == ksi.OPERATOR_ROLE


def test_failsafe_scores_unknown_type_loudly():
    """An untagged/unknown-type resource must resolve to the conservative default
    (never lower risk): cui / high / internet-reachable."""
    comp = {"type": "totally_unknown_type", "attributes": {}}
    ksi.apply_classification_defaults(comp)
    cls = comp["attributes"]["classification"]
    assert cls["data_sensitivity"] == "cui"
    assert cls["mission_criticality"] == "high"
    assert cls["internet_reachable"] is True
