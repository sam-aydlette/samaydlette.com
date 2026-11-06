"""Runtime readers (FRC-CSX-VVK, VDR-TFR-MVX): live configuration, same policy.

infrastructure/lambda/describers.js turns read-only AWS responses into the
Terraform-shaped inputs the deploy gate's Rego reads. These tests drive it
through tests/fixtures/runtime/harness.js with a fake AWS adapter and
evaluate every input with the same policy the gate runs, so they prove:

  * compliant live responses (shapes copied from read-only calls against the
    production account, identifiers replaced) pass the policy;
  * every drifted value in responses-drifted.json (the known-bad fixture) is
    caught by the rule that gates the plan;
  * a denied call is reported as an unread attribute (resource_read_error,
    unassessed), never as a pass and never as a finding;
  * the function's deployment package is a validation of its own whose
    component refs include the packages it ships, so a package component
    has a runtime validation.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "runtime"
POLICY = REPO / "infrastructure" / "policy"
CONFIG = REPO / "infrastructure" / "schemas" / "runtime-vv-config.json"

requires_node = pytest.mark.skipif(not shutil.which("node"), reason="requires node on PATH")


def _opa1():
    opa = shutil.which("opa")
    if not opa:
        return False
    return "Rego Version: v1" in subprocess.run([opa, "version"], capture_output=True, text=True).stdout


requires_opa1 = pytest.mark.skipif(not _opa1(), reason="requires the pinned OPA >= 1.x on PATH")


def run(responses):
    out = subprocess.run(
        ["node", str(FIX / "harness.js"), str(FIX / "components.json"), str(FIX / f"responses-{responses}.json")],
        capture_output=True, text=True, check=True,
    )
    return json.loads(out.stdout)


def evaluate(inputs, tmp_path):
    data = tmp_path / "inputs.json"
    data.write_text(json.dumps({"fx": {"inputs": inputs}}))
    query = (
        "[[x.type, x.name, {v.id | some v in data.terraform.compliance.compliance_report.violations "
        'with input as {"resource": x}}] | some x in data.fx.inputs]'
    )
    out = subprocess.run(
        ["opa", "eval", "--strict-builtin-errors", "-d", str(POLICY), "-d", str(data), "--format", "json", query],
        capture_output=True, text=True, check=True,
    )
    rows = json.loads(out.stdout)["result"][0]["expressions"][0]["value"]
    return {(t, n): set(ids) for t, n, ids in rows}


# The drift each known-bad response introduces, and the rule that must catch it.
DRIFTED = {
    ("aws_iam_role", "lambda_opa"): {"iam_trust_public"},
    ("aws_iam_role", "deploy"): {"iam_oidc_trust_unscoped"},
    # Every action on every resource includes reading the logs (KSI-MLA-ALA).
    ("aws_iam_role_policy", "lambda_opa"): {"iam_admin_wildcard", "log_read_grant_unexpected"},
    ("aws_iam_group", "operators"): {"iam_admin_policy_attached"},
    # A group's inline policy is read with GetGroupPolicy and judged like a role's.
    ("aws_iam_group_policy", "operators_s3_bucket"): {"iam_admin_wildcard", "log_read_grant_unexpected"},
    # The managed policy the inventory records on the group is no longer
    # attached: the attachment cannot be validated, so it is unassessed.
    ("aws_iam_group_policy_attachment", "operators"): {"resource_read_error"},
    ("aws_iam_role_policy_attachment", "legacy"): set(),
    ("aws_iam_openid_connect_provider", "github"): {"oidc_audience_unexpected"},
    ("aws_lambda_function", "opa_compliance"): {"lambda_env_not_cmk", "lambda_public_function_url"},
    ("lambda_deployment_package", "opa_compliance"): {"package_integrity_mismatch"},
    ("aws_cloudwatch_log_group", "opa_compliance"): {"log_group_not_cmk", "log_retention_below_minimum"},
    ("aws_cloudtrail", "management"): {"trail_log_validation_disabled", "trail_not_logging"},
    ("aws_cloudwatch_metric_alarm", "evidence"): {"alarm_not_actionable"},
    ("aws_cloudwatch_event_rule", "opa_compliance"): {"schedule_disabled"},
    ("aws_sns_topic", "evidence_alerts"): {"sns_topic_unencrypted"},
    ("aws_sqs_queue", "compliance_dlq"): {"sqs_queue_unencrypted"},
    ("aws_dynamodb_table", "tflock"): {"dynamodb_pitr_disabled"},
    ("aws_cognito_user_pool", "silk_reeling"): {
        "cognito_mfa_not_required", "cognito_password_too_short", "cognito_self_signup_enabled",
    },
    ("aws_kms_key", "at_rest"): {"kms_rotation_disabled"},
    ("aws_kms_key", "dnssec_ksk"): {"kms_key_disabled"},
    ("aws_apigatewayv2_api", "silk_reeling"): set(),
    ("aws_apigatewayv2_stage", "silk_reeling/$default"): {"apigw_access_logging_disabled", "apigw_unthrottled"},
    ("aws_apigatewayv2_route", "silk_reeling/ANY /api/{proxy+}"): {"apigw_route_unauthorized"},
    ("aws_route53_zone", "website"): {"dnssec_not_signing"},
    ("aws_acm_certificate", "website"): {"certificate_expiring"},
}


@requires_node
@requires_opa1
def test_compliant_live_shapes_pass(tmp_path):
    got = evaluate(run("compliant")["inputs"], tmp_path)
    failing = {k: v for k, v in got.items() if v}
    assert not failing, f"compliant responses produced findings: {failing}"


@requires_node
@requires_opa1
def test_every_drift_is_caught_by_the_gate_rule(tmp_path):
    got = evaluate(run("drifted")["inputs"], tmp_path)
    assert got == DRIFTED


@requires_node
def test_inline_policies_carry_their_holder():
    """The log-access rule keys its allowlist on the policy's holder; the reader
    takes it from the inventory id it already read by (no further AWS call)."""
    holders = {(i["type"], i["name"]): (i["values"].get("role"), i["values"].get("group"))
               for i in run("compliant")["inputs"] if i["type"] in ("aws_iam_role_policy", "aws_iam_group_policy")}
    assert holders[("aws_iam_role_policy", "lambda_opa")] == ("samaydlette-com-lambda-opa-role", None)
    assert holders[("aws_iam_group_policy", "operators_s3_bucket")] == (None, "operators")


@requires_node
@requires_opa1
def test_denied_reads_are_unassessed_not_findings(tmp_path):
    result = run("denied")
    got = evaluate(result["inputs"], tmp_path)
    assert got and all(ids == {"resource_read_error"} for ids in got.values()), got
    for inp in result["inputs"]:
        assert inp.get("read_errors"), f"{inp['type']}.{inp['name']} has no read_errors"


@requires_node
def test_every_machine_type_has_a_reader_or_existing_check():
    """Each governed machine type is read live: by a describers.js reader, or
    by the long-standing bucket/distribution/secret checks in index.js."""
    readers = set(run("compliant")["readers"])
    machine = set(json.loads(CONFIG.read_text())["machine_types"])
    in_index = {"object_store", "cdn_distribution", "secrets_manager"}
    assert machine - readers - in_index == set()


@requires_node
def test_every_component_gets_one_validation_with_its_ref():
    result = run("compliant")
    components = json.loads((FIX / "components.json").read_text())
    machine = [c for c in components if c["type"] not in ("npm_package",)]
    refs = [set(v["component_refs"]) for v in result["validations"]]
    for c in machine:
        assert any(c["component_id"] in r for r in refs), c["component_id"]


@requires_node
def test_package_integrity_validation_covers_shipped_packages_only():
    result = run("compliant")
    pkg = [v for v in result["validations"]
           if "npm::@open-policy-agent/opa-wasm@1.9.0" in v["component_refs"]]
    assert len(pkg) == 1
    assert "aws::function::opa_compliance" in pkg[0]["component_refs"]
    # A build-time package is not deployed in the function, so it is not
    # claimed by the function's integrity check.
    assert not any("npm::pa11y@9.0.0" in v["component_refs"] for v in result["validations"])


@requires_node
def test_unread_tags_are_reported_not_assumed():
    result = run("denied")
    by = {(i["type"], i["name"]): i for i in result["inputs"]}
    assert "tags" in by[("aws_lambda_function", "opa_compliance")]["read_errors"]


@requires_node
@requires_opa1
def test_published_violations_carry_no_account_id(tmp_path):
    """Violations are copied into the published runtime signal: the live
    responses carry the (example) account id in ARNs, the violations must not."""
    data = tmp_path / "inputs.json"
    data.write_text(json.dumps({"fx": {"inputs": run("drifted")["inputs"]}}))
    query = (
        "[v | some x in data.fx.inputs; "
        'some v in data.terraform.compliance.compliance_report.violations with input as {"resource": x}]'
    )
    out = subprocess.run(
        ["opa", "eval", "--strict-builtin-errors", "-d", str(POLICY), "-d", str(data), "--format", "json", query],
        capture_output=True, text=True, check=True,
    )
    violations = json.loads(out.stdout)["result"][0]["expressions"][0]["value"]
    assert len(violations) >= len(DRIFTED) - 1
    assert "123456789012" not in json.dumps(violations)


@requires_node
def test_group_policies_and_attachments_are_read_with_their_own_apis():
    """Inline group policies use GetGroupPolicy (their id is group:name) and
    attachments list the holder's attached policies and compare names, so none
    of the bootstrap IAM policy components comes back unread."""
    by = {(i["type"], i["name"]): i for i in run("compliant")["inputs"]}
    grp = by[("aws_iam_group_policy", "operators_s3_bucket")]
    assert "read_errors" not in grp and '"s3:GetObject"' in grp["values"]["policy"]
    role_att = by[("aws_iam_role_policy_attachment", "legacy")]
    assert "read_errors" not in role_att
    assert [a.rsplit("/", 1)[1] for a in role_att["values"]["attached_policy_arns"]] == ["github-actions-deploy"]
    grp_att = by[("aws_iam_group_policy_attachment", "operators")]
    assert "read_errors" not in grp_att
    assert grp_att["values"]["attached_policy_arns"] == ["arn:aws:iam::aws:policy/IAMFullAccess"]


@requires_node
def test_every_bootstrap_iam_policy_shape_has_a_reader_that_is_not_the_role_policy_api():
    """The inventory's iam_policy components from bootstrap (group inline
    policies and the role and group attachments) each reach a reader that
    calls the matching API, not GetRolePolicy on a split id."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("bks_rt", REPO / "scripts" / "build-ksi-signal.py")
    bks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bks)
    state = json.loads((REPO / "tests" / "fixtures" / "bootstrap-iam" / "state.json").read_text())
    comps = [c for c in bks.build_cloud_components(state, {}, module_dir="infrastructure/bootstrap")
             if c["type"] == "iam_policy"]
    assert {c["attributes"]["tf_type"] for c in comps} >= {
        "aws_iam_group_policy", "aws_iam_role_policy_attachment", "aws_iam_group_policy_attachment"}
    out = subprocess.run(
        ["node", "-e", _CALLS, str(REPO / "infrastructure" / "lambda" / "describers.js")],
        input=json.dumps(comps), capture_output=True, text=True, check=True)
    calls = json.loads(out.stdout)
    for c in comps:
        made = calls[c["component_id"]]
        t = c["attributes"]["tf_type"]
        want = {"aws_iam_group_policy": "getGroupPolicy", "aws_iam_role_policy": "getRolePolicy",
                "aws_iam_role_policy_attachment": "listAttachedRolePolicies",
                "aws_iam_group_policy_attachment": "listAttachedGroupPolicies"}[t]
        assert made == [want], (c["component_id"], made)


# Records which IAM API each component's reader calls (every call denied).
_CALLS = r"""
const { READERS } = require(process.argv[1]);
const comps = JSON.parse(require('fs').readFileSync(0));
(async () => {
    const out = {};
    for (const c of comps) {
        const calls = [];
        const iam = new Proxy({}, { get: (_, m) => async () => { calls.push(m); const e = new Error('x'); e.name = 'AccessDenied'; throw e; } });
        await READERS.iam_policy({ aws: { iam }, components: comps, taggableTypes: [] }, c);
        out[c.component_id] = calls;
    }
    process.stdout.write(JSON.stringify(out));
})();
"""
