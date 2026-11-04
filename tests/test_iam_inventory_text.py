"""The inventory's IAM text says what the trust policy says.

The per-type default once described every IAM role as "Trust policy bound to
lambda.amazonaws.com" and every inline policy as "attached to the Lambda role",
including the GitHub OIDC roles that deploy the system. The text is now derived
from each role's trust policy in Terraform state; a role whose trust cannot be
read makes no claim about who it trusts.
"""
import importlib.util
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("bks_iam", REPO / "scripts" / "build-ksi-signal.py")
bks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bks)

STATE = json.loads((REPO / "tests" / "fixtures" / "resources" / "iam-trust-state.json").read_text())
TEXT_KEYS = ("function", "baseline_configuration", "diagram_label")


def comps(module_dir="infrastructure/bootstrap"):
    return {c["component_id"]: c["attributes"] for c in bks.build_cloud_components(STATE, {}, module_dir=module_dir)}


def test_github_oidc_role_is_described_as_one():
    a = comps()["aws::iam_role::deploy"]
    assert a["trusted_principals"] == ["federated:token.actions.githubusercontent.com"]
    assert "GitHub OIDC provider" in a["baseline_configuration"]
    assert "no AWS service principal" in a["baseline_configuration"]
    for k in TEXT_KEYS:
        assert "lambda" not in a[k].lower(), (k, a[k])
    assert a["function"] == "CI deploy role (reviewer-gated prod environment)"


def test_lambda_role_text_is_unchanged():
    a = comps("infrastructure/main.tf")["aws::iam_role::lambda_opa"]
    assert a["trusted_principals"] == ["service:lambda.amazonaws.com"]
    assert a["baseline_configuration"] == ("Trust policy bound to lambda.amazonaws.com; inline policy hashed in "
                                           "attributes (body in infrastructure/main.tf)")


def test_a_role_whose_trust_cannot_be_read_claims_nothing_about_it():
    a = comps()["aws::iam_role::mystery"]
    assert "trusted_principals" not in a
    assert "bound to" not in a["baseline_configuration"]
    assert "lambda" not in a["function"].lower()


def test_inline_policies_name_their_own_role_and_module():
    c = comps()
    assert c["aws::iam_policy::reconcile_reads"]["function"] == "Inline policy on role github-actions-deploy-oidc"
    assert "infrastructure/bootstrap" in c["aws::iam_policy::reconcile_reads"]["baseline_configuration"]
    assert "Lambda" not in c["aws::iam_policy::reconcile_reads"]["baseline_configuration"]
    app = comps("infrastructure/main.tf")
    assert app["aws::iam_policy::lambda_opa"]["function"] == "Inline policy on role samaydlette-com-lambda-opa-role"
    assert "infrastructure/main.tf" in app["aws::iam_policy::lambda_opa"]["baseline_configuration"]


def test_group_text_states_mfa_for_humans_and_keys_for_machines():
    for b in (comps()["aws::iam_group::read_only"]["baseline_configuration"],
              bks.IIW_DEFAULTS["iam_group"]["baseline_configuration"]):
        assert "human members (console password) authenticate with MFA" in b
        assert "machine members authenticate with access keys and have no console password" in b


def test_read_only_group_is_not_described_as_administration():
    a = comps()["aws::iam_group::read_only"]
    assert "read-only" in a["function"].lower()
    assert "admin" not in (a["function"] + a["baseline_configuration"]).lower()


def test_no_arn_or_account_number_in_any_iam_text():
    for cid, a in comps().items():
        for k in (*TEXT_KEYS, "trusted_principals"):
            v = json.dumps(a.get(k, ""))
            assert "arn:aws" not in v and not re.search(r"(?<!\d)\d{12}(?!\d)", v), (cid, k, v)
