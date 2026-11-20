"""Each CI OIDC role trusts exactly one workflow file (infrastructure/bootstrap/).

The sub condition scopes a role to an environment or ref; job_workflow_ref
scopes it to the workflow file that may present the token. Without it, any
workflow on main that declared the environment could assume the role.
"""
import re
from pathlib import Path

import pytest

BOOT = Path(__file__).resolve().parent.parent / "infrastructure" / "bootstrap"
KEY = "token.actions.githubusercontent.com:job_workflow_ref"
PIN = {
    ("main.tf", "trust"): ["deploy-with-opa.yml@refs/heads/main"],
    ("evidence-nightly.tf", "evidence_nightly_trust"): ["evidence-nightly.yml@refs/heads/main"],
    ("plan-role.tf", "plan_trust"): ["deploy-with-opa.yml@refs/pull/*/merge", "deploy-with-opa.yml@refs/heads/main"],
}


def workflow_pins(text, doc):
    """The job_workflow_ref values in one trust policy document, or None."""
    body = re.search(rf'data "aws_iam_policy_document" "{doc}" \{{(.*?)\n\}}', text, re.S).group(1)
    for cond in re.findall(r"condition \{(.*?)\n    \}", body, re.S):
        if KEY in cond:
            values = re.search(r"values\s*=\s*\[(.*?)\]", cond, re.S).group(1)
            return [v.removeprefix("${var.github_repo}/.github/workflows/") for v in re.findall(r'"([^"]+)"', values)]
    return None


@pytest.mark.parametrize("file,doc", list(PIN))
def test_each_role_trusts_only_its_workflow(file, doc):
    assert workflow_pins((BOOT / file).read_text(), doc) == PIN[(file, doc)]


def test_a_trust_policy_without_the_pin_is_detected():
    text = (BOOT / "main.tf").read_text()
    unpinned = text.replace(KEY, "token.actions.githubusercontent.com:sub")
    assert workflow_pins(unpinned, "trust") is None
