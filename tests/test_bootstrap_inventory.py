# =============================================================================
# WS5a: the CI/CD identity plane (infrastructure/bootstrap) is inventoried.
# The bootstrap module's GitHub OIDC provider, deploy/assessment roles, operators
# group, and managed policy must normalize into canonical components with stable
# native_ids and IIW asset types — they are the highest-privilege identities
# governing the system and belong in the inventory, not excused.
# =============================================================================
import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("bks", REPO / "scripts" / "build-ksi-signal.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


bks = _load()

ACC = "arn:aws:iam::975050324277"
BOOTSTRAP_STATE = {"values": {"root_module": {"resources": [
    {"type": "aws_iam_openid_connect_provider", "name": "github",
     "address": "aws_iam_openid_connect_provider.github",
     "values": {"arn": f"{ACC}:oidc-provider/token.actions.githubusercontent.com",
                "url": "token.actions.githubusercontent.com"}},
    {"type": "aws_iam_role", "name": "deploy", "address": "aws_iam_role.deploy",
     "values": {"arn": f"{ACC}:role/github-actions-deploy-oidc",
                "name": "github-actions-deploy-oidc", "assume_role_policy": "{\"x\":1}"}},
    {"type": "aws_iam_group", "name": "operators", "address": "aws_iam_group.operators",
     "values": {"arn": f"{ACC}:group/operators", "name": "operators"}},
    {"type": "aws_iam_policy", "name": "assessment", "address": "aws_iam_policy.assessment",
     "values": {"arn": f"{ACC}:policy/assessment-readonly", "name": "assessment-readonly",
                "policy": "{\"Statement\":[]}"}},
]}}}


def _by_type(comps):
    out = {}
    for c in comps:
        out.setdefault(c["type"], []).append(c)
    return out


def test_bootstrap_types_normalize():
    comps = bks.build_cloud_components(BOOTSTRAP_STATE, {})
    bt = _by_type(comps)
    assert "oidc_provider" in bt and "iam_group" in bt
    assert bt["oidc_provider"][0]["resource_type"] == "AWS::IAM::OIDCProvider"
    assert bt["iam_group"][0]["resource_type"] == "AWS::IAM::Group"


def test_managed_policy_uses_its_own_arn():
    comps = bks.build_cloud_components(BOOTSTRAP_STATE, {})
    pol = [c for c in comps if c["type"] == "iam_policy"][0]
    assert pol["native_id"] == f"{ACC}:policy/assessment-readonly"  # ARN, not synthesized


def test_oidc_and_group_carry_arn_native_ids_and_iiw_type():
    comps = bks.build_cloud_components(BOOTSTRAP_STATE, {})
    bt = _by_type(comps)
    oidc, grp = bt["oidc_provider"][0], bt["iam_group"][0]
    assert oidc["native_id"].endswith("oidc-provider/token.actions.githubusercontent.com")
    assert grp["native_id"].endswith("group/operators")
    assert oidc["attributes"]["iiw_asset_type"] == "OIDC Identity Provider (IAM)"
    assert grp["attributes"]["iiw_asset_type"] == "IAM Group"


def test_bootstrap_components_evidence_iam_ksis():
    # Once inventoried, the bootstrap identities become evidence for IAM-family KSIs.
    comps = bks.build_cloud_components(BOOTSTRAP_STATE, {})
    catalog = {"KSI": {"IAM": {"id": "KSI-IAM", "name": "Identity", "indicators": [
        {"id": "KSI-IAM-ELP", "name": "Least Privilege", "impact": {"moderate": True},
         "controls": [{"control_id": "ac-6"}]}]}}}
    ksis = bks.build_ksi_statuses(catalog, comps, [])
    ksi = next(k for k in ksis if k["id"] == "KSI-IAM-ELP")
    refs = ksi["evidence"]["component_refs"]
    assert any(("oidc_provider" in r) or ("iam_group" in r) or ("iam_role" in r) for r in refs)


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
