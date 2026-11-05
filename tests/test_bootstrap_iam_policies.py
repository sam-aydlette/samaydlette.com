"""The bootstrap groups' inline policies and the managed-policy attachments on
the roles and groups are inventory components, so a scanner finding that names
one (checkov on infrastructure/bootstrap) resolves to it instead of being
recorded as vdr.unresolved-component. Attached policies are published by name
only: their ARNs carry the account ID."""
import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
STATE = json.loads((REPO / "tests" / "fixtures" / "bootstrap-iam" / "state.json").read_text())


def _load(name, script):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / script)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


bks = _load("bks_iam", "build-ksi-signal.py")
vdr = _load("vdr_iam", "build-vdr-report.py")


def _comps():
    return {c["component_id"]: c for c in bks.build_cloud_components(STATE, {}, module_dir="infrastructure/bootstrap")}


def _tf(comps):
    return [(cid, c["attributes"].get("tf_type"), c["attributes"].get("tf_name")) for cid, c in comps.items()]


def test_group_policies_and_attachment_blocks_are_components():
    comps = _comps()
    pol = comps["aws::iam_policy::operators_s3_bucket"]
    assert pol["native_id"] == "iam-group-policy::operators/s3-bucket"
    assert pol["attributes"]["attached_to_group"] == "operators"
    assert "policy_document_sha256" in pol["attributes"]
    legacy = comps["aws::iam_policy::legacy"]
    assert legacy["native_id"] == "iam-role-policy-attachment::github-actions-deploy-oidc/legacy"
    assert legacy["attributes"]["tf_address"] == "aws_iam_role_policy_attachment.legacy"
    assert legacy["attributes"]["attached_policies"] == [
        {"policy_name": "github_actions_3", "aws_managed": False},
        {"policy_name": "github_policy_3", "aws_managed": False}]
    assert comps["aws::iam_policy::read_only"]["native_id"] == "iam-group-policy-attachment::read-only/read_only"
    assert comps["aws::iam_policy::plan_read_only"]["attributes"]["attached_policies"] == [
        {"policy_name": "ReadOnlyAccess", "aws_managed": True}]
    assert len({c["native_id"] for c in comps.values()}) == len(comps)


def test_no_account_id_in_any_new_component():
    text = json.dumps([c for c in _comps().values() if c["type"] == "iam_policy"])
    assert "123456789012" not in text


def test_known_bad_without_the_components_the_checkov_findings_resolve_to_nothing():
    """The live findings that were vdr.unresolved-component: each resolves now,
    and against an inventory without the bootstrap policies (the fixture with
    them removed) each still resolves to nothing."""
    comps = _comps()
    findings = ["aws_iam_group_policy.operators_assessment_readonly", "aws_iam_group_policy.operators_s3_bucket",
                "aws_iam_group_policy.read_only_deny_sensitive", "aws_iam_role_policy_attachment.legacy"]
    for res in findings:
        name = res.split(".", 1)[1]
        assert vdr.resolve_component({"resource": res}, {}, _tf(comps)) == f"aws::iam_policy::{name}", res
    without = {cid: c for cid, c in comps.items() if c["type"] != "iam_policy"}
    for res in findings:
        assert vdr.resolve_component({"resource": res}, {}, _tf(without)) is None


def test_the_bootstrap_policies_fall_in_the_ci_cd_boundary_entry():
    cls = (REPO / "docs" / "boundary" / "boundary-classification.json").read_text()
    assert '"aws::iam_policy::*"' in cls


def test_an_attachment_on_a_group_resolves_to_the_attachment_not_the_group():
    comps = _comps()
    comps.update({c["component_id"]: c for c in bks.build_cloud_components(
        {"values": {"root_module": {"resources": [
            {"type": "aws_iam_group", "name": "read_only", "address": "aws_iam_group.read_only",
             "values": {"arn": "arn:aws:iam::123456789012:group/read-only", "name": "read-only"}}]}}}, {})})
    tf = _tf(comps)
    assert vdr.resolve_component({"resource": "aws_iam_group_policy_attachment.read_only"}, {}, tf) == \
        "aws::iam_policy::read_only"
    assert vdr.resolve_component({"resource": "aws_iam_group.read_only"}, {}, tf) == "aws::iam_group::read_only"
