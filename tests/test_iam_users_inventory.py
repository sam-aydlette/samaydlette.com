"""IAM users in Terraform (infrastructure/bootstrap/iam-users.tf) and the inventory.

Every IAM user is a component of type iam_user. Permissions come from groups
only: no Terraform in this repository attaches a policy to a user.
"""
import importlib.util
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ksi_users", REPO / "scripts" / "build-ksi-signal.py")
ksi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ksi)
BOOT = REPO / "infrastructure" / "bootstrap"
TF = (BOOT / "iam-users.tf").read_text()
BOUNDARY = json.loads((REPO / "docs" / "boundary" / "boundary-classification.json").read_text())


def _users():
    state = {"values": {"root_module": {"resources": [
        {"type": "aws_iam_user", "name": n, "address": f"aws_iam_user.{n}",
         "values": {"arn": f"arn:aws:iam::1:user/{n}", "name": n}}
        for n in ("operator", "read_only", "corroboration_collector")]}}}
    return ksi.build_cloud_components(state, {})


def test_each_user_is_an_inventoried_component_with_its_cloudformation_type():
    users = _users()
    assert [c["component_id"] for c in users] == [
        "aws::iam_user::operator", "aws::iam_user::read_only", "aws::iam_user::corroboration_collector"]
    assert {c["resource_type"] for c in users} == {"AWS::IAM::User"}


def test_users_are_placed_in_the_boundary():
    assert any("aws::iam_user::*" in g["match"] and g["zone"] == "system" for g in BOUNDARY["groups"])


def test_every_declared_user_is_in_a_group():
    users = re.findall(r'resource "aws_iam_user" "(\w+)"', TF)
    member = re.findall(r"user\s*=\s*aws_iam_user\.(\w+)\.name", TF + (BOOT / "main.tf").read_text())
    assert users and sorted(users) == sorted(set(member))


def policies_on_users(texts):
    return [t for text in texts for t in re.findall(r'resource "(aws_iam_user_policy(?:_attachment)?)"', text)]


def test_no_policy_is_attached_to_a_user():
    texts = [f.read_text() for f in (REPO / "infrastructure").rglob("*.tf") if ".terraform" not in f.parts]
    assert policies_on_users(texts) == []
    assert policies_on_users(['resource "aws_iam_user_policy_attachment" "x" {}']) == ["aws_iam_user_policy_attachment"]
