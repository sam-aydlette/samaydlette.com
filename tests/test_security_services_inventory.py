"""The AWS security services (infrastructure/security-services.tf) in the canonical
inventory and the boundary.

IAM Access Analyzer's external-access analyzer is a resource with an ARN, so it is
an inventoried component, and its derived classification must equal the tags
Terraform applies (reconciliation invariant (i) compares the two live). Turning
Inspector's Lambda scanning on is an account setting with no resource, so it is
a leveraged AWS service in the boundary classification, never a component.
"""
import importlib.util
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ksi_sec", REPO / "scripts" / "build-ksi-signal.py")
ksi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ksi)
TF = (REPO / "infrastructure" / "security-services.tf").read_text()
BOUNDARY = json.loads((REPO / "docs" / "boundary" / "boundary-classification.json").read_text())


def _components():
    state = {"values": {"root_module": {"resources": [
        {"type": "aws_accessanalyzer_analyzer", "name": "external_access",
         "address": "aws_accessanalyzer_analyzer.external_access",
         "values": {"arn": "arn:aws:access-analyzer:us-east-2:1:analyzer/samaydlette-com-external-access"}},
        {"type": "aws_inspector2_enabler", "name": "lambda", "address": "aws_inspector2_enabler.lambda",
         "values": {"id": "1-LAMBDA", "resource_types": ["LAMBDA"]}},
    ]}}}
    return ksi.build_cloud_components(state, {})


def _profile(name):
    """The tag profile local.cls.<name> in infrastructure/main.tf."""
    main = (REPO / "infrastructure" / "main.tf").read_text()
    body = re.search(rf"\b{name} = \{{([^}}]*)\}}", main).group(1)
    return dict(re.findall(r'(\w+) = "([^"]*)"', body))


def test_the_analyzer_is_an_inventoried_component_with_its_cloudformation_type():
    (c,) = _components()
    assert c["component_id"] == "aws::access_analyzer::external_access"
    assert c["type"] == "access_analyzer" and c["resource_type"] == "AWS::AccessAnalyzer::Analyzer"
    assert c["native_id"].endswith(":analyzer/samaydlette-com-external-access")


def test_turning_on_inspector_is_not_a_component():
    assert "aws_inspector2_enabler" not in ksi.TYPE_BY_TF_TYPE
    assert [c["type"] for c in _components()] == ["access_analyzer"]


def test_the_analyzers_classification_equals_the_tags_terraform_applies():
    (c,) = _components()
    profile = re.search(r'resource "aws_accessanalyzer_analyzer" "external_access" \{.*?merge\(local\.cls\.(\w+),',
                        TF, re.S).group(1)
    tags = _profile(profile)
    cls = c["attributes"]["classification"]
    assert (cls["data_sensitivity"], cls["mission_criticality"], cls["internet_reachable"], cls["archetype"]) == (
        tags["DataSensitivity"], tags["MissionCriticality"], tags["InternetReachable"] == "true", tags["Archetype"])


def test_the_analyzer_is_placed_in_the_boundary_and_inspector_is_leveraged():
    groups = [g for g in BOUNDARY["groups"] if "aws::access_analyzer::*" in g["match"]]
    assert len(groups) == 1 and groups[0]["zone"] == "system"
    assert "Inspector" in BOUNDARY["leveraged"]["services"]


def test_only_lambda_scanning_is_enabled():
    assert re.search(r'resource_types\s*=\s*\["LAMBDA"\]', TF)
    assert "LAMBDA_CODE" not in TF.split('resource "aws_inspector2_enabler"')[1]


def test_opa_requires_governance_and_classification_tags_on_the_analyzer():
    data = json.loads((REPO / "infrastructure" / "policy" / "config" / "data.json").read_text())["gate"]
    assert "aws_accessanalyzer_analyzer" in data["governance_tag_types"]
    assert "aws_accessanalyzer_analyzer" in data["taggable_types"]
