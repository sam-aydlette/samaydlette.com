"""Each published VDR finding names the inventory component it affects, or none.

The boundary map places findings on components, so a wrong attribution is a false
statement about a specific resource. Resolution must be exact or not happen.
"""

import importlib.util
import json
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("vdr_c", REPO / "scripts" / "build-vdr-report.py")
vdr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vdr)

SIGNAL = {"components": [
    {"component_id": "aws::object_store::logs", "type": "object_store", "native_id": "arn:aws:s3:::example-logs",
     "resource_type": "AWS::S3::Bucket", "attributes": {"tf_type": "aws_s3_bucket", "tf_name": "logs"}},
    {"component_id": "aws::audit_log_trail::management", "type": "audit_log_trail", "native_id": "trail",
     "attributes": {"tf_type": "aws_cloudtrail", "tf_name": "management"}},
    {"component_id": "npm::yaml@1.10.3", "type": "npm_package", "global_id": {"purl": "pkg:npm/yaml@1.10.3"},
     "attributes": {"name": "yaml"}},
]}


def resolve(resource):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "ksi-signal.json"
        p.write_text(json.dumps(SIGNAL))
        return vdr.resolve_component({"resource": resource}, vdr.build_component_index(p), vdr.tf_components_of(p))


def test_exact_identifier():
    assert resolve("arn:aws:s3:::example-logs") == "aws::object_store::logs"


def test_terraform_address_and_its_sub_resources():
    assert resolve("aws_s3_bucket.logs") == "aws::object_store::logs"
    assert resolve("aws_s3_bucket_server_side_encryption_configuration.logs") == "aws::object_store::logs"
    assert resolve("aws_cloudtrail.management") == "aws::audit_log_trail::management"


def test_package_style_resources_use_containment():
    assert resolve("npm:yaml") == "npm::yaml@1.10.3"


def test_file_level_findings_stay_unattributed():
    assert resolve(".checkov.yaml") is None
    assert resolve("infrastructure/logging.tf") is None
    assert resolve("aws_s3_bucket.nonexistent") is None
