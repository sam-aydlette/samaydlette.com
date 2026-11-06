"""scripts/check-policy-annotations.py: every annotated rule states the
Terraform types it evaluates (custom.resource_types), which the strict
per-KSI count (build-sdr.py rule_methods) relies on."""

import importlib.util
import shutil
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "policy-annotations"
spec = importlib.util.spec_from_file_location("check_policy_annotations", REPO / "scripts" / "check-policy-annotations.py")
cpa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cpa)

pytestmark = pytest.mark.skipif(shutil.which("opa") is None, reason="opa not available")


def test_the_committed_policy_passes():
    assert cpa.main([]) == 0


def test_a_well_formed_fixture_passes():
    assert cpa.main(["--policy-dir", str(FIX / "good")]) == 0


@pytest.mark.parametrize("name,why", [
    ("missing-resource-types", "custom.resource_types must be a list of Terraform resource types"),
    ("type-not-named", "custom.resource_types ['aws_kms_key'] are not named in the rule's file"),
    ("wildcard-mixed", 'custom.resource_types: "*" stands alone'),
    ("runtime-only-not-bool", "custom.runtime_only must be true or false"),
])
def test_known_bad_annotations_fail_each_for_its_reason(name, why, capsys):
    assert cpa.main(["--policy-dir", str(FIX / name)]) == 1
    out = capsys.readouterr()
    assert why in out.err + out.out


@pytest.mark.parametrize("custom,text,errs", [
    ({"resource_types": ["aws_s3_bucket"]}, '"aws_s3_bucket"', []),
    ({"resource_types": ["*"]}, "", []),
    ({"resource_types": []}, "", []),
    ({"resource_types": ["aws_s3_bucket", "aws_s3_bucket"]}, '"aws_s3_bucket"', ["lists a type twice"]),
    ({"resource_types": "aws_s3_bucket"}, "", ["must be a list"]),
    ({"resource_types": ["aws_s3_bucket"], "runtime_only": "yes"}, '"aws_s3_bucket"', ["must be true or false"]),
])
def test_resource_type_errors(custom, text, errs):
    got = cpa.resource_type_errors(custom, text)
    assert len(got) == len(errs) and all(e in g for e, g in zip(errs, got, strict=True))
