"""Fixture-corpus regression tests for the OPA compliance gate.

Runs every plan fixture in tests/fixtures/plans/ through the policy exactly
as the deploy gate does (`opa eval --strict-builtin-errors -d
infrastructure/policy`) and asserts the expected verdict and violation ids.
This is the executable form of the golden corpus: a behavioral change in the
gate fails here, in CI, with a readable diff of ids.

Requires the pinned OPA (>= 1.x) on PATH — the same binary the workflow
installs. Skips with a clear message when only a pre-1.0 opa is available.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
POLICY = REPO / "infrastructure" / "policy"
PLANS = REPO / "tests" / "fixtures" / "plans"

# fixture name -> (expected compliant, expected violation-id set)
EXPECTED = {
    "compliant-stack": (True, set()),
    "data-source-website-bucket": (True, set()),
    "delete-only": (True, set()),
    "empty": (False, {"input_error"}),
    "garbage": (False, {"input_error"}),
    "missing-classification": (False, {"missing_classification_tag"}),
    "cloudfront-insecure-protocol": (False, {"insecure_protocol"}),
    "cloudfront-weak-tls": (False, {"weak_tls"}),
    "s3-missing-tags": (False, {"missing_required_tags"}),
    "s3-versioning-disabled": (False, {"versioning_disabled"}),
    "s3-encryption-disabled": (False, {"encryption_disabled"}),
    "s3-public-access-open": (False, {"public_access_not_fully_blocked"}),
    "s3-computed-bucket-name": (False, {"encryption_disabled", "public_access_not_fully_blocked"}),
}


def _opa_version_ok():
    opa = shutil.which("opa")
    if not opa:
        return False
    out = subprocess.run([opa, "version"], capture_output=True, text=True)
    return "Rego Version: v1" in out.stdout


requires_opa1 = pytest.mark.skipif(
    not _opa_version_ok(),
    reason="requires the pinned OPA >= 1.x on PATH (see .github/workflows/deploy-with-opa.yml OPA_VERSION)",
)


def eval_report(input_path: Path) -> dict:
    out = subprocess.run(
        [
            "opa", "eval", "--strict-builtin-errors",
            "-d", str(POLICY),
            "-i", str(input_path),
            "data.terraform.compliance.compliance_report",
        ],
        capture_output=True, text=True, check=True,
    )
    return json.loads(out.stdout)["result"][0]["expressions"][0]["value"]


@requires_opa1
@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_plan_fixture_verdict(name):
    report = eval_report(PLANS / f"{name}.json")
    want_compliant, want_ids = EXPECTED[name]
    got_ids = {v["id"] for v in report["violations"]}
    assert report["compliant"] is want_compliant, (
        f"{name}: compliant={report['compliant']}, expected {want_compliant} "
        f"(violations: {sorted(got_ids)})"
    )
    assert got_ids == want_ids, f"{name}: violation ids {sorted(got_ids)} != expected {sorted(want_ids)}"


@requires_opa1
def test_every_violation_is_uniform():
    """Every violation object carries the uniform contract fields."""
    required = {"id", "type", "category", "severity", "resource", "address", "message", "control_ids", "ksi_ids"}
    for name in sorted(EXPECTED):
        report = eval_report(PLANS / f"{name}.json")
        for v in report["violations"]:
            missing = required - set(v)
            assert not missing, f"{name}: violation {v.get('id')} missing fields {missing}"


@requires_opa1
def test_accessibility_scan_fixture():
    """Scanner-facts fixture (real pa11y output over tests/fixtures/html/)
    produces the expected per-page decisions."""
    report = eval_report(REPO / "tests" / "fixtures" / "a11y" / "fixture-pages-scan.json")
    assert report["compliant"] is False
    failing = {v["resource"] for v in report["violations"]}
    assert failing == {"missing-alt.html", "missing-lang.html"}
