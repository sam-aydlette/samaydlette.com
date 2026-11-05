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


# --- a .checkov.yaml suppression affects the resources its decision names --------

INV_SIGNAL = {"components": [
    {"component_id": "aws::cdn_distribution::website", "type": "cdn_distribution",
     "attributes": {"tf_type": "aws_cloudfront_distribution", "tf_name": "website",
                    "classification": {"internet_reachable": True}}},
    {"component_id": "aws::function::opa_compliance", "type": "function",
     "attributes": {"tf_type": "aws_lambda_function", "tf_name": "opa_compliance",
                    "classification": {"internet_reachable": False}}},
    {"component_id": "aws::function::silk_reeling", "type": "function",
     "attributes": {"tf_type": "aws_lambda_function", "tf_name": "silk_reeling",
                    "classification": {"internet_reachable": True}}},
]}


def _inventory(tmp_path):
    p = tmp_path / "ksi-signal.json"
    p.write_text(json.dumps(INV_SIGNAL))
    return vdr.load_inventory(p)


def test_a_decision_resource_resolves_only_when_it_names_one_component(tmp_path):
    inv = _inventory(tmp_path)
    # The register's aws-<type>[::<name>] form, matched to the one component of that type.
    assert vdr.resolve_decision_resource("aws-cloudfront-distribution", inv) == "aws::cdn_distribution::website"
    assert vdr.resolve_decision_resource("aws-lambda-function::silk-reeling", inv) == "aws::function::silk_reeling"
    # An exact inventory identifier.
    assert vdr.resolve_decision_resource("aws::function::opa_compliance", inv) == "aws::function::opa_compliance"
    # Two Lambdas and no name, or a name no component carries: never a guess.
    assert vdr.resolve_decision_resource("aws-lambda-function", inv) is None
    assert vdr.resolve_decision_resource("aws-lambda::compliance-monitor", inv) is None
    assert vdr.resolve_decision_resource(".checkov.yaml", inv) is None
    # Several components: the internet-reachable one, the conservative choice for IRV.
    assert vdr.resolve_decision_resources(
        ["aws::function::opa_compliance", "aws-lambda-function::silk-reeling"], inv) == "aws::function::silk_reeling"


def test_a_suppression_carries_its_decisions_resources():
    supp = {s["tool_id"]: s for s in vdr.ingest_suppressions(str(REPO / ".checkov.yaml"))}
    reg = {r["id"]: r for r in json.loads((REPO / "data" / "decisions.json").read_text())["decisions"]}
    for check, s in supp.items():
        assert s["resource"] == ".checkov.yaml"
        assert s["affected_resources"] == reg[s["decision_id"]]["applies_to"]["resources"], check


def test_a_suppressions_reachability_is_decided_from_the_resource_it_affects(tmp_path):
    inv = _inventory(tmp_path)
    sup = {"tracking_id": "CKV_AWS_68", "decision_id": "DEC-007", "source": "checkov-suppression",
           "tool_id": "CKV_AWS_68", "title": "CKV_AWS_68 suppressed", "resource": ".checkov.yaml",
           "affected_resources": ["aws-cloudfront-distribution"], "current_disposition": "risk-accepted",
           "pain": "N2", "is_kev": False, "explanation": "x"}
    unresolved = {**sup, "tracking_id": "CKV_AWS_117", "tool_id": "CKV_AWS_117",
                  "affected_resources": ["aws-lambda::compliance-monitor"]}
    report, _ = vdr.build_report([], [sup, unresolved], set(), {}, inventory=inv)
    by = {r["tracking_id"]: r for r in report["risk_accepted"]}
    assert by["CKV_AWS_68"]["component_id"] == "aws::cdn_distribution::website"
    assert by["CKV_AWS_68"]["irv_basis"] == "inventory" and by["CKV_AWS_68"]["internet_reachable"] is True
    assert by["CKV_AWS_68"]["affected_resources"] == ["aws-cloudfront-distribution"]
    # A resource that resolves to nothing stays unresolved, and fails safe.
    assert by["CKV_AWS_117"]["component_id"] is None and by["CKV_AWS_117"]["irv_basis"] == "unresolved"


# --- the runs a VDR build read, for the period reports (VER-RPT-PER) -----------------

def test_runtime_results_are_counted_only_from_a_verified_signal():
    ok = {"verified": True, "fresh": True, "emitted_at": "2026-11-05T17:56:05Z", "signal_id": "s-1",
          "divergence": "converged", "validations": [{"result": "pass"}, {"result": "fail"}, {"result": "pass"}]}
    out = vdr.runtime_verification_summary(ok)
    assert out["uri"].endswith("/.well-known/ksi-signal-runtime.json")
    assert (out["validations"], out["failed"], out["divergence"], out["signal_id"]) == (3, 1, "converged", "s-1")
    bad = vdr.runtime_verification_summary({"verified": False, "reason": "runtime signal signature does not verify",
                                            "validations": [{"result": "pass"}]})
    assert bad["verified"] is False and bad["validations"] is None and bad["failed"] is None
    assert "does not verify" in bad["reason"]


def test_the_dast_scan_time_is_the_reports_own(tmp_path):
    zap = tmp_path / "zap.json"
    zap.write_text(json.dumps({"@generated": "Thu, 5 Nov 2026 12:47:20", "created": "2026-11-05T12:47:20.585268837Z",
                               "site": [{"alerts": [{}, {}]}, {"alerts": [{}]}]}))
    assert vdr.dast_summary(str(zap)) == {"scanner": "zap", "status": "ok",
                                          "generated_at": "2026-11-05T12:47:20.585268+00:00", "alerts": 3}
    assert vdr.dast_summary(str(tmp_path / "absent.json"))["status"] == "missing"
    assert vdr.dast_summary(None) is None
