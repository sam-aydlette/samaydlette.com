"""Finding -> inventory component resolution, IRV from the inventory, stable
tracking IDs (REQ-IRV-6, REQ-DLN-1, REQ-SRC-1; Appendix B T7)."""
import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "resolution"


def _vdr():
    spec = importlib.util.spec_from_file_location("vdr", REPO / "scripts" / "build-vdr-report.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


vdr = _vdr()
SIG = str(FIX / "ksi-signal.json")


def build(findings, suppressions=(), ledger=None):
    cfg, _ = vdr.load_pain_config()
    inv = vdr.load_inventory(SIG)
    report, blocking = vdr.build_report(list(findings), list(suppressions), set(), ledger or {},
                                        config=cfg, inventory=inv)
    return report


def one(f, **kw):
    r = build([{"tracking_id": "t", "source": "checkov", "tool_id": "CKV_X", "severity": "LOW", **f}], **kw)
    return r["findings"][0]


# --- IRV is the inventory's, not a name heuristic --------------------------------

def test_cognito_is_irv_from_the_inventory():
    f = one({"resource": "aws_cognito_user_pool.silk_reeling"})
    assert f["component_id"] == "aws::identity_provider::silk_reeling"
    assert f["internet_reachable"] is True and f["irv_basis"] == "inventory"


def test_app_lambda_is_irv_from_the_inventory():
    assert one({"resource": "aws_lambda_function.silk_reeling"})["internet_reachable"] is True


def test_internal_bucket_child_resource_is_nirv_from_the_inventory():
    f = one({"resource": "aws_s3_bucket_public_access_block.logs"})
    assert f["component_id"] == "aws::object_store::logs" and f["internet_reachable"] is False


# --- T7: an unresolved finding is IRV, fail-safe, flagged ---------------------------

def test_t7_unresolved_finding_is_irv_failsafe_and_flagged():
    r = build([{"tracking_id": "t", "source": "checkov", "tool_id": "CKV_X", "severity": "LOW",
                "resource": "aws_sqs_queue.nowhere"}])
    f = r["findings"][0]
    assert f["component_id"] is None and f["unresolved_component"] is True
    assert f["internet_reachable"] is True and f["irv_basis"] == "unresolved"
    assert r["summary"]["unresolved_components"] == 1


def test_unresolved_finding_gets_failsafe_pain_not_a_substring_match():
    cfg, _ = vdr.load_pain_config()
    inv = vdr.load_inventory(SIG)
    f = {"resource": "aws_sqs_queue.logs-ish", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    assert vdr.classification_for(f, inv, None) is vdr._FAILSAFE_CLASSIFICATION


def test_package_finding_is_irv_until_its_host_is_recorded():
    f = one({"source": "grype", "resource": "pkg:npm/left-pad@1.0.0", "cve": "CVE-0000-0010"})
    assert f["component_id"] == "npm::left-pad@1.0.0"
    assert f["internet_reachable"] is True and f["irv_basis"] == "package-host-unrecorded"


def test_observed_reachability_wins():
    f = one({"source": "zap", "resource": "aws_s3_bucket.logs", "internet_reachable": True})
    assert f["internet_reachable"] is True and f["irv_basis"] == "observed"


def test_suppression_record_without_a_resource_is_irv():
    r = build([], suppressions=[{"tracking_id": "CKV_AWS_117", "source": "checkov-suppression", "tool_id": "CKV_AWS_117",
                                  "resource": ".checkov.yaml", "pain": "N1", "is_kev": False}])
    s = r["risk_accepted"][0]
    assert s["internet_reachable"] is True and s["irv_basis"] == "unresolved"


def test_no_name_hint_table_remains():
    src = (REPO / "scripts" / "build-vdr-report.py").read_text()
    assert "INTERNET_REACHABLE_RESOURCE_HINTS" not in src
    assert all(set(v) == {"pain"} for v in vdr.SUPPRESSION_EVALUATION.values())


# --- Checkov resolution and stable IDs -------------------------------------------------

def _sarif(tmp_path, uri, line, snippet=None):
    region = {"startLine": line, "endLine": line + 2}
    if snippet is not None:
        region["snippet"] = {"text": snippet}
    doc = {"version": "2.1.0", "runs": [{"results": [{"ruleId": "CKV_AWS_18", "level": "warning",
            "message": {"text": "m"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}]}]}]}
    p = tmp_path / "c.sarif"
    p.write_text(json.dumps(doc))
    return str(p)


def test_checkov_address_from_snippet(tmp_path):
    f = vdr.ingest_checkov(_sarif(tmp_path, "infrastructure/x.tf", 10, 'resource "aws_s3_bucket" "logs" {\n  x = 1\n}'))[0]
    assert f["resource"] == "aws_s3_bucket.logs"
    assert f["tracking_id"] == "checkov-CKV_AWS_18-aws_s3_bucket.logs"
    assert f["legacy_tracking_id"] == "checkov-CKV_AWS_18-infrastructure/x.tf"


def test_checkov_address_from_file_and_line(tmp_path):
    uri = str((FIX / "main.tf.fixture").relative_to(REPO))
    f = vdr.ingest_checkov(_sarif(tmp_path, uri, 6))[0]
    assert f["resource"] == "aws_s3_bucket_public_access_block.logs"


def test_checkov_file_outside_repo_is_not_read(tmp_path):
    f = vdr.ingest_checkov(_sarif(tmp_path, "../../etc/passwd", 1))[0]
    assert f["resource"] == "../../etc/passwd" and f["tracking_id"].endswith("../../etc/passwd")


def test_tfsec_id_survives_a_line_move(tmp_path):
    def run(line):
        p = tmp_path / f"t{line}.json"
        p.write_text(json.dumps({"results": [{"rule_id": "AVD-AWS-0089", "resource": "aws_s3_bucket.logs",
                                              "severity": "LOW", "location": {"filename": "/w/x.tf", "start_line": line}}]}))
        return vdr.ingest_tfsec(str(p))[0]
    a, b = run(10), run(42)
    assert a["tracking_id"] == b["tracking_id"] == "tfsec-AVD-AWS-0089-aws_s3_bucket.logs"
    assert a["legacy_tracking_id"] != b["legacy_tracking_id"]


def test_clock_carries_over_from_the_legacy_id():
    ledger = {"checkov-CKV_X-infrastructure/x.tf": {"first_detected": "2026-01-01T00:00:00+00:00",
                                                   "first_evaluated": "2026-01-01T00:00:00+00:00"}}
    f = one({"resource": "aws_s3_bucket.logs", "tracking_id": "checkov-CKV_X-aws_s3_bucket.logs",
             "legacy_tracking_id": "checkov-CKV_X-infrastructure/x.tf"}, ledger=ledger)
    assert f["first_detected"] == "2026-01-01T00:00:00+00:00"


def test_no_terraform_outside_infrastructure():
    """The SAST scans (Checkov `directory: .`, tfsec at the repo root) read every
    .tf file in the repository, and their findings feed the published VDR. A
    Terraform test fixture would become production findings with no POA&M
    reference and fail reconciliation; fixtures use the .tf.fixture suffix."""
    stray = [p.relative_to(REPO) for p in REPO.rglob("*.tf")
             if not p.relative_to(REPO).parts[0] in ("infrastructure", ".venv", "node_modules")
             and ".terraform" not in p.parts]
    assert not stray, f"Terraform outside infrastructure/ is scanned into the VDR: {stray}"
