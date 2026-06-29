# =============================================================================
# Task 8: false-positive reclassification in the VDR.
# The four checks moved to the docs/poam.md False Positives register
# (CKV_AWS_144/23/174/50) must be reported as false-positives, NOT as
# risk-accepted suppressions (which would carry a null poam_ref and overstate
# open risk). Verifies the partition against the real .checkov.yaml + poam.md.
# =============================================================================
import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FP_CKVS = {"CKV_AWS_144", "CKV_AWS_23", "CKV_AWS_174", "CKV_AWS_50"}


def _vdr():
    spec = importlib.util.spec_from_file_location("vdr", REPO / "scripts" / "build-vdr-report.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


vdr = _vdr()
CHECKOV = str(REPO / ".checkov.yaml")


def test_fp_register_loaded_from_poam():
    fp = vdr.false_positive_checks()
    assert FP_CKVS <= fp, f"FP register missing some of {FP_CKVS}: got {fp}"


def test_fp_checks_reported_as_false_positive_not_risk_accepted():
    fps = vdr.ingest_false_positives(CHECKOV)
    fp_ids = {r["tracking_id"] for r in fps}
    assert FP_CKVS <= fp_ids
    assert all(r["current_disposition"] == "false-positive" for r in fps if r["tracking_id"] in FP_CKVS)
    # Disposition model: a false positive is tracked as an OPEN POA&M item and
    # carries a poam_ref (it is not dropped to an untracked list).
    assert all(r["poam_ref"] for r in fps), [r["tracking_id"] for r in fps if not r["poam_ref"]]


def test_fp_checks_excluded_from_risk_accepted():
    supp = vdr.ingest_suppressions(CHECKOV)
    ra_ids = {r["tracking_id"] for r in supp}
    assert not (FP_CKVS & ra_ids), f"FP checks leaked into risk-accepted: {FP_CKVS & ra_ids}"


def test_no_risk_accepted_suppression_has_null_poam_ref():
    # every remaining risk-accepted suppression must still map to a POA&M item
    supp = vdr.ingest_suppressions(CHECKOV)
    null_refs = [r["tracking_id"] for r in supp if r.get("poam_ref") is None]
    assert null_refs == [], f"risk-accepted suppressions with null poam_ref: {null_refs}"


def test_classify_inline_and_tfsec_findings_map_to_poam():
    # The audit's orphaned-open findings now classify to their POA&M item.
    assert vdr.classify_finding("CKV2_AWS_56") == ("risk-accepted", "POAM-026")
    assert vdr.classify_finding("CKV_AWS_355") == ("false-positive", "POAM-027")
    assert vdr.classify_finding("CKV_AWS_356") == ("false-positive", "POAM-027")
    assert vdr.classify_finding("CKV2_AWS_62") == ("false-positive", "POAM-004")
    # tfsec AVD ids route through their Checkov equivalent.
    assert vdr.classify_finding("AVD-AWS-0089") == ("false-positive", "POAM-028")
    assert vdr.classify_finding("AVD-AWS-0132") == ("false-positive", "POAM-029")


def test_classify_unmapped_finding_is_open():
    # A genuinely-new finding has no documented suppression → stays open with no
    # poam_ref, which the reconciliation gate (invariant h) fails closed on.
    assert vdr.classify_finding("CKV_AWS_9999") == (None, None)


def test_build_report_gives_every_finding_a_poam_ref_or_open():
    # An inline-suppressed checkov finding and a tfsec finding must not surface
    # as orphaned-open: each carries its poam_ref and a non-open disposition.
    findings = [
        {"source": "checkov", "tool_id": "CKV_AWS_356", "tracking_id": "checkov-CKV_AWS_356-r1",
         "severity": "MEDIUM", "resource": "infrastructure/bootstrap/main.tf"},
        {"source": "tfsec", "tool_id": "AVD-AWS-0132", "tracking_id": "tfsec-AVD-AWS-0132-logs",
         "severity": "LOW", "resource": "aws_s3_bucket.logs"},
    ]
    report, blocking = vdr.build_report(findings, [], set(), {})
    assert blocking == []
    by_id = {f["tracking_id"]: f for f in report["findings"]}
    assert by_id["checkov-CKV_AWS_356-r1"]["poam_ref"] == "POAM-027"
    assert by_id["checkov-CKV_AWS_356-r1"]["final_disposition"] == "false-positive"
    assert by_id["tfsec-AVD-AWS-0132-logs"]["poam_ref"] == "POAM-029"
    assert report["summary"]["total_findings"] == 0  # none open
    assert report["summary"]["dispositioned_findings"] == 2


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
