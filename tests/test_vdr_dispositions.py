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
    assert all(r["poam_ref"] is None for r in fps)  # FP carries no poam_ref


def test_fp_checks_excluded_from_risk_accepted():
    supp = vdr.ingest_suppressions(CHECKOV)
    ra_ids = {r["tracking_id"] for r in supp}
    assert not (FP_CKVS & ra_ids), f"FP checks leaked into risk-accepted: {FP_CKVS & ra_ids}"


def test_no_risk_accepted_suppression_has_null_poam_ref():
    # every remaining risk-accepted suppression must still map to a POA&M item
    supp = vdr.ingest_suppressions(CHECKOV)
    null_refs = [r["tracking_id"] for r in supp if r.get("poam_ref") is None]
    assert null_refs == [], f"risk-accepted suppressions with null poam_ref: {null_refs}"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
