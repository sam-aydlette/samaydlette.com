# =============================================================================
# Task 1 keystone: reconciliation gate unit tests.
# One test per invariant (a-f), driven by a hermetic clean fixture set that is
# then mutated to trigger each violation. Also asserts the committed broken
# fixture under tests/fixtures/broken/ fails the gate (the Done-check).
# =============================================================================
import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("reconcile", REPO / "scripts" / "reconcile.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


rc = _load()

SIGNAL_ID = "11111111-1111-4111-8111-111111111111"
COMMIT = "abc123"
ARN_LAMBDA = "arn:aws:lambda:us-east-2:975050324277:function:app"
ARN_BUCKET = "arn:aws:s3:::samaydlette.com"


def clean_set():
    """A minimal artifact set that satisfies every invariant."""
    signal = {
        "signal_id": SIGNAL_ID,
        "emitted_at": "2026-06-13T15:00:00Z",
        "categorization": {"impact_level": "Moderate"},
        "provenance": {"source": {"commit": COMMIT}},
        "components": [
            {"component_id": "aws::function::app", "type": "function",
             "resource_type": "AWS::Lambda::Function", "native_id": ARN_LAMBDA},
            {"component_id": "aws::object_store::website", "type": "object_store",
             "resource_type": "AWS::S3::Bucket", "native_id": ARN_BUCKET},
        ],
    }
    ssp = {"system-security-plan": {
        "metadata": {"props": [{"name": "ksi-signal-source", "value": SIGNAL_ID}]},
        "system-characteristics": {"security-sensitivity-level": "moderate"},
        "system-implementation": {"components": [{"type": "this-system", "title": "whole system"}]},
    }}
    poam = {"plan-of-action-and-milestones": {
        "metadata": {"props": [
            {"name": "impact-level", "value": "moderate"},
            {"name": "ksi-signal-id", "value": SIGNAL_ID},
        ]},
        "poam-items": [{"props": [{"name": "poam-id", "value": "POAM-007"}]}],
    }}
    vdr = {"impact_level": "Moderate", "class": "C", "ksi_signal_id": SIGNAL_ID,
           "risk_accepted": [{"tracking_id": "CKV_AWS_68", "poam_ref": "POAM-007"}]}
    dashboard = "<h3>FedRAMP Rev 5 Moderate</h3>"
    checkov = "skip-check:\n  - CKV_AWS_68\n"
    ckv_to_poam = {"CKV_AWS_68": "POAM-007"}
    poam_md = "| POAM-007 | SC-7 | CloudFront WAF not attached | Checkov | CKV_AWS_68 | asset | N2 | Moderate | Low | Yes | Open (risk-accepted) |"
    fps = set()
    return dict(signal=signal, ssp=ssp, poam=poam, vdr=vdr, dashboard_html=dashboard,
                checkov_text=checkov, ckv_to_poam=ckv_to_poam, poam_md_text=poam_md,
                false_positive_ckvs=fps)


def test_clean_set_passes_all():
    v = rc.run_all(**clean_set(), live_arns={ARN_LAMBDA, ARN_BUCKET}, expected_commit=COMMIT)
    assert v == [], v


def test_a_completeness_catches_missing_live_resource():
    s = clean_set()
    extra = "arn:aws:secretsmanager:us-east-2:975050324277:secret:zzz"
    v = rc.check_a_completeness(s["signal"], {ARN_LAMBDA, ARN_BUCKET, extra})
    assert any("not in inventory" in x and extra in x for x in v)


def test_b_referential_catches_unresolved_poam_asset():
    s = clean_set()
    s["poam"]["plan-of-action-and-milestones"]["poam-items"] = [
        {"props": [{"name": "aws-arn", "value": "arn:aws:lambda:us-east-2:975050324277:function:ghost"}]}
    ]
    v = rc.check_b_referential(s["signal"], s["ssp"], s["poam"])
    assert any("does not resolve" in x for x in v)


def test_c_uncategorized_suppression_fails():
    s = clean_set()
    s["checkov_text"] = "skip-check:\n  - CKV_AWS_68\n  - CKV_AWS_999\n"  # 999 unmapped
    v = rc.check_c_suppressions(rc.parse_checkov_skips(s["checkov_text"]),
                                s["ckv_to_poam"], s["poam_md_text"], s["vdr"],
                                s["false_positive_ckvs"])
    assert any("CKV_AWS_999" in x and "uncategorized" in x for x in v)


def test_c_risk_accepted_needs_vdr_poam_ref():
    s = clean_set()
    s["vdr"]["risk_accepted"] = []  # POAM-007 no longer has a poam_ref in the VDR
    v = rc.check_c_suppressions(rc.parse_checkov_skips(s["checkov_text"]),
                                s["ckv_to_poam"], s["poam_md_text"], s["vdr"],
                                s["false_positive_ckvs"])
    assert any("no non-null poam_ref" in x for x in v)


def test_d_impact_catches_low_ssp():
    s = clean_set()
    s["ssp"]["system-security-plan"]["system-characteristics"]["security-sensitivity-level"] = "low"
    v = rc.check_d_impact(s["signal"], s["ssp"], s["poam"], s["vdr"], s["dashboard_html"])
    assert any("ssp" in x and "low" in x for x in v)


def test_d_impact_catches_low_dashboard():
    s = clean_set()
    s["dashboard_html"] = "<h3>FIPS-199 Low</h3>"
    v = rc.check_d_impact(s["signal"], s["ssp"], s["poam"], s["vdr"], s["dashboard_html"])
    assert any("dashboard" in x for x in v)


def test_e_binding_catches_mismatched_signal_id():
    s = clean_set()
    s["vdr"]["ksi_signal_id"] = "99999999-9999-4999-8999-999999999999"
    v = rc.check_e_binding(s["signal"], s["ssp"], s["poam"], s["vdr"])
    assert any("vdr" in x and "!=" in x for x in v)


def test_f_freshness_catches_stale_commit():
    s = clean_set()
    v = rc.check_f_freshness(s["signal"], s["ssp"], s["poam"], s["vdr"], expected_commit="different")
    assert any("commit" in x for x in v)


def test_g_poam_parity_catches_md_item_missing_from_oscal():
    s = clean_set()
    # docs/poam.md tracks a formal item (table row) the OSCAL POA&M omits — the
    # exact drift that hid POAM-019..025 from the published artifact.
    s["poam_md_text"] = "| POAM-042 | SC-7 | Weakness | Checkov | CKV_X | asset | N1 | Low | - | No | Risk-accepted |"
    v = rc.check_g_poam_parity(s["poam"], s["poam_md_text"])
    assert any("POAM-042" in x and "absent from the OSCAL POA&M" in x for x in v)


def test_g_poam_parity_catches_oscal_item_not_in_md():
    s = clean_set()
    s["poam"]["plan-of-action-and-milestones"]["poam-items"] = [
        {"props": [{"name": "poam-id", "value": "POAM-099"}]}
    ]
    v = rc.check_g_poam_parity(s["poam"], s["poam_md_text"])
    assert any("POAM-099" in x and "not a formal item" in x for x in v)


def test_g_poam_parity_ignores_prose_cross_references():
    s = clean_set()
    # A prose "see POAM-016" reference is NOT a formal item; it must not be required.
    s["poam"]["plan-of-action-and-milestones"]["poam-items"] = []
    s["poam_md_text"] = "Single S3 origin; multi-origin would need multi-region storage (see POAM-016)."
    assert rc.check_g_poam_parity(s["poam"], s["poam_md_text"]) == []


def test_h_finding_without_poam_ref_fails():
    # An open finding with no poam_ref is exactly the audit's failure mode.
    s = clean_set()
    s["vdr"]["findings"] = [{"tracking_id": "checkov-CKV_AWS_356-r1", "current_disposition": "open"}]
    v = rc.check_h_finding_coverage(s["vdr"], s["poam"])
    assert any("checkov-CKV_AWS_356-r1" in x and "no poam_ref" in x for x in v)


def test_h_finding_with_unknown_poam_ref_fails():
    s = clean_set()
    s["vdr"]["false_positives"] = [{"tracking_id": "CKV_X", "poam_ref": "POAM-404"}]
    v = rc.check_h_finding_coverage(s["vdr"], s["poam"])
    assert any("POAM-404" in x and "not a POA&M item" in x for x in v)


def test_h_passes_when_every_finding_resolves():
    s = clean_set()
    s["vdr"]["false_positives"] = [{"tracking_id": "CKV_AWS_68", "poam_ref": "POAM-007"}]
    assert rc.check_h_finding_coverage(s["vdr"], s["poam"]) == []


def test_g_poam_parity_passes_when_sets_match():
    s = clean_set()
    s["poam_md_text"] = "### POAM-001 — A weakness\n| POAM-007 | SC-7 | ... |"
    s["poam"]["plan-of-action-and-milestones"]["poam-items"] = [
        {"props": [{"name": "poam-id", "value": "POAM-001"}]},
        {"props": [{"name": "poam-id", "value": "POAM-007"}]},
    ]
    assert rc.check_g_poam_parity(s["poam"], s["poam_md_text"]) == []


def test_committed_broken_fixture_fails_via_main(monkeypatch, capsys):
    """The Done-check: the gate exits non-zero on the committed broken fixture."""
    import sys
    broken = REPO / "tests" / "fixtures" / "broken"
    if not broken.exists():
        pytest.skip("broken fixture dir not present")
    monkeypatch.setattr(sys, "argv", ["reconcile.py", "--artifacts-dir", str(broken),
                                       "--dashboard", str(broken / "viewer.html"),
                                       "--checkov", str(broken / ".checkov.yaml"), "--poam-md", str(broken / "poam.md")])
    assert rc.main() == 1


def test_committed_clean_fixture_passes_via_main(monkeypatch):
    import sys
    clean = REPO / "tests" / "fixtures" / "clean"
    if not clean.exists():
        pytest.skip("clean fixture dir not present")
    # Hermetic: reconcile's --expect-commit defaults to $GITHUB_SHA, which is set
    # in CI and would make freshness invariant (f) compare the fixture's pinned
    # commit against the live run's SHA and fail. The fixture is not pinned to any
    # particular run, so drop the ambient value (matches local behaviour).
    monkeypatch.delenv("GITHUB_SHA", raising=False)
    monkeypatch.setattr(sys, "argv", ["reconcile.py", "--artifacts-dir", str(clean),
                                       "--dashboard", str(clean / "viewer.html"),
                                       "--live-fixture", str(clean / "live-arns.json"),
                                       "--checkov", str(clean / ".checkov.yaml"), "--poam-md", str(clean / "poam.md")])
    assert rc.main() == 0


def test_state_backend_bucket_excluded_from_live_sweep():
    # The Terraform state bucket is management-plane (bootstrap-managed) and must
    # be excluded from the (a) live completeness sweep; real system buckets are not.
    assert rc.is_state_backend_bucket("samaydlette-com-tfstate") is True
    assert rc.is_state_backend_bucket("samaydlette-com-logs") is False
    assert rc.is_state_backend_bucket("samaydlette.com") is False
    assert rc.is_state_backend_bucket("") is False


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
