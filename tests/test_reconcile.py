# =============================================================================
# Task 1 keystone: reconciliation gate unit tests.
# One test per invariant, driven by a hermetic clean fixture set that is
# then mutated to trigger each violation. Also asserts the committed broken
# fixture under tests/fixtures/broken/ fails the gate (the Done-check).
# =============================================================================
import copy
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
# The AWS-documentation example account. Nothing here validates or asserts the
# value, so it stays synthetic rather than naming the real one in a public repo.
ACCOUNT = "123456789012"
ARN_LAMBDA = f"arn:aws:lambda:us-east-2:{ACCOUNT}:function:app"
ARN_BUCKET = "arn:aws:s3:::samaydlette.com"

REGISTER = {"schema": "decisions/1", "decisions": [
    {"id": "DEC-005", "former_id": "POAM-005", "title": "fixed", "status": "closed", "disposition": "remediated",
     "justification": "fixed", "applies_to": {"check_ids": [], "vuln_ids": [], "resources": []}},
    {"id": "DEC-007", "former_id": "POAM-007", "title": "CloudFront WAF not attached", "status": "in-force",
     "disposition": "risk-accepted", "justification": "SC-7 met via managed interfaces", "decided_by": "Operator",
     "decided_on": "2026-01-01", "review_by": "2027-01-01",
     "applies_to": {"check_ids": ["CKV_AWS_68"], "vuln_ids": [], "resources": []}},
]}


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
    vdr = {"impact_level": "Moderate", "class": "C", "ksi_signal_id": SIGNAL_ID,
           "risk_accepted": [{"tracking_id": "CKV_AWS_68", "decision_id": "DEC-007"}]}
    dashboard = "<h3>FedRAMP Rev 5 Moderate</h3>"
    checkov = "skip-check:\n  - CKV_AWS_68\n"
    return dict(signal=signal, ssp=ssp, vdr=vdr, dashboard_html=dashboard, checkov_text=checkov,
                register=copy.deepcopy(REGISTER))


def _record(s, rid):
    return next(r for r in s["register"]["decisions"] if r["id"] == rid)


def test_clean_set_passes_all():
    v = rc.run_all(**clean_set(), live_arns={ARN_LAMBDA, ARN_BUCKET}, expected_commit=COMMIT)
    assert v == [], v


def test_a_completeness_catches_missing_live_resource():
    s = clean_set()
    extra = f"arn:aws:secretsmanager:us-east-2:{ACCOUNT}:secret:zzz"
    v = rc.check_a_completeness(s["signal"], {ARN_LAMBDA, ARN_BUCKET, extra})
    assert any("not in inventory" in x and extra in x for x in v)


def test_a_completeness_rejects_arn_that_extends_an_inventoried_one():
    """The hole the prefix match opened: a live resource whose ARN merely EXTENDS
    an inventoried one is a different resource and must still fail the sweep.

    Log groups and per-purpose buckets are where this bites — '<name>-archive'
    next to an inventoried '<name>'. Under the old prefix comparison this passed
    deny-by-default silently, which is the one thing invariant (a) exists to stop.
    """
    s = clean_set()
    extends = ARN_BUCKET + "-archive"
    v = rc.check_a_completeness(s["signal"], {ARN_LAMBDA, ARN_BUCKET, extends})
    assert any(extends in x for x in v), v


def test_a_completeness_still_tolerates_log_group_wildcard():
    """The ':*' suffix is the one ARN-form difference that is genuinely the same
    resource, and the normalization that replaced the prefix match must keep it."""
    base = "arn:aws:logs:us-east-2:%s:log-group:/aws/lambda/app" % ACCOUNT
    signal = {"components": [{"component_id": "lg", "native_id": base}]}
    assert rc.check_a_completeness(signal, {base + ":*"}) == []


def test_b_referential_catches_unresolved_ssp_component():
    s = clean_set()
    s["ssp"]["system-security-plan"]["system-implementation"]["components"].append(
        {"type": "service", "title": "ghost",
         "props": [{"name": "aws-arn", "value": f"arn:aws:lambda:us-east-2:{ACCOUNT}:function:ghost"}]})
    v = rc.check_b_referential(s["signal"], s["ssp"])
    assert any("does not resolve" in x for x in v)


def test_c_uncategorized_suppression_fails():
    s = clean_set()
    s["checkov_text"] = "skip-check:\n  - CKV_AWS_68\n  - CKV_AWS_999\n"  # 999 has no record
    v = rc.check_c_suppressions(rc.parse_checkov_skips(s["checkov_text"]), s["register"], s["vdr"])
    assert any("CKV_AWS_999" in x and "uncategorized" in x for x in v)


def test_c_a_suppression_whose_record_is_closed_is_uncategorized():
    s = clean_set()
    rec = _record(s, "DEC-007")
    rec.update(status="closed", disposition="remediated")
    v = rc.check_c_suppressions(rc.parse_checkov_skips(s["checkov_text"]), s["register"], s["vdr"])
    assert any("CKV_AWS_68" in x and "uncategorized" in x for x in v)


def test_c_risk_accepted_needs_vdr_decision_id():
    s = clean_set()
    s["vdr"]["risk_accepted"] = []  # DEC-007 no longer has a decision_id in the VDR
    v = rc.check_c_suppressions(rc.parse_checkov_skips(s["checkov_text"]), s["register"], s["vdr"])
    assert any("no non-null decision_id" in x for x in v)


def test_d_impact_catches_low_ssp():
    s = clean_set()
    s["ssp"]["system-security-plan"]["system-characteristics"]["security-sensitivity-level"] = "low"
    v = rc.check_d_impact(s["signal"], s["ssp"], s["vdr"], s["dashboard_html"])
    assert any("ssp" in x and "low" in x for x in v)


def test_d_impact_reads_the_trust_center_page():
    s = clean_set()
    s["dashboard_html"] = (REPO / "website" / "trust" / "index.html").read_text()
    assert rc.check_d_impact(s["signal"], s["ssp"], s["vdr"], s["dashboard_html"]) == []


def test_d_impact_catches_low_dashboard():
    s = clean_set()
    s["dashboard_html"] = "<h3>FIPS-199 Low</h3>"
    v = rc.check_d_impact(s["signal"], s["ssp"], s["vdr"], s["dashboard_html"])
    assert any("dashboard" in x for x in v)


def test_e_binding_catches_mismatched_signal_id():
    s = clean_set()
    s["vdr"]["ksi_signal_id"] = "99999999-9999-4999-8999-999999999999"
    v = rc.check_e_binding(s["signal"], s["ssp"], s["vdr"])
    assert any("vdr" in x and "!=" in x for x in v)


def test_f_freshness_catches_stale_commit():
    s = clean_set()
    v = rc.check_f_freshness(s["signal"], s["vdr"], expected_commit="different")
    assert any("commit" in x for x in v)


def test_h_finding_without_decision_id_fails():
    # An open finding with no decision_id is exactly the audit's failure mode.
    s = clean_set()
    s["vdr"]["findings"] = [{"tracking_id": "checkov-CKV_AWS_356-r1", "current_disposition": "open"}]
    v = rc.check_h_finding_coverage(s["vdr"], s["register"])
    assert any("checkov-CKV_AWS_356-r1" in x and "no decision_id" in x for x in v)


def test_h_finding_with_unknown_decision_id_fails():
    s = clean_set()
    s["vdr"]["false_positives"] = [{"tracking_id": "CKV_X", "decision_id": "DEC-404"}]
    v = rc.check_h_finding_coverage(s["vdr"], s["register"])
    assert any("DEC-404" in x and "not in the decision register" in x for x in v)


def test_h_finding_resolving_to_a_closed_decision_fails():
    # A remediated record is history, not a decision in force: a finding that
    # still cites it is an undecided finding.
    s = clean_set()
    s["vdr"]["findings"] = [{"tracking_id": "f1", "current_disposition": "false-positive", "decision_id": "DEC-005"}]
    v = rc.check_h_finding_coverage(s["vdr"], s["register"])
    assert any("f1" in x and "a closed decision" in x for x in v)


def test_h_a_former_poam_id_is_not_a_decision_id():
    # Findings carry the record's own ID; the former ID only resolves narrative text (j).
    s = clean_set()
    s["vdr"]["findings"] = [{"tracking_id": "f1", "current_disposition": "risk-accepted", "decision_id": "POAM-007"}]
    assert rc.check_h_finding_coverage(s["vdr"], s["register"])


def test_h_passes_when_every_finding_resolves():
    s = clean_set()
    s["vdr"]["false_positives"] = [{"tracking_id": "CKV_AWS_68", "decision_id": "DEC-007"}]
    assert rc.check_h_finding_coverage(s["vdr"], s["register"]) == []


def test_g_is_retired_with_the_poam_it_kept_in_parity():
    # (g) compared two copies of the POA&M; the register is one copy. It leaves
    # the runner, the titles and the gate-mode register together.
    assert "g" not in rc.INVARIANT_TITLES and not hasattr(rc, "check_g_poam_parity")
    import json
    modes = json.loads((REPO / "infrastructure" / "schemas" / "gate-modes.json").read_text())
    assert "reconcile.g" not in json.dumps(modes)


def test_committed_broken_fixture_fails_via_main(monkeypatch, capsys):
    """The Done-check: the gate exits non-zero on the committed broken fixture."""
    import sys
    broken = REPO / "tests" / "fixtures" / "broken"
    if not broken.exists():
        pytest.skip("broken fixture dir not present")
    monkeypatch.setattr(sys, "argv", ["reconcile.py", "--artifacts-dir", str(broken),
                                       "--dashboard", str(broken / "viewer.html"),
                                       "--checkov", str(broken / ".checkov.yaml"),
                                       "--decisions", str(broken / "decisions.json")])
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
                                       "--checkov", str(clean / ".checkov.yaml"),
                                       "--decisions", str(clean / "decisions.json")])
    assert rc.main() == 0


def test_state_backend_bucket_excluded_from_live_sweep():
    # The Terraform state bucket is management-plane (bootstrap-managed) and must
    # be excluded from the (a) live completeness sweep; real system buckets are not.
    assert rc.is_state_backend_bucket("samaydlette-com-tfstate") is True
    assert rc.is_state_backend_bucket("samaydlette-com-logs") is False
    assert rc.is_state_backend_bucket("samaydlette.com") is False
    assert rc.is_state_backend_bucket("") is False


def test_j_unknown_decision_reference_fails():
    s = clean_set()
    s["signal"]["components"][0]["baseline_configuration"] = "hardened per POAM-999"
    v = rc.check_j_decision_id_validity(s["signal"], s["ssp"], s["vdr"], s["register"])
    assert any("POAM-999" in x and "(j)" in x for x in v)


def test_j_retired_id_is_referenceable():
    s = clean_set()
    s["ssp"]["system-security-plan"]["metadata"]["remarks"] = "multi-region declined; see POAM-016 (retired)"
    v = rc.check_j_decision_id_validity(s["signal"], s["ssp"], s["vdr"], s["register"])
    assert v == [], v


def test_j_register_items_and_valid_refs_pass():
    s = clean_set()
    s["signal"]["components"][0]["baseline_configuration"] = "throttled (POAM-007; now DEC-007)"
    v = rc.check_j_decision_id_validity(s["signal"], s["ssp"], s["vdr"], s["register"])
    assert v == [], v


def test_j_unknown_dec_reference_fails():
    s = clean_set()
    s["vdr"]["note"] = "see DEC-999"
    v = rc.check_j_decision_id_validity(s["signal"], s["ssp"], s["vdr"], s["register"])
    assert any("DEC-999" in x for x in v)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
