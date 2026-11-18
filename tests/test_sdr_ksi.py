"""The Security Decision Record's metadata (SDR-CSO-MTD) and per-KSI summaries
(SDR-CSX-KSI) in scripts/build-sdr.py.

SDR-CSO-MTD and SDR-CSX-KSI cite these tests.
"""
import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _fedramp_schema  # noqa: E402
import _frr  # noqa: E402
import _ksi_methods  # noqa: E402
import _rules  # noqa: E402

_spec = importlib.util.spec_from_file_location("build_sdr", REPO / "scripts" / "build-sdr.py")
assert _spec and _spec.loader
sdr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sdr)

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
RUN = "https://github.com/o/r/actions/runs/1"
METHODS = _ksi_methods.load_methods()
BY_KEY = {m["key"]: m for m in METHODS}
STATEMENTS = sdr.ksi_statements()

IMPLEMENTED = {"status": "Implemented", "passing": 2, "failing": [], "methods": [
    {"method": "check:checkov-tfsec", "stage": "deploy", "passed": True},
    {"method": "opa:versioning_disabled", "stage": "live", "passed": True}]}
SHORT = {"status": "Not Demonstrated", "passing": 1, "failing": ["check:grype@nightly"], "methods": [
    {"method": "check:grype", "stage": "deploy", "passed": True},
    {"method": "check:grype", "stage": "nightly", "passed": False}]}
NONE = {"status": "Not Demonstrated", "passing": 0, "failing": [], "methods": []}
CUT = {"status": "Not Applicable", "passing": 0, "failing": [], "methods": []}


def item(res, kid="KSI-CNA-IBP", cut=None):
    return sdr._ksi_item(kid, res, BY_KEY, STATEMENTS[kid], cut)


def text(i):
    return " ".join(i["ksiImplementation"] + i["ksiValidation"])


# --- SDR-CSO-MTD ---------------------------------------------------------------------

def test_the_metadata_carries_version_time_and_source_in_fedramps_fields_and_ours():
    md = sdr.sdr_metadata(NOW, "abc123", RUN)
    assert md["version"] == "abc123"
    assert md["lastUpdated"] == md["last_updated"] == NOW.isoformat()
    assert md["updateSource"] == md["source_of_update"]
    assert "abc123" in md["updateSource"] and RUN in md["updateSource"]
    assert "local build" in sdr.sdr_metadata(NOW, "abc123", None)["updateSource"]


def test_a_record_without_a_commit_fails_the_build():
    with pytest.raises(SystemExit, match="SDR-CSO-MTD"):
        sdr.sdr_metadata(NOW, None, RUN)


def test_the_metadata_is_validated_against_fedramps_schema():
    ksis = {k: NONE for k in _ksi_methods.catalog_ksis()}
    args = (_frr.load(), _rules.applicable_provider_rules(), {"ksis": ksis, "short": [], "findings": []}, METHODS)
    doc = sdr.build_fedramp(*args, metadata=sdr.sdr_metadata(NOW, "abc123", RUN))
    assert doc["metadata"]["version"] == "abc123"
    assert _fedramp_schema.validate(doc, "sdr") == []
    with pytest.raises(SystemExit, match="FedRAMP's schema"):
        sdr.build_fedramp(*args, metadata={"version": "abc123"})  # no lastUpdated or updateSource


# --- SDR-CSX-KSI ---------------------------------------------------------------------

def test_every_ksi_states_its_objective_from_the_catalog():
    i = item(IMPLEMENTED)
    assert i["ksiImplementation"][0] == f"Objective: {STATEMENTS['KSI-CNA-IBP']}"


def test_a_ksi_with_no_objective_fails_the_build():
    with pytest.raises(SystemExit, match="SDR-CSX-KSI"):
        sdr._ksi_item("KSI-CNA-IBP", IMPLEMENTED, BY_KEY, "", None)


def test_each_measure_says_what_it_does_and_how_often_it_runs():
    impl = item(IMPLEMENTED)["ksiImplementation"]
    assert f"Measure: {BY_KEY['checkov-tfsec']['measure'].rstrip('.')}. Runs {sdr.STAGE_CYCLE['deploy']}." in impl
    assert any("OPA rule versioning_disabled" in x and sdr.STAGE_CYCLE["live"] in x for x in impl)


def test_an_implemented_ksi_is_verified_and_validated_by_what_ran():
    v = item(IMPLEMENTED)["ksiValidation"]
    assert v[0].startswith("Verification: 2 automated methods pass")
    assert sdr.KSI_AUTOMATION in v
    assert "Validation: check:checkov-tfsec@deploy passed on the results published in " \
           "/.well-known/ksi-signal.json." in v


def test_a_failing_method_changes_the_summary():
    i = item(SHORT)
    assert "failing: check:grype@nightly" in text(i)
    assert "A measure in place is failing." in text(i) and "not built yet" not in text(i)
    assert any(x.startswith("Validation: check:grype@nightly FAILED") for x in i["ksiValidation"])
    assert not any(x.startswith("Verification: ") and "pass and none fail" in x for x in i["ksiValidation"])


def test_a_ksi_not_met_gives_the_reason_the_risk_and_that_the_reason_is_not_accepted():
    i = item(NONE)
    assert "The missing measures are not built yet." in text(i)
    assert sdr.NOT_FOLLOWED_RISK in text(i)
    assert f"Verification: {sdr.KSI_NOT_ACCEPTED}" in i["ksiValidation"]
    assert "Validation: none; no measure is in place." in i["ksiValidation"]


def test_a_not_applicable_ksi_gives_the_missing_trigger_and_who_accepted_it():
    cut = {"not_applicable": "No customer data.", "approval": {"by": "Sam Aydlette", "on": "2026-11-06"}}
    i = item(CUT, "KSI-SVC-RUD", cut)
    assert "Not Applicable: No customer data." in text(i)
    assert "Reason accepted by a senior official: Sam Aydlette, 2026-11-06." in i["ksiValidation"]
    unapproved = item(CUT, "KSI-SVC-RUD", {"not_applicable": "No customer data."})
    assert "The reason has not been accepted by a senior official." in unapproved["ksiValidation"]


def test_rule_records_no_longer_claim_the_same_verification_for_every_ksi():
    import json
    catalog = json.loads((REPO / "infrastructure" / "schemas" / "ksi-catalog.json").read_text())
    for r in sdr.build_records(catalog, {}):
        assert "verification" not in r and "validation" not in r


def test_the_markdown_shows_each_ksis_status_and_summary():
    md = sdr.render_markdown({
        "note": "n", "class": "C", "impact_level": "moderate", "ksi_signal_id": "s",
        "metadata": sdr.sdr_metadata(NOW, "abc123", RUN),
        "metrics": {"current": {"ksi_in_scope": 0, "controls_in_scope": 0, "signal_validations": 0,
                                "signal_failing": 0, "vdr_total": 0, "vdr_blocking": 0,
                                "vdr_accepted": 0, "vdr_kev": 0}, "daily_metric_data": []},
        "status_summary": {"rules": {"rules": 0, "by_status": {}, "awaiting_approval": 0},
                           "ksis": {"total": 1, "by_status": {}}},
        "keySecurityIndicators": [item(NONE)],
        "rule_records": [], "assessor_records": {"status": "no assessor record", "records": []}})
    assert "abc123" in md
    assert "| `KSI-CNA-IBP` | Not Demonstrated |" in md and sdr.KSI_NOT_ACCEPTED in md
