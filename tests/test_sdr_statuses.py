"""The SDR's FedRAMP-shaped statuses (scripts/build-sdr.py: build_fedramp, status_summary)."""

import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _frr  # noqa: E402
import _ksi_methods  # noqa: E402
import _rules  # noqa: E402

_spec = importlib.util.spec_from_file_location("build_sdr", REPO / "scripts" / "build-sdr.py")
assert _spec and _spec.loader
sdr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sdr)


def _ksi(status, passing, failing=()):
    methods = [{"method": "opa:versioning_disabled", "stage": "plan", "passed": True}][:passing]
    return {"status": status, "passing": passing, "failing": list(failing), "methods": methods}


@pytest.fixture(scope="module")
def inputs():
    ksis = {k: _ksi("Not Demonstrated", 0) for k in _ksi_methods.catalog_ksis()}
    ksis["KSI-RPL-ABO"] = _ksi("Implemented", 2) | {"methods": [
        {"method": "opa:versioning_disabled", "stage": "plan", "passed": True},
        {"method": "check:grype", "stage": "nightly", "passed": True}]}
    ksis["KSI-CNA-ULN"] = _ksi("Not Demonstrated", 1)
    ksis["KSI-SVC-SIN"] = _ksi("Not Demonstrated", 1, ["opa:weak_tls@live"])
    ksis["KSI-SVC-RUD"] = _ksi("Not Applicable", 0)
    return _frr.load(), _rules.applicable_provider_rules(), {"ksis": ksis, "short": [], "findings": []}, \
        _ksi_methods.load_methods()


def test_the_fedramp_section_validates_against_fedramps_schema(inputs):
    doc = sdr.build_fedramp(*inputs)
    assert len(doc["fedRampRequirements"]) == 154
    assert len(doc["keySecurityIndicators"]) == 46


def test_rule_statuses_map_to_fedramps_enum_and_keep_ours(inputs):
    items = {i["frrID"]: i for i in sdr.build_fedramp(*inputs)["fedRampRequirements"]}
    for rec in inputs[0]["records"]:
        item = items[rec["frr_id"]]
        assert item["statusDetail"]["status"] == rec["status"]
        if rec["status"] == "Not Applicable":
            assert "frrImplementationStatus" not in item
        elif rec["status"] == "Implemented":
            assert item["frrImplementationStatus"] == "Implemented"
        else:
            assert item["frrImplementationStatus"] == "Not Implemented"


def test_ksi_statuses_map_to_fedramps_enum(inputs):
    items = {i["ksiId"]: i for i in sdr.build_fedramp(*inputs)["keySecurityIndicators"]}
    assert items["KSI-RPL-ABO"]["ksiImplementationStatus"] == "Implemented"
    assert items["KSI-CNA-ULN"]["ksiImplementationStatus"] == "Partially Implemented"
    assert items["KSI-SVC-SIN"]["ksiImplementationStatus"] == "Not Implemented"
    assert "ksiImplementationStatus" not in items["KSI-SVC-RUD"]
    assert items["KSI-RPL-ABO"]["ksiTests"] == ["opa:versioning_disabled@plan", "check:grype@nightly"]
    assert [e["evidenceLocation"] for e in items["KSI-RPL-ABO"]["ksiEvidence"]] == [
        "https://samaydlette.com/.well-known/ksi-signal.json",
        "https://samaydlette.com/.well-known/vdr-status.json"]


def test_a_status_outside_fedramps_enum_fails_the_build(inputs, monkeypatch):
    monkeypatch.setitem(sdr.FRR_FEDRAMP_STATUS, "Not Demonstrated", "Coming soon")
    with pytest.raises(SystemExit, match="FedRAMP's schema"):
        sdr.build_fedramp(*inputs)


def test_the_summary_counts_every_rule_and_ksi(inputs):
    frr, applicable, ksi, _ = inputs
    s = sdr.status_summary(frr, applicable, ksi)
    assert s["rules"]["rules"] == 154
    assert s["ksis"]["total"] == 46
    assert s["ksis"]["by_status"]["Implemented"] == 1


def test_every_rule_not_followed_states_its_risk_and_acceptance(inputs):
    items = {i["frrID"]: i for i in sdr.build_fedramp(*inputs)["fedRampRequirements"]}
    for rec in inputs[0]["records"]:
        item = items[rec["frr_id"]]
        assert item["frrAssessment"] == [sdr.NO_INDEPENDENT_WORK]
        accepted = [v for v in item["frrValidation"] if "senior official" in v]
        if rec["status"] == "Implemented":
            assert not accepted and "Resulting risk" not in item["frrImplementation"][0]
        else:
            assert "Resulting risk" in item["frrImplementation"][0]
            assert accepted == ([f"Reason accepted by a senior official: {rec['approval']['by']}, {rec['approval']['on']}."]
                                if rec.get("approval") else ["The reason has not been accepted by a senior official."])


def test_the_readable_record_has_a_row_per_rule(inputs):
    doc = sdr.build_fedramp(*inputs)
    lines = sdr._rule_lines(doc)
    assert sum(1 for x in lines if x.startswith("| `")) == 154
