"""Fail-safe classification and agency scope (REQ-PAI-3, REQ-PAI-4, REQ-PAI-6; T44)."""
import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("vdr", REPO / "scripts" / "build-vdr-report.py")
vdr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vdr)
CFG, _ = vdr.load_pain_config()
TOTAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_failsafe_is_multi_agency_mission_critical():
    fs = vdr._FAILSAFE_CLASSIFICATION
    assert fs["agency_scope"] == "multi" and fs["mission_criticality"] == "high"


def test_t44_missing_scope_is_multi_agency():
    assert vdr.scope_flag({"data_sensitivity": "internal"}, CFG) == 1


def test_declared_single_scope_uses_the_governed_value():
    assert vdr.scope_flag({"agency_scope": "single"}, CFG) == CFG["multi_agency_default"]


def test_unresolved_debilitating_finding_can_reach_n5():
    f = {"cvss_vector": TOTAL, "_classification": vdr._FAILSAFE_CLASSIFICATION}
    assert vdr.assign_pain(f, {}, CFG) == "N5"


def test_methodology_publishes_the_deviation():
    assert "default decision tables" in vdr.PAIN_CLASSIFIER_DEVIATION
