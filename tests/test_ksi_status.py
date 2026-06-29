# =============================================================================
# WS4: per-KSI status block in the KSI signal.
# Every in-scope (Moderate) catalog indicator is emitted with a status derived
# consistently from the validations/components in its family's domain, so the
# SSP's named KSIs are machine-traceable to a live result.
# =============================================================================
import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("bks", REPO / "scripts" / "build-ksi-signal.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


bks = _load()

CATALOG = {
    "KSI": {
        "MLA": {"id": "KSI-MLA", "name": "Monitoring", "indicators": [
            {"id": "KSI-MLA-LET", "name": "Logging Everything", "impact": {"low": True, "moderate": True},
             "controls": [{"control_id": "au-2"}]},
        ]},
        "IAM": {"id": "KSI-IAM", "name": "Identity", "indicators": [
            {"id": "KSI-IAM-ELP", "name": "Least Privilege", "impact": {"low": True, "moderate": True},
             "controls": [{"control_id": "ac-6"}]},
            {"id": "KSI-IAM-LOW", "name": "Low only", "impact": {"low": True, "moderate": False},
             "controls": [{"control_id": "ac-2"}]},
        ]},
        "CED": {"id": "KSI-CED", "name": "Education", "indicators": [
            {"id": "KSI-CED-RAT", "name": "Training", "impact": {"low": True, "moderate": True},
             "controls": [{"control_id": "at-2"}]},
        ]},
    }
}

COMPONENTS = [
    {"component_id": "aws::log_group::lambda", "type": "log_group"},
    {"component_id": "aws::iam_role::deploy", "type": "iam_role"},
]


def _ksis(validations):
    return {k["id"]: k for k in bks.build_ksi_statuses(CATALOG, COMPONENTS, validations)}


def test_only_moderate_in_scope_emitted():
    ksis = _ksis([])
    assert "KSI-IAM-LOW" not in ksis           # moderate=False → out of scope
    assert {"KSI-MLA-LET", "KSI-IAM-ELP", "KSI-CED-RAT"} <= set(ksis)


def test_passing_validation_yields_pass_with_evidence():
    vals = [{"validation_id": "v-1", "result": "pass", "component_refs": ["aws::log_group::lambda"]}]
    k = _ksis(vals)["KSI-MLA-LET"]
    assert k["status"] == "pass"
    assert k["method"] == "policy-validation"
    assert "v-1" in k["evidence"]["validation_ids"]
    assert k["controls"] == ["au-2"]


def test_failing_validation_in_domain_yields_fail():
    vals = [{"validation_id": "v-9", "result": "fail", "component_refs": ["aws::log_group::lambda"]}]
    k = _ksis(vals)["KSI-MLA-LET"]
    assert k["status"] == "fail"
    assert k["evidence"]["failed_validation_ids"] == ["v-9"]


def test_component_domain_without_validation_is_inventory_attestation():
    k = _ksis([])["KSI-IAM-ELP"]  # IAM components exist, no terraform.compliance check fires
    assert k["status"] == "pass"
    assert k["method"] == "inventory-attestation"
    assert "aws::iam_role::deploy" in k["evidence"]["component_refs"]


def test_documentation_family_has_no_component_evidence():
    k = _ksis([])["KSI-CED-RAT"]
    assert k["method"] == "documentation"
    assert k["evidence"]["component_refs"] == []


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
