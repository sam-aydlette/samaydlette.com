# The user-facing authentication controls (IA-2*, IA-8, AC-7/11/12) must be
# dispositioned from the canonical inventory: implemented while the app's
# identity_provider component is deployed, reverting to the pre-app profiles
# when it is not. A hand-set flag cannot drift this way.

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

spec = importlib.util.spec_from_file_location("ssp", REPO / "scripts" / "build-oscal-ssp.py")
ssp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ssp)

APP_SIGNAL = {"components": [
    {"component_id": "aws::identity_provider::silk_reeling", "type": "identity_provider"},
    {"component_id": "aws::object_store::website", "type": "object_store"},
]}
NO_APP_SIGNAL = {"components": [
    {"component_id": "aws::object_store::website", "type": "object_store"},
]}


def test_app_present_marks_auth_controls_implemented():
    overrides = ssp._app_auth_overrides(APP_SIGNAL)
    for cid in ("ia-2", "ia-2.1", "ia-2.2", "ia-2.8", "ia-8", "ac-7", "ac-12"):
        status, origination, statement = ssp.resolve_control_profile(
            cid, cid.upper(), app_overrides=overrides)
        assert status == "implemented", (cid, status)
        assert origination == "sp-system"
    # Session lock stays honestly not-applicable for a browser SPA.
    status, _, _ = ssp.resolve_control_profile("ac-11", "AC-11", app_overrides=overrides)
    assert status == "not-applicable"


def test_app_absent_reverts_to_pre_app_dispositions():
    overrides = ssp._app_auth_overrides(NO_APP_SIGNAL)
    assert overrides == {}
    status, _, _ = ssp.resolve_control_profile("ia-2", "IA-2", app_overrides=overrides)
    assert status == "not-applicable"


def test_app_auth_precedes_hub_override():
    # ia-2 exists in the hub as not-applicable; the inventory-derived profile
    # must win while the app is deployed.
    assert "ia-2" in ssp.CONTROL_OVERRIDES
    overrides = ssp._app_auth_overrides(APP_SIGNAL)
    status, _, _ = ssp.resolve_control_profile("ia-2", "IA-2", app_overrides=overrides)
    assert status == "implemented"
