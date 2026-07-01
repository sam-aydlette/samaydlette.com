"""PR-D Part 2: reconcile invariant (i) — live AWS classification tags must equal
the inventory's projected classification (attributes.classification)."""
import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("rc", REPO / "scripts" / "reconcile.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


rc = _load()

# One managed component with a full classification block and a live ARN.
_CLS = {
    "data_sensitivity": "public", "mission_criticality": "moderate",
    "internet_reachable": False, "agency_scope": "single",
    "owner": "platform-operator", "archetype": "security-tooling",
}
_ARN = "arn:aws:lambda:us-east-2:1:function:samaydlette-com-opa-compliance"
_SIGNAL = {"components": [
    {"component_id": "aws::function::opa_compliance", "native_id": _ARN,
     "attributes": {"classification": _CLS}},
]}
# Live tags that exactly match the projected classification (note bool -> string,
# owner -> OwnerRole).
_MATCHING_TAGS = {_ARN: {
    "DataSensitivity": "public", "MissionCriticality": "moderate",
    "InternetReachable": "false", "AgencyScope": "single",
    "OwnerRole": "platform-operator", "Archetype": "security-tooling",
}}


def test_matching_tags_pass():
    assert rc.check_i_classification_tags(_SIGNAL, _MATCHING_TAGS) == []


def test_drifted_value_fails():
    # BROKEN FIXTURE: the live Archetype tag drifted from the inventory.
    drifted = {_ARN: dict(_MATCHING_TAGS[_ARN], Archetype="app-tier")}
    v = rc.check_i_classification_tags(_SIGNAL, drifted)
    assert len(v) == 1 and "Archetype" in v[0]


def test_internet_reachable_bool_maps_to_string():
    # inventory False must equal live "false"; a live "true" is drift.
    bad = {_ARN: dict(_MATCHING_TAGS[_ARN], InternetReachable="true")}
    v = rc.check_i_classification_tags(_SIGNAL, bad)
    assert len(v) == 1 and "InternetReachable" in v[0]


def test_owner_maps_to_ownerrole():
    bad = {_ARN: dict(_MATCHING_TAGS[_ARN], OwnerRole="someone-else")}
    v = rc.check_i_classification_tags(_SIGNAL, bad)
    assert len(v) == 1 and "OwnerRole" in v[0]


def test_component_without_live_tags_is_skipped():
    # A component whose ARN is not among the live tagged resources (bootstrap /
    # non-cloud) is out of scope — no false positive.
    assert rc.check_i_classification_tags(_SIGNAL, {}) == []


def test_component_tagged_but_without_our_keys_is_skipped():
    # A live resource that carries only unrelated tags is not reconciled.
    unrelated = {_ARN: {"Name": "x", "Environment": "prod"}}
    assert rc.check_i_classification_tags(_SIGNAL, unrelated) == []


def test_arn_trailing_glob_is_tolerated():
    # Log-group ARNs sometimes carry a trailing ':*'; matching must tolerate it.
    lg_arn = "arn:aws:logs:us-east-2:1:log-group:/aws/lambda/samaydlette-com-opa-compliance"
    sig = {"components": [{"component_id": "aws::log_group::opa_compliance",
                          "native_id": lg_arn + ":*",
                          "attributes": {"classification": _CLS}}]}
    tags = {lg_arn: _MATCHING_TAGS[_ARN]}
    assert rc.check_i_classification_tags(sig, tags) == []
