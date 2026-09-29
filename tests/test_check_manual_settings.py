"""The hand-applied settings are compared with their expected values in code.

Pure-function tests over recorded API shapes; nothing here calls the network.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("cms", REPO / "scripts" / "check-manual-settings.py")
assert spec and spec.loader
cms = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cms)

ENVS = {"environments": [
    {"name": "prod", "protection_rules": [{"type": "required_reviewers", "reviewers": [{"type": "User"}]}]},
    {"name": "evidence-nightly", "protection_rules": [{"type": "branch_policy"}]},
]}
BRANCH = {"protected": True, "protection": {"required_status_checks": {
    "enforcement_level": "everyone", "contexts": sorted(cms.EXPECTED_REQUIRED_CHECKS)}}}


def test_github_settings_as_expected_are_ok():
    r = cms.evaluate_github(ENVS, ["main"], BRANCH)
    assert r["status"] == "ok" and r["facts"]["prod_required_reviewers"] == 1


def test_github_drift_is_named():
    envs = {"environments": [{"name": "prod", "protection_rules": []}, {"name": "evidence-nightly"}]}
    branch = {"protected": True, "protection": {"required_status_checks": {"enforcement_level": "non_admins", "contexts": ["Security Scan"]}}}
    r = cms.evaluate_github(envs, ["main", "feature/*"], branch)
    assert r["status"] == "attention"
    for phrase in ("no required reviewer", "not only main", "does not require", "administrators"):
        assert phrase in r["detail"]


def test_github_results_carry_no_reviewer_identity():
    envs = {"environments": [{"name": "prod", "protection_rules": [
        {"type": "required_reviewers", "reviewers": [{"type": "User", "reviewer": {"login": "someone"}}]}]},
        {"name": "evidence-nightly"}]}
    assert "someone" not in json.dumps(cms.evaluate_github(envs, ["main"], BRANCH))


def test_dnssec_needs_every_resolver_to_authenticate_and_see_the_ds():
    good = {"Status": 0, "AD": True, "Answer": [{"type": 43}]}
    assert cms.evaluate_dnssec({"A": good, "B": good})["status"] == "ok"
    assert cms.evaluate_dnssec({"A": good, "B": {"Status": 0, "AD": False, "Answer": []}})["status"] == "attention"
    assert cms.evaluate_dnssec({"A": {"Status": 2, "AD": False}})["status"] == "attention"


def test_sns_needs_a_confirmed_subscription_and_none_pending():
    assert cms.evaluate_sns({"SubscriptionsConfirmed": "1", "SubscriptionsPending": "0"})["status"] == "ok"
    assert cms.evaluate_sns({"SubscriptionsConfirmed": "0", "SubscriptionsPending": "1"})["status"] == "attention"
    assert cms.evaluate_sns({"SubscriptionsConfirmed": "1", "SubscriptionsPending": "1"})["status"] == "attention"


def test_unreadable_sources_are_not_observed(monkeypatch):
    def boom(*a, **k):
        raise OSError("offline")
    monkeypatch.setattr(cms, "_get_json", boom)
    assert cms.check_github()["status"] == "not_observed"
    assert cms.check_dnssec()["status"] == "not_observed"
