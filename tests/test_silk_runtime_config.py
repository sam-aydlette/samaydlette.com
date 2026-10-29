"""The Silk Reeling runtime-config check: a running app that disagrees with
Terraform must fail the deploy (POAM-038)."""

import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "check-silk-runtime-config.py"

spec = importlib.util.spec_from_file_location("_silk_runtime_config", SCRIPT)
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

EXPECTED = {
    "cognitoEnabled": True,
    "domain": "example.auth.us-east-2.amazoncognito.com",
    "clientId": "abc123",
    "redirectUri": "https://example.com/silk-reeling/",
}


def test_matching_app_passes():
    actual = dict(EXPECTED, present={"issuer": True})
    assert check.mismatches(EXPECTED, actual) == []


def test_app_without_cognito_settings_fails():
    # What the drifted function actually served.
    actual = {"cognitoEnabled": False, "present": {"issuer": False}}
    assert check.mismatches(EXPECTED, actual) == ["clientId", "cognitoEnabled", "domain", "redirectUri"]


def test_stale_client_id_fails():
    assert check.mismatches(EXPECTED, dict(EXPECTED, clientId="old")) == ["clientId"]


def test_main_exit_codes(monkeypatch):
    monkeypatch.setattr(check, "fetch", lambda url, timeout=30: {"cognitoEnabled": False})
    assert check.main([json.dumps(EXPECTED), "--attempts", "1"]) == 1
    monkeypatch.setattr(check, "fetch", lambda url, timeout=30: dict(EXPECTED))
    assert check.main([json.dumps(EXPECTED)]) == 0


def test_not_deployed_passes():
    assert check.main([""]) == 0


def test_unreachable_endpoint_fails_closed(monkeypatch):
    def boom(url, timeout=30):
        raise OSError("down")
    monkeypatch.setattr(check, "fetch", boom)
    monkeypatch.setattr(check.time, "sleep", lambda s: None)
    assert check.main([json.dumps(EXPECTED), "--attempts", "2"]) == 2
