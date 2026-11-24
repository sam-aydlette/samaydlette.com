"""The Silk Reeling runtime-config check: a running app that disagrees with
Terraform, or a gateway that answers without a token, must fail the deploy
(POAM-038)."""

import importlib.util
import json
from pathlib import Path

import pytest

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


ARGS = ["--function", "fn", "--gateway", "https://gw.example"]
CLOSED = {"/": 404, "/api/healthz": 401}


def _gateway(monkeypatch, answers):
    monkeypatch.setattr(check, "status", lambda url, timeout=30: answers[url.removeprefix("https://gw.example")])


def test_main_exit_codes(monkeypatch):
    _gateway(monkeypatch, CLOSED)
    monkeypatch.setattr(check, "invoke", lambda fn, timeout=60: {"cognitoEnabled": False})
    assert check.main([json.dumps(EXPECTED), *ARGS, "--attempts", "1"]) == 1
    monkeypatch.setattr(check, "invoke", lambda fn, timeout=60: dict(EXPECTED))
    assert check.main([json.dumps(EXPECTED), *ARGS]) == 0


def test_not_deployed_passes():
    assert check.main([""]) == 0


def test_a_deployed_app_needs_the_function_and_an_https_gateway():
    assert check.main([json.dumps(EXPECTED)]) == 2
    assert check.main([json.dumps(EXPECTED), "--function", "fn", "--gateway", "http://gw.example"]) == 2


def test_unreachable_function_fails_closed(monkeypatch):
    def boom(fn, timeout=60):
        raise OSError("down")
    monkeypatch.setattr(check, "invoke", boom)
    monkeypatch.setattr(check.time, "sleep", lambda s: None)
    assert check.main([json.dumps(EXPECTED), *ARGS, "--attempts", "2"]) == 2


@pytest.mark.parametrize("answers", [
    {"/": 200, "/api/healthz": 401},   # a catch-all route serves without a token
    {"/": 404, "/api/healthz": 200},   # the API route lost its authorizer
    {"/": 404, "/api/healthz": 500},   # neither refused nor absent: not proven closed
])
def test_a_gateway_that_answers_without_a_token_fails(monkeypatch, answers):
    _gateway(monkeypatch, answers)
    monkeypatch.setattr(check, "invoke", lambda fn, timeout=60: dict(EXPECTED))
    assert check.main([json.dumps(EXPECTED), *ARGS]) == 1


def test_the_invoke_reads_the_body_and_refuses_an_error(monkeypatch, tmp_path):
    class R:
        def __init__(self, rc, out):
            self.returncode, self.stdout = rc, out

    def fake_run(cmd, **kw):
        assert cmd[:4] == ["aws", "lambda", "invoke", "--function-name"] and cmd[4] == "fn"
        assert json.loads(cmd[cmd.index("--payload") + 1])["rawPath"] == "/auth-config"
        Path(cmd[-1]).write_text(json.dumps(fake_run.response))
        return R(0, fake_run.stdout)

    monkeypatch.setattr(check.subprocess, "run", fake_run)
    fake_run.stdout, fake_run.response = "{}", {"statusCode": 200, "body": json.dumps(EXPECTED)}
    assert check.invoke("fn") == EXPECTED
    fake_run.response = {"statusCode": 500, "body": "{}"}
    with pytest.raises(ValueError):
        check.invoke("fn")
    fake_run.stdout, fake_run.response = '{"FunctionError": "Unhandled"}', {"statusCode": 200, "body": "{}"}
    with pytest.raises(ValueError):
        check.invoke("fn")
