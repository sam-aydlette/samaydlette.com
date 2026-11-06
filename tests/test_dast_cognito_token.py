"""The DAST scanner's Cognito sign-in (scripts/dast-cognito-token.py).

SRP-6a and TOTP are checked against fixed vectors: TOTP against RFC 6238's
own, SRP against a vector cross-checked with pycognito 2024.5.1 (the PASSWORD_VERIFIER
signature for a fixed secret exponent, server value, salt, secret block and
time). The flow is checked against a scripted Cognito: the password never
leaves the process, only the token reaches the owner-only --out file, and an unexpected challenge
stops the sign-in.
"""
import importlib.util
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("dast_token", REPO / "scripts" / "dast-cognito-token.py")
tok = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tok)

POOL = "us-east-2_AbCdEfGhI"
PASSWORD = "Correct-Horse-Battery-9!"
SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # RFC 6238's SHA-1 key, base32


@pytest.mark.parametrize("t,code", [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                                    (1234567890, "89005924"), (2000000000, "69279037")])
def test_totp_matches_rfc6238(t, code):
    assert tok.totp(SEED, t, digits=8) == code
    assert tok.totp(SEED.lower(), t) == code[-6:]


def test_srp_password_verifier_matches_the_reference_vector():
    a = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF % tok.N
    big_b = pow(2, 0xDEADBEEFCAFEBABE1234, tok.N)
    params = {"USER_ID_FOR_SRP": "uuid-user-1", "SRP_B": format(big_b, "x"), "SALT": "8f3a1c",
              "SECRET_BLOCK": "c2VjcmV0YmxvY2tieXRlcw=="}
    now = datetime(2026, 11, 5, 7, 3, 9, tzinfo=timezone.utc)
    out = tok.password_verifier(POOL, PASSWORD, params, a, tok.large_a(a), now)
    assert out == {"TIMESTAMP": "Thu Nov 5 07:03:09 UTC 2026", "USERNAME": "uuid-user-1",
                   "PASSWORD_CLAIM_SECRET_BLOCK": "c2VjcmV0YmxvY2tieXRlcw==",
                   "PASSWORD_CLAIM_SIGNATURE": "MFnkJNc5ZDDsrbP0nbK49s56hPcd65Q5CD50xT1T1Zs="}


def test_srp_refuses_a_degenerate_server_value():
    a = tok.small_a()
    with pytest.raises(tok.AuthError, match="B mod N"):
        tok.password_key(POOL, "u", PASSWORD, tok.large_a(a), a, tok.N * 3, "00")


def test_pad_hex_and_timestamp_forms():
    assert tok.pad_hex(0xF) == "0f" and tok.pad_hex(0x8F) == "008f" and tok.pad_hex(0x7F) == "7f"
    assert tok.cognito_timestamp(datetime(2026, 1, 12, 23, 4, 5, tzinfo=timezone.utc)) == "Mon Jan 12 23:04:05 UTC 2026"


def test_region_comes_from_the_pool_id():
    assert tok.region_of(POOL) == "us-east-2"
    with pytest.raises(tok.AuthError):
        tok.region_of("not-a-pool")


class Cognito:
    """A scripted Cognito: answers each call in turn and records the bodies."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = []

    def __call__(self, region, action, body):
        self.calls.append((region, action, body))
        want, answer = self.answers.pop(0)
        assert action == want, (action, want)
        return answer(body) if callable(answer) else answer


SRP_CHALLENGE = {"ChallengeName": "PASSWORD_VERIFIER", "ChallengeParameters": {
    "USER_ID_FOR_SRP": "uuid-user-1", "SRP_B": format(pow(2, 12345, tok.N), "x"), "SALT": "ab12",
    "SECRET_BLOCK": "c2VjcmV0"}}


def test_sign_in_answers_srp_then_totp_and_returns_the_access_token(monkeypatch):
    cog = Cognito([
        ("InitiateAuth", SRP_CHALLENGE),
        ("RespondToAuthChallenge", {"ChallengeName": "SOFTWARE_TOKEN_MFA", "Session": "s1"}),
        ("RespondToAuthChallenge", {"AuthenticationResult": {"AccessToken": "header.payload.sig"}}),
    ])
    monkeypatch.setattr(tok, "call", cog)
    monkeypatch.setattr(tok.time, "time", lambda: 59)
    assert tok.access_token(POOL, "client1", "scanner@example.invalid", PASSWORD, SEED) == "header.payload.sig"
    (_, _, init), (_, _, pv), (_, _, mfa) = cog.calls
    assert init["AuthFlow"] == "USER_SRP_AUTH" and init["AuthParameters"]["USERNAME"] == "scanner@example.invalid"
    assert pv["ChallengeName"] == "PASSWORD_VERIFIER" and pv["ChallengeResponses"]["USERNAME"] == "uuid-user-1"
    assert mfa["ChallengeResponses"] == {"USERNAME": "uuid-user-1", "SOFTWARE_TOKEN_MFA_CODE": "287082"}
    assert mfa["Session"] == "s1"
    assert all(region == "us-east-2" for region, _, _ in cog.calls)
    assert PASSWORD not in json.dumps([body for _, _, body in cog.calls])


def test_an_unexpected_challenge_stops_the_sign_in(monkeypatch):
    monkeypatch.setattr(tok, "call", Cognito([
        ("InitiateAuth", SRP_CHALLENGE),
        ("RespondToAuthChallenge", {"ChallengeName": "NEW_PASSWORD_REQUIRED", "Session": "s"}),
    ]))
    with pytest.raises(tok.AuthError, match="NEW_PASSWORD_REQUIRED"):
        tok.access_token(POOL, "client1", "u", PASSWORD, SEED)


def test_enroll_associates_verifies_and_returns_the_seed(monkeypatch):
    cog = Cognito([
        ("InitiateAuth", SRP_CHALLENGE),
        ("RespondToAuthChallenge", {"ChallengeName": "MFA_SETUP", "Session": "s1"}),
        ("AssociateSoftwareToken", {"SecretCode": SEED, "Session": "s2"}),
        ("VerifySoftwareToken", {"Status": "SUCCESS", "Session": "s3"}),
        ("RespondToAuthChallenge", {"AuthenticationResult": {"AccessToken": "t"}}),
    ])
    monkeypatch.setattr(tok, "call", cog)
    monkeypatch.setattr(tok.time, "time", lambda: 59)
    assert tok.enroll(POOL, "client1", "u", PASSWORD) == SEED
    assert cog.calls[3][2]["UserCode"] == "287082" and cog.calls[3][2]["Session"] == "s2"
    assert cog.calls[4][2]["ChallengeName"] == "MFA_SETUP" and cog.calls[4][2]["Session"] == "s3"


def _main(monkeypatch, env, argv):
    for k in ("SILK_DAST_USERNAME", "SILK_DAST_PASSWORD", "SILK_DAST_TOTP_SECRET", "SILK_DAST_USER_POOL_ID",
              "SILK_DAST_CLIENT_ID"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = tok.main(argv)
    return rc, out.getvalue(), err.getvalue()


FULL = {"SILK_DAST_USERNAME": "u", "SILK_DAST_PASSWORD": PASSWORD, "SILK_DAST_TOTP_SECRET": SEED,
        "SILK_DAST_USER_POOL_ID": POOL}


def test_main_writes_only_the_token_to_an_owner_only_file(monkeypatch, tmp_path):
    cfg = tmp_path / "auth.json"
    cfg.write_text(json.dumps({"clientId": "abc123"}))
    seen = {}

    def fake(pool, cid, user, pw, seed):
        seen.update(pool=pool, cid=cid)
        return "the-token"
    monkeypatch.setattr(tok, "access_token", fake)
    dest = tmp_path / "token"
    dest.write_text("stale")
    dest.chmod(0o644)
    rc, out, err = _main(monkeypatch, FULL, ["token", "--auth-config", str(cfg), "--out", str(dest)])
    assert (rc, out, err) == (0, "", "")
    assert dest.read_text() == "the-token"
    assert dest.stat().st_mode & 0o777 == 0o600
    assert seen == {"pool": POOL, "cid": "abc123"}


def test_main_requires_an_output_file(monkeypatch):
    with pytest.raises(SystemExit):
        _main(monkeypatch, FULL, ["token"])


def test_main_refuses_missing_credentials_without_naming_values(monkeypatch):
    rc, out, err = _main(monkeypatch, {"SILK_DAST_PASSWORD": PASSWORD}, ["token", "--out", "/nonexistent/x"])
    assert rc == 2 and out == ""
    assert "SILK_DAST_USERNAME" in err and PASSWORD not in err


def test_a_failed_sign_in_says_why_without_secrets(monkeypatch):
    def boom(*a):
        raise tok.AuthError("RespondToAuthChallenge: NotAuthorizedException: Incorrect username or password.")
    monkeypatch.setattr(tok, "access_token", boom)
    rc, out, err = _main(monkeypatch, {**FULL, "SILK_DAST_CLIENT_ID": "abc"}, ["token", "--out", "/nonexistent/x"])
    assert rc == 1 and out == ""
    assert "NotAuthorizedException" in err and PASSWORD not in err and SEED not in err
