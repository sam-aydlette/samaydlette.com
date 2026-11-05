#!/usr/bin/env python3
"""Sign the DAST scanner user in to the Silk Reeling Cognito pool; print its access token.

The authenticated ZAP API scan (.github/workflows/zap-dast.yml) needs a real
Cognito access token, the same kind the SPA sends, so that the API Gateway JWT
authorizer and the app's own check let the scan through to the code behind
/api. The app client is a public PKCE client whose only password flow is
USER_SRP_AUTH, and the pool requires TOTP MFA for every user. This script does
exactly that sign-in, with the standard library only:

    InitiateAuth(USER_SRP_AUTH) -> PASSWORD_VERIFIER (SRP-6a proof of the password,
    which never leaves the runner) -> SOFTWARE_TOKEN_MFA (an RFC 6238 code from the
    scanner user's TOTP seed) -> access token

No app-client flow is widened and no AWS credentials are used: InitiateAuth,
RespondToAuthChallenge, AssociateSoftwareToken and VerifySoftwareToken are
Cognito's public, unsigned user APIs.

    token   (default) print the access token on stdout, nothing else
    enroll  one time, run by the operator after creating the user: answer the
            MFA_SETUP challenge by associating a new TOTP seed, verify it, and
            print the seed on stdout (pipe it straight into `gh secret set`)

Environment: SILK_DAST_USERNAME, SILK_DAST_PASSWORD, SILK_DAST_USER_POOL_ID,
SILK_DAST_TOTP_SECRET (token only), SILK_DAST_CLIENT_ID (else read from
--auth-config, the published /.well-known/silk-reeling-auth.json).

Nothing secret is ever printed except the one value asked for on stdout; error
messages carry Cognito's error type and message only.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

# RFC 5054 3072-bit group, the one Cognito's SRP uses; g = 2. This is a client
# for Cognito's fixed SRP protocol, not new cryptography: the PASSWORD_VERIFIER
# signature is checked against a reference vector cross-checked with pycognito
# (tests/test_dast_cognito_token.py), and the stdlib keeps the scan job free of
# third-party packages that would see the password.
N_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
)
N = int(N_HEX, 16)
G = 2
INFO = b"Caldera Derived Key\x01"
REGION_RE = re.compile(r"^([a-z]{2}(?:-[a-z]+)+-\d)_[A-Za-z0-9]+$")


class AuthError(Exception):
    """A sign-in step failed. The text never carries a password, seed or token."""


# ----------------------------------------------------------------------------- SRP-6a


def _hash_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().rjust(64, "0")


def _hex_hash(hex_string: str) -> str:
    return _hash_hex(bytes.fromhex(hex_string))


def pad_hex(value: "int | str") -> str:
    """Cognito's padding: an even number of digits, and a leading 00 when the
    high bit would make the value read as negative."""
    h = value if isinstance(value, str) else format(value, "x")
    if len(h) % 2 == 1:
        h = "0" + h
    elif h[0] in "89abcdefABCDEF":
        h = "00" + h
    return h


K = int(_hex_hash("00" + N_HEX + "0" + format(G, "x")), 16)


def small_a() -> int:
    return int.from_bytes(secrets.token_bytes(128), "big") % N


def large_a(a: int) -> int:
    big_a = pow(G, a, N)
    if big_a % N == 0:
        raise AuthError("SRP: A mod N is zero")
    return big_a


def _hkdf(ikm: bytes, salt: bytes) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, INFO, hashlib.sha256).digest()[:16]


def password_key(pool_id: str, user_id: str, password: str, big_a: int, a: int, big_b: int, salt_hex: str) -> bytes:
    if big_b % N == 0:
        raise AuthError("SRP: server B mod N is zero")
    u = int(_hex_hash(pad_hex(big_a) + pad_hex(big_b)), 16)
    if u == 0:
        raise AuthError("SRP: u is zero")
    pool_name = pool_id.split("_", 1)[1]
    up_hash = _hash_hex(f"{pool_name}{user_id}:{password}".encode("utf-8"))
    x = int(_hex_hash(pad_hex(salt_hex) + up_hash), 16)
    s = pow(big_b - K * pow(G, x, N), a + u * x, N)
    return _hkdf(bytes.fromhex(pad_hex(s)), bytes.fromhex(pad_hex(format(u, "x"))))


_DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def cognito_timestamp(now: datetime) -> str:
    """'Thu Nov 5 07:03:09 UTC 2026', in UTC, English names whatever the locale,
    the day unpadded: the form Cognito signs."""
    t = now.astimezone(timezone.utc)
    return (f"{_DAYS[t.weekday()]} {_MONTHS[t.month - 1]} {t.day:d} "
            f"{t.hour:02d}:{t.minute:02d}:{t.second:02d} UTC {t.year:d}")


def password_verifier(pool_id: str, password: str, params: dict, a: int, big_a: int, now: datetime) -> dict:
    """The PASSWORD_VERIFIER challenge responses for Cognito's challenge parameters."""
    user_id = params["USER_ID_FOR_SRP"]
    key = password_key(pool_id, user_id, password, big_a, a, int(params["SRP_B"], 16), params["SALT"])
    stamp = cognito_timestamp(now)
    msg = (pool_id.split("_", 1)[1].encode("utf-8") + user_id.encode("utf-8")
           + base64.standard_b64decode(params["SECRET_BLOCK"]) + stamp.encode("utf-8"))
    sig = base64.standard_b64encode(hmac.new(key, msg, hashlib.sha256).digest()).decode("ascii")
    return {"TIMESTAMP": stamp, "USERNAME": user_id, "PASSWORD_CLAIM_SECRET_BLOCK": params["SECRET_BLOCK"],
            "PASSWORD_CLAIM_SIGNATURE": sig}


# ----------------------------------------------------------------------------- TOTP


def totp(seed_b32: str, at: float, digits: int = 6, step: int = 30) -> str:
    """RFC 6238 (HMAC-SHA1), the code an authenticator app shows. SHA-1 here is
    what Cognito's software-token MFA (and every authenticator app) computes;
    it is an HMAC, where SHA-1's collision weakness does not apply."""
    seed = seed_b32.strip().replace(" ", "").upper()
    key = base64.b32decode(seed + "=" * (-len(seed) % 8))
    mac = hmac.new(key, struct.pack(">Q", int(at) // step), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).rjust(digits, "0")


# ----------------------------------------------------------------------------- Cognito


def region_of(pool_id: str) -> str:
    m = REGION_RE.match(pool_id or "")
    if not m:
        raise AuthError("SILK_DAST_USER_POOL_ID is not a Cognito user pool id")
    return m.group(1)


def call(region: str, action: str, body: dict) -> dict:
    req = urllib.request.Request(
        f"https://cognito-idp.{region}.amazonaws.com/", data=json.dumps(body).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/x-amz-json-1.1",
                 "X-Amz-Target": f"AWSCognitoIdentityProviderService.{action}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (fixed https endpoint)
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            err = json.loads(exc.read().decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            err = {}
        kind = str(err.get("__type") or exc.code).split("#")[-1]
        raise AuthError(f"{action}: {kind}: {str(err.get('message') or '')[:200]}") from None
    except urllib.error.URLError as exc:
        raise AuthError(f"{action}: {type(exc.reason).__name__}") from None


def sign_in(pool_id: str, client_id: str, username: str, password: str, now=None) -> dict:
    """Through PASSWORD_VERIFIER; returns the next Cognito response."""
    region = region_of(pool_id)
    a = small_a()
    big_a = large_a(a)
    r = call(region, "InitiateAuth", {"AuthFlow": "USER_SRP_AUTH", "ClientId": client_id,
                                      "AuthParameters": {"USERNAME": username, "SRP_A": format(big_a, "x")}})
    if r.get("ChallengeName") != "PASSWORD_VERIFIER":
        raise AuthError(f"InitiateAuth: expected PASSWORD_VERIFIER, got {r.get('ChallengeName')}")
    params = r.get("ChallengeParameters") or {}
    responses = password_verifier(pool_id, password, params, a, big_a, now or datetime.now(timezone.utc))
    body = {"ChallengeName": "PASSWORD_VERIFIER", "ClientId": client_id, "ChallengeResponses": responses}
    if r.get("Session"):
        body["Session"] = r["Session"]
    nxt = call(region, "RespondToAuthChallenge", body)
    nxt["_user_id"] = params["USER_ID_FOR_SRP"]
    return nxt


def access_token(pool_id: str, client_id: str, username: str, password: str, seed: str) -> str:
    region = region_of(pool_id)
    r = sign_in(pool_id, client_id, username, password)
    if r.get("ChallengeName") == "SOFTWARE_TOKEN_MFA":
        r = call(region, "RespondToAuthChallenge", {
            "ChallengeName": "SOFTWARE_TOKEN_MFA", "ClientId": client_id, "Session": r.get("Session"),
            "ChallengeResponses": {"USERNAME": r["_user_id"], "SOFTWARE_TOKEN_MFA_CODE": totp(seed, time.time())}})
    elif r.get("ChallengeName"):
        raise AuthError(f"unexpected challenge {r['ChallengeName']} (run `enroll` once, or set the "
                        "password permanent with admin-set-user-password --permanent)")
    token = (r.get("AuthenticationResult") or {}).get("AccessToken")
    if not token:
        raise AuthError("Cognito returned no access token")
    return token


def enroll(pool_id: str, client_id: str, username: str, password: str) -> str:
    """Answer MFA_SETUP with a new TOTP seed; returns the seed."""
    region = region_of(pool_id)
    r = sign_in(pool_id, client_id, username, password)
    if r.get("ChallengeName") != "MFA_SETUP":
        raise AuthError(f"expected MFA_SETUP, got {r.get('ChallengeName') or 'tokens'} (already enrolled?)")
    assoc = call(region, "AssociateSoftwareToken", {"Session": r["Session"]})
    seed = assoc["SecretCode"]
    ver = call(region, "VerifySoftwareToken", {"Session": assoc["Session"], "UserCode": totp(seed, time.time()),
                                               "FriendlyDeviceName": "zap-dast"})
    if ver.get("Status") != "SUCCESS":
        raise AuthError("VerifySoftwareToken did not succeed")
    done = call(region, "RespondToAuthChallenge", {"ChallengeName": "MFA_SETUP", "ClientId": client_id,
                                                   "Session": ver["Session"],
                                                   "ChallengeResponses": {"USERNAME": r["_user_id"]}})
    if not (done.get("AuthenticationResult") or {}).get("AccessToken"):
        raise AuthError("MFA_SETUP completed without tokens")
    return seed


def client_id_from(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        cfg = json.load(fh)
    cid = cfg.get("clientId") if isinstance(cfg, dict) else None
    if not isinstance(cid, str) or not re.fullmatch(r"[A-Za-z0-9]{1,128}", cid):
        raise AuthError(f"{path} carries no app client id")
    return cid


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", nargs="?", choices=("token", "enroll"), default="token")
    ap.add_argument("--auth-config", help="the published silk-reeling-auth.json (for the app client id)")
    args = ap.parse_args(argv)
    env = os.environ
    need = ["SILK_DAST_USERNAME", "SILK_DAST_PASSWORD", "SILK_DAST_USER_POOL_ID"]
    if args.mode == "token":
        need.append("SILK_DAST_TOTP_SECRET")
    missing = [k for k in need if not env.get(k)]
    if missing:
        print(f"::error::not set: {', '.join(missing)}", file=sys.stderr)
        return 2
    try:
        cid = env.get("SILK_DAST_CLIENT_ID") or (client_id_from(args.auth_config) if args.auth_config else "")
        if not cid:
            raise AuthError("no app client id (SILK_DAST_CLIENT_ID or --auth-config)")
        if args.mode == "enroll":
            out = enroll(env["SILK_DAST_USER_POOL_ID"], cid, env["SILK_DAST_USERNAME"], env["SILK_DAST_PASSWORD"])
        else:
            out = access_token(env["SILK_DAST_USER_POOL_ID"], cid, env["SILK_DAST_USERNAME"],
                               env["SILK_DAST_PASSWORD"], env["SILK_DAST_TOTP_SECRET"])
    except (AuthError, KeyError, OSError, ValueError) as exc:
        detail = str(exc) if isinstance(exc, AuthError) else type(exc).__name__
        print(f"::error::Cognito sign-in failed: {detail.replace('::', ':')}", file=sys.stderr)
        return 1
    sys.stdout.write(out + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
