"""Tests for scripts/verify-attestation.py (Task 15 / S3).

Builds a synthetic Sigstore new-bundle-format attestation (inline DSSE envelope
wrapping an in-toto SLSA v1 Statement) and checks that the dependency-free
consumer accepts a correct one and fails closed on tampering.
"""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "verify_attestation", REPO / "scripts" / "verify-attestation.py"
)
va = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(va)


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _bundle(subject_sha, inv_sha, signal_id="sig-1", commit="c0ffee"):
    stmt = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": va.SLSA_V1,
        "subject": [{"name": "oscal-ssp.json", "digest": {"sha256": subject_sha}}],
        "predicate": {
            "buildDefinition": {
                "buildType": "https://samaydlette.com/buildtypes/compliance-artifact/v1",
                "resolvedDependencies": [
                    {"uri": "git+x@refs/heads/main", "digest": {"gitCommit": commit}},
                    {"uri": "ksi-signal.json", "digest": {"sha256": inv_sha},
                     "annotations": {"role": "canonical-inventory", "signal_id": signal_id}},
                    {"uri": "scripts/build-oscal-ssp.py", "digest": {"sha256": "abcd"},
                     "annotations": {"role": "generator"}},
                ],
            },
            "runDetails": {"builder": {"id": "https://github.com/.../deploy-with-opa.yml@refs/heads/main"}},
        },
    }
    payload = base64.b64encode(json.dumps(stmt).encode()).decode()
    return {"dsseEnvelope": {"payloadType": "application/vnd.in-toto+json", "payload": payload, "signatures": [{"sig": "x"}]}}


def _write(tmp_path, name, data: bytes):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_accepts_correct_attestation(tmp_path):
    art = _write(tmp_path, "oscal-ssp.json", b'{"system":"x"}')
    inv = _write(tmp_path, "ksi-signal.json", b'{"signal_id":"sig-1"}')
    bundle = _write(tmp_path, "a.intoto.jsonl",
                    json.dumps(_bundle(_sha(art.read_bytes()), _sha(inv.read_bytes()))).encode())
    stmt, errors = va.check(str(bundle), str(art), str(inv))
    assert errors == []
    assert stmt["predicateType"] == va.SLSA_V1


def test_fails_on_subject_mismatch(tmp_path):
    art = _write(tmp_path, "oscal-ssp.json", b'{"system":"x"}')
    inv = _write(tmp_path, "ksi-signal.json", b'{"signal_id":"sig-1"}')
    # subject digest is for DIFFERENT bytes -> binding must fail
    bundle = _write(tmp_path, "a.intoto.jsonl",
                    json.dumps(_bundle(_sha(b"other-bytes"), _sha(inv.read_bytes()))).encode())
    _, errors = va.check(str(bundle), str(art), str(inv))
    assert any("subject digest" in e for e in errors)


def test_fails_on_tampered_inventory_digest(tmp_path):
    art = _write(tmp_path, "oscal-ssp.json", b'{"system":"x"}')
    inv = _write(tmp_path, "ksi-signal.json", b'{"signal_id":"sig-1"}')
    # predicate claims an inventory digest that is not the real ksi-signal bytes
    bundle = _write(tmp_path, "a.intoto.jsonl",
                    json.dumps(_bundle(_sha(art.read_bytes()), "deadbeef")).encode())
    _, errors = va.check(str(bundle), str(art), str(inv))
    assert any("inventory digest" in e for e in errors)


def test_rejects_non_dsse_bundle(tmp_path):
    art = _write(tmp_path, "oscal-ssp.json", b"x")
    bundle = _write(tmp_path, "legacy.json", json.dumps({"cert": "...", "rekorBundle": {}}).encode())
    try:
        va.check(str(bundle), str(art))
        assert False, "should have raised on a legacy (non-DSSE) bundle"
    except ValueError as e:
        assert "dsseEnvelope" in str(e)
