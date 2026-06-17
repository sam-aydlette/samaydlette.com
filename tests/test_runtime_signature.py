"""Verifier-side test for the signed runtime KSI signal (POAM-002, Task 5).

This reproduces, in Python, exactly what an external consumer does to verify the
runtime signal published at /.well-known/ksi-signal-runtime.json:

  1. strip provenance.attestation,
  2. canonicalize (sorted keys, compact separators, UTF-8),
  3. SHA-256 + ECDSA-verify the DER signature against the published P-256 key.

The canonicalization here is byte-identical to the Lambda's signer
(infrastructure/lambda/canonical.js) — verified independently and pinned below —
so this proves the signature is verifiable cross-language, not just by re-running
the JS that produced it.
"""

import base64
import copy
import json

import pytest

cryptography = pytest.importorskip("cryptography")
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def canonical_bytes(signal):
    """The exact bytes the signer hashes — provenance.attestation removed."""
    s = copy.deepcopy(signal)
    if isinstance(s.get("provenance"), dict):
        s["provenance"].pop("attestation", None)
    return json.dumps(
        s, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def verify(signal, public_key):
    """Return True iff provenance.attestation.signature is valid for `signal`."""
    sig = base64.b64decode(signal["provenance"]["attestation"]["signature"])
    public_key.verify(sig, canonical_bytes(signal), ec.ECDSA(hashes.SHA256()))
    return True


SAMPLE = {
    "signal_version": "1.0.0",
    "emitted_at": "2026-06-17T00:00:00Z",
    "emitter": "runtime",
    "system_id": "sys-1",
    "csp": "aws",
    "provenance": {
        "source": {"repository": "r", "commit": "abc", "ref": "runtime"},
        "builder": {"id": "b", "run_id": "x", "version": "1"},
    },
    "components": [{"id": "c2", "type": "t"}, {"id": "c1", "type": "t"}],
    "validations": [{"id": "v1", "result": "pass"}],
    "unicode": "café—ok",
}

# Pinned canonical form — must stay byte-identical to canonical.js (cross-checked
# with `node -e "require('./canonical').canonicalize(...)"`). A drift here means
# the JS signer and any verifier have diverged.
EXPECTED_CANONICAL = (
    '{"components":[{"id":"c2","type":"t"},{"id":"c1","type":"t"}],'
    '"csp":"aws","emitted_at":"2026-06-17T00:00:00Z","emitter":"runtime",'
    '"provenance":{"builder":{"id":"b","run_id":"x","version":"1"},'
    '"source":{"commit":"abc","ref":"runtime","repository":"r"}},'
    '"signal_version":"1.0.0","system_id":"sys-1","unicode":"café—ok",'
    '"validations":[{"id":"v1","result":"pass"}]}'
)


def _sign(signal, private_key):
    sig = private_key.sign(canonical_bytes(signal), ec.ECDSA(hashes.SHA256()))
    signed = copy.deepcopy(signal)
    signed["provenance"]["attestation"] = {
        "type": "kms-ecdsa-p256",
        "algorithm": "ECDSA_SHA_256",
        "signature": base64.b64encode(sig).decode(),
    }
    return signed


def test_canonical_form_is_pinned():
    assert canonical_bytes(SAMPLE).decode("utf-8") == EXPECTED_CANONICAL


def test_attestation_is_excluded_from_canonical_bytes():
    base = canonical_bytes(SAMPLE)
    withatt = copy.deepcopy(SAMPLE)
    withatt["provenance"]["attestation"] = {"signature": "anything"}
    assert canonical_bytes(withatt) == base


def test_valid_signature_verifies():
    key = ec.generate_private_key(ec.SECP256R1())
    signed = _sign(SAMPLE, key)
    assert verify(signed, key.public_key()) is True


def test_tampered_signal_fails():
    key = ec.generate_private_key(ec.SECP256R1())
    signed = _sign(SAMPLE, key)
    signed["validations"][0]["result"] = "fail"  # flip a claim after signing
    with pytest.raises(InvalidSignature):
        verify(signed, key.public_key())


def test_wrong_key_fails():
    signed = _sign(SAMPLE, ec.generate_private_key(ec.SECP256R1()))
    other = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(InvalidSignature):
        verify(signed, other)


def test_pem_roundtrip_matches_published_form():
    """The Lambda publishes SPKI PEM; ensure that round-trips to a usable key."""
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    loaded = serialization.load_pem_public_key(pem)
    signed = _sign(SAMPLE, key)
    # verify against the key reconstructed from PEM (what a consumer loads)
    sig = base64.b64decode(signed["provenance"]["attestation"]["signature"])
    loaded.verify(sig, canonical_bytes(signed), ec.ECDSA(hashes.SHA256()))
