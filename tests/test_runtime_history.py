"""Runtime run history (VER-RPT-PER): a bounded, signed record of every run.

The runtime signal is overwritten on each run; infrastructure/lambda/history.js
carries a summary of previous runs into the next signal, inside the signed
payload. These tests drive it under plain node with a signal signed here by a
throwaway P-256 key (same recipe as the KMS signer: canonical JSON without
provenance.attestation, ECDSA SHA-256, DER), and check that history is carried
only from a signal that verifies, that a reset says why, and that the list is
deduplicated, ordered and bounded.
"""

import base64
import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest

cryptography = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
HISTORY = REPO / "infrastructure" / "lambda" / "history.js"
SCHEMA = REPO / "infrastructure" / "schemas" / "ksi-signal.schema.json"

pytestmark = pytest.mark.skipif(not shutil.which("node"), reason="requires node on PATH")

DRIVER = """
const h = require(process.argv[1]);
const a = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const verified = h.verifySignal(a.previous, a.pem);
const limit = a.limit === undefined ? h.RUN_HISTORY_LIMIT : a.limit;
process.stdout.write(JSON.stringify({
  verified, limit: h.RUN_HISTORY_LIMIT,
  history: h.nextRunHistory(a.previous, verified, a.current, limit),
}));
"""


def node(previous, pem, current, limit=None):
    args = {"previous": previous, "pem": pem, "current": current}
    if limit is not None:
        args["limit"] = limit
    out = subprocess.run(
        ["node", "-e", DRIVER, str(HISTORY)], input=json.dumps(args),
        capture_output=True, text=True, check=True,
    )
    return json.loads(out.stdout)


def canonical(signal):
    s = copy.deepcopy(signal)
    s["provenance"].pop("attestation", None)
    return json.dumps(s, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


@pytest.fixture(scope="module")
def key():
    k = ec.generate_private_key(ec.SECP256R1())
    pem = k.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return k, pem


def sign(signal, k):
    s = copy.deepcopy(signal)
    sig = k.sign(canonical(s), ec.ECDSA(hashes.SHA256()))
    s["provenance"]["attestation"] = {"signature": base64.b64encode(sig).decode()}
    return s


def signal(n, history=None, failed=0, divergence="consistent"):
    s = {
        "signal_id": f"sig-{n:03d}",
        "emitted_at": f"2026-10-{n:02d}T06:00:00Z" if n <= 31 else f"2026-11-{n - 31:02d}T06:00:00Z",
        "provenance": {"source": {"ref": "runtime"}},
        "validations": [{"result": "fail" if i < failed else "pass", "violations": []} for i in range(5)],
        "divergence": {"status": divergence},
    }
    if history is not None:
        s["run_history"] = history
    return s


def test_first_run_resets_and_says_why(key):
    out = node(None, key[1], signal(2))
    assert out["history"] == [{
        "signal_id": "sig-002", "emitted_at": "2026-10-02T06:00:00Z", "validations": 5,
        "failed": 0, "unassessed": 0, "divergence": "consistent",
        "history_reset": "no previous runtime signal",
    }]


def test_verified_previous_without_history_is_seeded(key):
    prev = sign(signal(1, failed=2), key[0])
    out = node(prev, key[1], signal(2))
    assert out["verified"] is True
    assert [e["signal_id"] for e in out["history"]] == ["sig-001", "sig-002"]
    assert out["history"][0]["failed"] == 2
    assert all("history_reset" not in e for e in out["history"])


def test_verified_history_is_carried_forward(key):
    first = node(None, key[1], signal(1))["history"]
    prev = sign(signal(2, history=first + [{"signal_id": "sig-002", "emitted_at": "2026-10-02T06:00:00Z",
                                            "validations": 5, "failed": 0, "divergence": "consistent"}]), key[0])
    out = node(prev, key[1], signal(3))
    assert [e["signal_id"] for e in out["history"]] == ["sig-001", "sig-002", "sig-003"]
    assert out["history"][0]["history_reset"] == "no previous runtime signal"


def test_tampered_previous_restarts_history(key):
    prev = sign(signal(2, history=[{"signal_id": "sig-001", "emitted_at": "2026-10-01T06:00:00Z",
                                    "validations": 5, "failed": 0, "divergence": "consistent"}]), key[0])
    prev["run_history"][0]["failed"] = 0
    prev["run_history"].insert(0, {"signal_id": "forged", "emitted_at": "2026-01-01T00:00:00Z",
                                   "validations": 99, "failed": 0, "divergence": "consistent"})
    out = node(prev, key[1], signal(3))
    assert out["verified"] is False
    assert [e["signal_id"] for e in out["history"]] == ["sig-003"]
    assert out["history"][0]["history_reset"] == "previous runtime signal did not verify"


def test_signed_by_another_key_restarts_history(key):
    other = ec.generate_private_key(ec.SECP256R1())
    out = node(sign(signal(2, history=[]), other), key[1], signal(3))
    assert out["verified"] is False
    assert out["history"][0]["history_reset"] == "previous runtime signal did not verify"


def test_unsigned_previous_restarts_history(key):
    out = node(signal(2, history=[]), key[1], signal(3))
    assert out["verified"] is False


def test_duplicate_and_malformed_entries_dropped(key):
    hist = [
        {"signal_id": "sig-001", "emitted_at": "2026-10-01T06:00:00Z", "validations": 5, "failed": 0,
         "divergence": "consistent"},
        {"signal_id": "sig-001", "emitted_at": "2026-10-01T06:00:00Z", "validations": 5, "failed": 0,
         "divergence": "consistent"},
        {"signal_id": "bad", "emitted_at": "2026-10-01T07:00:00Z", "validations": "five", "failed": 0,
         "divergence": "consistent"},
    ]
    out = node(sign(signal(2, history=hist), key[0]), key[1], signal(2))
    assert [e["signal_id"] for e in out["history"]] == ["sig-001", "sig-002"]


def test_history_is_bounded_keeping_the_newest(key):
    hist = node(None, key[1], signal(1))["history"]
    for n in range(2, 8):
        hist = node(sign(signal(n - 1, history=hist), key[0]), key[1], signal(n), limit=4)["history"]
    assert [e["signal_id"] for e in hist] == ["sig-004", "sig-005", "sig-006", "sig-007"]


def test_limit_covers_a_year_and_matches_schema():
    out = node(None, None, signal(1))
    schema = json.loads(SCHEMA.read_text())
    run_history = schema["$defs"]["run_history"]
    assert out["limit"] >= 366
    assert run_history["maxItems"] == out["limit"]
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(out["history"], run_history)


def test_unassessed_counts_input_category_violations(key):
    cur = signal(1)
    cur["validations"][0]["violations"] = [{"id": "resource_read_error", "category": "input"}]
    cur["validations"][0]["result"] = "fail"
    out = node(None, key[1], cur)
    assert out["history"][0]["unassessed"] == 1
    assert out["history"][0]["failed"] == 1
