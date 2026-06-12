# Task 6 acceptance: the inventory gate blocks on a malformed PURL, a duplicate
# native_id, and an ecosystem-mistyped component; and passes a correct signal.

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("gate", REPO / "scripts" / "validate-ksi-signal.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def _sig(components):
    return {"components": components}


def test_a_malformed_purl_fails():
    s = _sig([{"type": "npm_package",
               "global_id": {"purl": "pkg:npm/@smithy/is-array-buffer@2.2.0"}}])
    errs, _ = gate.validate(s)
    assert errs and any("%40" in e or "scope" in e for e in errs)


def test_b_duplicate_native_id_fails():
    s = _sig([
        {"type": "function", "native_id": "arn:aws:lambda:::a"},
        {"type": "function", "native_id": "arn:aws:lambda:::a"},
    ])
    errs, _ = gate.validate(s)
    assert any("duplicate native_id" in e for e in errs)


def test_c_ecosystem_mistyped_fails():
    s = _sig([{"type": "npm_package", "global_id": {"purl": "pkg:pypi/flask@3.0.0"}}])
    errs, _ = gate.validate(s)
    assert any("inconsistent with PURL ecosystem" in e for e in errs)


def test_c_missing_version_fails():
    s = _sig([{"type": "npm_package", "global_id": {"purl": "pkg:npm/left-pad"}}])
    errs, _ = gate.validate(s)
    assert any("@version" in e for e in errs)


def test_d_correct_signal_passes():
    s = _sig([
        {"type": "npm_package", "global_id": {"purl": "pkg:npm/%40smithy/is-array-buffer@2.2.0"}},
        {"type": "pypi_package", "global_id": {"purl": "pkg:pypi/flask@3.0.0"}},
        {"type": "function", "native_id": "arn:aws:lambda:::a"},
        {"type": "function", "native_id": "arn:aws:lambda:::b"},
        {"type": "html_artifact", "global_id": {"sha256": "ab" * 32}},
    ])
    errs, n = gate.validate(s)
    assert errs == [], errs
    assert n == 5
