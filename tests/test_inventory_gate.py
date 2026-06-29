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


def test_e_pass_with_violations_fails():
    # The v-0015 defect: a validation marked result 'pass' while carrying
    # violations must be rejected by the gate.
    s = _sig([])
    s["validations"] = [{
        "validation_id": "v-0015", "result": "pass",
        "violations": [{"type": "encryption_disabled", "message": "x", "severity": "HIGH"}],
    }]
    errs, _ = gate.validate(s)
    assert any("v-0015" in e and "pass" in e for e in errs)


def test_e_fail_with_violations_passes_gate():
    # A correctly-labeled fail with violations, and a clean pass, both fine.
    s = _sig([])
    s["validations"] = [
        {"validation_id": "v-1", "result": "fail",
         "violations": [{"type": "x", "message": "y", "severity": "HIGH"}]},
        {"validation_id": "v-2", "result": "pass", "violations": []},
    ]
    errs, _ = gate.validate(s)
    assert errs == [], errs
