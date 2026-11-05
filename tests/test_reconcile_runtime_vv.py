"""Reconciliation invariant (n): runtime V&V coverage (VDR-TFR-MVX, VDR-TFR-PDD).

Every machine component of the inventory must have an assessed validation in a
verified runtime signal no older than the governed window (72h); every
component type must be classified, machine or excluded, in the governed
infrastructure/schemas/runtime-vv-config.json. The known-bad fixture under
tests/fixtures/runtime-vv/ breaks each condition once.
"""

import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "runtime-vv"
CLEAN = REPO / "tests" / "fixtures" / "clean"


def _load():
    spec = importlib.util.spec_from_file_location("reconcile_m", REPO / "scripts" / "reconcile.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


rc = _load()
CONFIG = rc.load_runtime_vv_config()


def fresh(validations):
    return {"verified": True, "fresh": True, "reason": None, "validations": validations}


def test_known_bad_fixture_fails_every_way():
    inv = json.loads((FIX / "ksi-signal.json").read_text())
    vals = json.loads((FIX / "runtime-validations-bad.json").read_text())["validations"]
    v = rc.check_n_runtime_coverage(inv, fresh(vals), CONFIG)
    assert any("quantum_widget" in x and "neither a machine type nor excluded" in x for x in v)
    assert any("aws::iam_role::deploy: no runtime validation" in x for x in v)
    assert any("aws::kms_key::at_rest" in x and "unassessed" in x for x in v)
    # One unassessed run is enough: a pass elsewhere does not paper over it.
    assert any("aws::object_store::site" in x and "unassessed" in x for x in v)
    assert not any("aws::function::app" in x for x in v)
    assert not any("npm::" in x for x in v)
    assert all(x.startswith("(n) ") for x in v)
    assert len(v) == 4


def test_full_coverage_passes():
    inv = json.loads((FIX / "ksi-signal.json").read_text())
    inv["components"] = [c for c in inv["components"] if c["type"] != "quantum_widget"]
    vals = [{"result": "fail", "component_refs": [c["component_id"]], "violations": [{"id": "x", "category": "iam"}]}
            for c in inv["components"] if c["type"] in CONFIG["machine_types"]]
    # A failing (assessed) validation still counts as V&V: the finding is the
    # VDR's business, not a coverage gap.
    assert rc.check_n_runtime_coverage(inv, fresh(vals), CONFIG) == []


@pytest.mark.parametrize("runtime", [
    None,
    {"verified": False, "fresh": False, "reason": "runtime signal signature does not verify (InvalidSignature)"},
    {"verified": True, "fresh": False, "reason": "runtime signal emitted 2026-11-01T00:00:00Z is outside 72h"},
])
def test_unverified_or_stale_signal_fails(runtime):
    inv = {"components": [{"component_id": "aws::function::app", "type": "function"}]}
    v = rc.check_n_runtime_coverage(inv, runtime, CONFIG)
    assert len(v) == 1 and v[0].startswith("(n) no usable runtime V&V within 72h")


def test_every_live_inventory_type_is_classified():
    """The committed config classifies every type the inventory builder emits."""
    spec = importlib.util.spec_from_file_location("ksi_m", REPO / "scripts" / "build-ksi-signal.py")
    ksi = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ksi)
    emitted = set(ksi.TYPE_BY_TF_TYPE.values()) | {"npm_package", "pypi_package", "html_artifact", "external_service"}
    classified = set(CONFIG["machine_types"]) | set(CONFIG["excluded_types"])
    assert emitted - classified == set()


@pytest.mark.parametrize("mutate,message", [
    (lambda c: c.update(max_age_hours=96), "max_age_hours"),
    (lambda c: c.update(max_age_hours=True), "max_age_hours"),
    (lambda c: c.pop("review_by"), "review_by"),
    (lambda c: c["excluded_types"].update(function="software"), "both machine and excluded"),
    (lambda c: c["machine_types"]["function"].pop("likely_to_drift"), "likely_to_drift"),
    (lambda c: c["excluded_types"].update(npm_package=" "), "needs a reason"),
])
def test_config_that_would_weaken_the_gate_is_rejected(tmp_path, mutate, message):
    cfg = copy.deepcopy(json.loads(rc.RUNTIME_VV_CONFIG.read_text()))
    mutate(cfg)
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps(cfg))
    with pytest.raises(ValueError, match=message):
        rc.load_runtime_vv_config(p)


def _clean_argv(*extra):
    return ["reconcile.py", "--artifacts-dir", str(CLEAN), "--dashboard", str(CLEAN / "viewer.html"),
            "--live-fixture", str(CLEAN / "live-arns.json"), "--checkov", str(CLEAN / ".checkov.yaml"),
            "--decisions", str(CLEAN / "decisions.json"), *extra]


def test_missing_runtime_signal_fails_main(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("GITHUB_SHA", raising=False)
    monkeypatch.setattr(sys, "argv", _clean_argv("--runtime-signal", str(tmp_path / "absent.json")))
    assert rc.main() == 1
    assert "(n) no usable runtime V&V" in capsys.readouterr().err


def test_covered_runtime_passes_main(monkeypatch, tmp_path):
    inv = json.loads((CLEAN / "ksi-signal.json").read_text())
    vals = [{"result": "pass", "component_refs": [c["component_id"]], "violations": []} for c in inv["components"]]
    monkeypatch.setattr(rc, "load_verified_runtime", lambda path, hours: fresh(vals))
    monkeypatch.delenv("GITHUB_SHA", raising=False)
    monkeypatch.setattr(sys, "argv", _clean_argv("--runtime-signal", str(tmp_path / "rt.json")))
    assert rc.main() == 0


def test_unusable_config_fails_main(monkeypatch, tmp_path):
    bad = tmp_path / "cfg.json"
    bad.write_text("{}")
    monkeypatch.delenv("GITHUB_SHA", raising=False)
    monkeypatch.setattr(sys, "argv", _clean_argv("--runtime-signal", str(tmp_path / "rt.json"),
                                                 "--runtime-vv-config", str(bad)))
    assert rc.main() == 1


def test_nightly_runs_invariant_m():
    wf = (REPO / ".github" / "workflows" / "evidence-nightly.yml").read_text()
    step = wf[wf.index("- name: Reconciliation gate (fail closed on drift)"):]
    step = step[:step.index("\n    - name:")]
    assert "--runtime-signal ksi-signal-runtime.json" in step
    assert "continue-on-error" not in step
