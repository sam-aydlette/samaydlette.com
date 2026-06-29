"""Tests for scripts/build-provenance.py (Task 14 / S2).

Verifies the SLSA v1 provenance predicate binds an artifact to the canonical
inventory's content hash + signal_id, the generator, the commit, and the run;
that the inventory/generator digests are the real sha256 of the bytes (so the
binding cannot be forged without changing the digest); and that builder.id is
the single-sourced pinned identity from build-ksi-signal.py's build_provenance()
(GITHUB_WORKFLOW_REF, the Fulcio SAN - never a wildcard or the display name).
"""
import hashlib
import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "build_provenance", REPO / "scripts" / "build-provenance.py"
)
bp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bp)

WORKFLOW_REF = "sam-aydlette/samaydlette.com/.github/workflows/deploy-with-opa.yml@refs/heads/main"
EXPECTED_BUILDER = "https://github.com/" + WORKFLOW_REF


def _ci_env(monkeypatch):
    for k in ("GITHUB_REPOSITORY", "GITHUB_WORKFLOW", "GITHUB_WORKFLOW_REF",
              "GITHUB_RUN_ID", "GITHUB_SHA", "GITHUB_REF", "KSI_SIGN"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("GITHUB_REPOSITORY", "sam-aydlette/samaydlette.com")
    monkeypatch.setenv("GITHUB_WORKFLOW_REF", WORKFLOW_REF)
    monkeypatch.setenv("GITHUB_RUN_ID", "42")
    monkeypatch.setenv("GITHUB_SHA", "deadbeef")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")


def _signal(tmp_path):
    p = tmp_path / "ksi-signal.json"
    p.write_text(json.dumps({"signal_id": "test-uuid-1234", "components": []}))
    return p


def _deps(pred):
    return {d.get("annotations", {}).get("role") or "src": d
            for d in pred["buildDefinition"]["resolvedDependencies"]}


def test_predicate_structure_and_bindings(tmp_path, monkeypatch):
    _ci_env(monkeypatch)
    sig = _signal(tmp_path)
    gen = REPO / "scripts" / "build-oscal-ssp.py"
    pred = bp.build_predicate(str(sig), str(gen))

    assert set(pred) == {"buildDefinition", "runDetails"}
    assert pred["buildDefinition"]["buildType"].startswith("https://")
    deps = _deps(pred)

    # commit binding comes through build_provenance() -> GITHUB_SHA
    assert deps["src"]["digest"]["gitCommit"] == "deadbeef"
    # inventory digest is the REAL sha256 of the bytes
    assert deps["canonical-inventory"]["digest"]["sha256"] == hashlib.sha256(sig.read_bytes()).hexdigest()
    assert deps["canonical-inventory"]["annotations"]["signal_id"] == "test-uuid-1234"
    assert pred["buildDefinition"]["internalParameters"]["inventory_signal_id"] == "test-uuid-1234"
    # generator digest is the real sha256 of the generator file
    assert deps["generator"]["uri"] == "scripts/build-oscal-ssp.py"
    assert deps["generator"]["digest"]["sha256"] == hashlib.sha256(gen.read_bytes()).hexdigest()


def test_builder_id_single_sourced_and_pinned(tmp_path, monkeypatch):
    _ci_env(monkeypatch)
    sig = _signal(tmp_path)
    pred = bp.build_predicate(str(sig), str(REPO / "scripts" / "build-iiw.py"))
    bid = pred["runDetails"]["builder"]["id"]
    assert bid == EXPECTED_BUILDER          # derived from WORKFLOW_REF, not hardcoded drift
    assert " " not in bid                   # never the spaced display name
    assert not bid.endswith("@*")           # never a wildcard ref
    assert "/actions/runs/42" in pred["runDetails"]["metadata"]["invocationId"]
