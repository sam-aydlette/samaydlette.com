# Task 3 acceptance: builder.id derives from GITHUB_WORKFLOW_REF (the Fulcio SAN),
# never from GITHUB_WORKFLOW (the display name, with spaces); and the published
# verification hint pins the exact identity, not a workflow wildcard.

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ksi", REPO / "scripts" / "build-ksi-signal.py")
ksi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ksi)

WORKFLOW_REF = "sam-aydlette/samaydlette.com/.github/workflows/deploy-with-opa.yml@refs/heads/main"
EXPECTED_ID = "https://github.com/" + WORKFLOW_REF


def _env(monkeypatch, **extra):
    for k in ("GITHUB_REPOSITORY", "GITHUB_WORKFLOW", "GITHUB_WORKFLOW_REF",
              "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_REF", "KSI_SIGN"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("GITHUB_REPOSITORY", "sam-aydlette/samaydlette.com")
    monkeypatch.setenv("GITHUB_SHA", "abc123")
    monkeypatch.setenv("GITHUB_WORKFLOW_REF", WORKFLOW_REF)
    for k, v in extra.items():
        monkeypatch.setenv(k, v)


def test_builder_id_from_workflow_ref(monkeypatch):
    _env(monkeypatch)
    prov = ksi.build_provenance()
    assert prov["builder"]["id"] == EXPECTED_ID
    assert " " not in prov["builder"]["id"]


def test_display_name_not_used(monkeypatch):
    # Even if GITHUB_WORKFLOW (spaced display name) is present, it must be ignored.
    _env(monkeypatch, GITHUB_WORKFLOW="Deploy Website with OPA Compliance")
    prov = ksi.build_provenance()
    assert prov["builder"]["id"] == EXPECTED_ID
    assert "Deploy Website" not in prov["builder"]["id"]


def test_attestation_pins_exact_identity_no_wildcard(monkeypatch):
    _env(monkeypatch, KSI_SIGN="1")
    prov = ksi.build_provenance()
    verif = prov["attestation"]["verification"]
    assert verif.get("certificate_identity") == EXPECTED_ID
    # no wildcard regexp field, and no ".+"
    assert "certificate_identity_regexp" not in verif
    assert ".+" not in str(verif.get("certificate_identity", ""))


def test_local_fallback_when_no_workflow_ref(monkeypatch):
    for k in ("GITHUB_REPOSITORY", "GITHUB_WORKFLOW", "GITHUB_WORKFLOW_REF",
              "GITHUB_SHA", "KSI_SIGN"):
        monkeypatch.delenv(k, raising=False)
    prov = ksi.build_provenance()
    assert prov["builder"]["id"] == "local"
