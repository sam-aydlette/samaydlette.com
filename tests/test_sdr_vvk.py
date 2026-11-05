"""FRC-CSX-VVK: the automated methods the SDR counts per KSI. Beyond the plan
gate and the runtime re-validation: dependency vulnerability scanning for a KSI
with npm or PyPI package components (only when the bound VDR verifies and is
fresh), and for KSI-CED-RAT the check of the operator's training attestation.
A KSI short of two methods without an in-force accepted decision fails the
build when --require-two-methods is given (the package maintainer)."""
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _controls  # noqa: E402
import _decisions  # noqa: E402
import _frr  # noqa: E402
import _rules  # noqa: E402

spec = importlib.util.spec_from_file_location("build_sdr_vvk", REPO / "scripts" / "build-sdr.py")
sdr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sdr)

FIX = REPO / "tests" / "fixtures" / "vvk"
CATALOG = json.loads((REPO / "infrastructure" / "schemas" / "ksi-catalog.json").read_text())
NOW = datetime(2026, 11, 5, 12, tzinfo=timezone.utc)
SIGNED = (True, None)
PKG = "pkg:npm/left-pad@1.3.0"


def _vdr(name="vdr-good.json"):
    return json.loads((FIX / name).read_text())


def _signal():
    """Every KSI validated against the plan over a function; the SCR KSIs over
    an npm package only (no runtime reaches a package); KSI-CED-RAT over
    nothing, evidenced by documentation."""
    comps = [{"component_id": "aws::function::app", "type": "function"},
             {"component_id": PKG, "type": "npm_package"}]
    ksis = []
    for f in CATALOG["KSI"].values():
        for i in f["indicators"]:
            refs = {"KSI-SCR-MIT": [PKG], "KSI-SCR-MON": [PKG], "KSI-CED-RAT": []}.get(i["id"],
                                                                                    ["aws::function::app"])
            doc = i["id"] == "KSI-CED-RAT"
            ksis.append({"id": i["id"], "status": "pass", "method": "documentation" if doc else "policy-validation",
                         "evidence": {"validation_ids": [] if doc else ["v-1"], "failed_validation_ids": [],
                                      "component_refs": refs}})
    return {"signal_id": "sig-1", "components": comps, "ksis": ksis}


RUNTIME = [{"validation_id": "r-1", "component_refs": ["aws::function::app"], "result": "pass"}]


def _build(dep_scan, training, accepted):
    sig = _signal()
    return sdr.build(CATALOG, sig, _frr.load(), _rules.applicable_provider_rules(), _controls.project(sig, CATALOG),
                     sdr.moderate_ids(), {}, RUNTIME, None, [], {"fedramp_class": "C", "impact_level": "Moderate"},
                     {}, {}, NOW, {"ac": "https://example.invalid/ac.md"},
                     dep_scan=dep_scan, training=training, accepted=accepted)


def _methods(doc):
    return {k["ksiId"]: k["providerExtensions"]["automatedMethods"] for k in doc["keySecurityIndicators"]}


# --- dependency scanning ------------------------------------------------------------------

def test_a_bound_signed_fresh_vdr_with_passing_grype_scans_counts():
    assert sdr.dependency_scan(_vdr(), _signal(), NOW, SIGNED, 24) == (True, None)


@pytest.mark.parametrize("fixture,signature,reason", [
    ("vdr-unbound.json", SIGNED, "not bound to this inventory"),
    ("vdr-stale.json", SIGNED, "not within its 24-hour window"),
    ("vdr-grype-failed.json", SIGNED, "a Grype dependency scan failed the detection gate"),
    ("vdr-no-grype.json", SIGNED, "lists no Grype dependency scan"),
    ("vdr-good.json", (False, "the VDR signature does not verify against the allowed identities"), "does not verify"),
])
def test_known_bad_vdrs_do_not_count_each_for_its_reason(fixture, signature, reason):
    ok, why = sdr.dependency_scan(_vdr(fixture), _signal(), NOW, signature, 24)
    assert not ok and reason in why


def test_the_vdr_signature_is_checked_against_the_allowed_identities(tmp_path):
    (tmp_path / "v.json").write_text("{}")
    (tmp_path / "v.bundle").write_text("{}")
    seen = []

    def verifier(path, bundle, ids):
        seen.append(list(ids))
        return False
    assert sdr.vdr_signature(tmp_path / "v.json", tmp_path / "v.bundle", ["id-a", "id-b"], verifier)[0] is False
    assert seen == [["id-a", "id-b"]]
    assert sdr.vdr_signature(tmp_path / "v.json", tmp_path / "v.bundle", ["id-a"], lambda *_a: True) == SIGNED
    assert sdr.vdr_signature(tmp_path / "v.json", None, ["id-a"])[0] is False


def test_dependency_scanning_counts_only_for_ksis_with_package_components():
    with_scan = _methods(_build(SIGNED, (False, "x"), {}))
    without = _methods(_build((False, "unsigned"), (False, "x"), {}))
    assert with_scan["KSI-SCR-MIT"] == with_scan["KSI-SCR-MON"] == 2
    assert without["KSI-SCR-MIT"] == without["KSI-SCR-MON"] == 1
    assert with_scan["KSI-SVC-VRI"] == without["KSI-SVC-VRI"] == 2  # no package component: plan + runtime


# --- the training attestation (KSI-CED-RAT) ---------------------------------------------

def test_the_committed_training_attestation_counts():
    assert sdr.training_attestation(_decisions.load(), NOW) == (True, None)


@pytest.mark.parametrize("fixture,reason", [
    ("decisions-training-too-old.json", "not decided within the last 365 days"),
    ("decisions-no-acceptance.json", "no training attestation (DEC-192)"),
])
def test_known_bad_training_attestations_do_not_count(fixture, reason):
    ok, why = sdr.training_attestation(_decisions.load(FIX / fixture), NOW)
    assert not ok and reason in why


def test_a_lapsed_training_attestation_does_not_count():
    reg = _decisions.load()
    assert sdr.training_attestation(reg, datetime(2027, 11, 6, tzinfo=timezone.utc))[0] is False


# --- shortfalls -----------------------------------------------------------------------------

def test_with_the_committed_register_every_ksi_has_two_methods_or_an_accepted_finding():
    reg = _decisions.load()
    accepted = sdr.vvk_acceptances(reg, NOW)
    assert accepted == {"KSI-CED-RAT": "DEC-191"}
    doc = _build(SIGNED, sdr.training_attestation(reg, NOW), accepted)
    m = _methods(doc)
    assert m["KSI-CED-RAT"] == 1 and all(v >= 2 for k, v in m.items() if k != "KSI-CED-RAT")
    assert sdr.vvk_shortfalls(doc) == []
    rat = next(k for k in doc["keySecurityIndicators"] if k["ksiId"] == "KSI-CED-RAT")
    assert rat["providerExtensions"]["fewerMethodsAccepted"] == "DEC-191"
    assert any("accepted finding: DEC-191" in line for line in rat["ksiValidation"])
    assert any("Training attestation check: the operator's training attestation (DEC-192)" in line
               for line in rat["ksiValidation"])


def test_known_bad_without_the_acceptance_ksi_ced_rat_is_a_shortfall():
    reg = _decisions.load(FIX / "decisions-no-acceptance.json")
    doc = _build(SIGNED, sdr.training_attestation(reg, NOW), sdr.vvk_acceptances(reg, NOW))
    short = sdr.vvk_shortfalls(doc)
    assert len(short) == 1 and short[0].startswith("KSI-CED-RAT: 0 automated method(s)")


def test_an_unsigned_vdr_leaves_the_supply_chain_ksis_short():
    reg = _decisions.load()
    doc = _build((False, "unsigned"), sdr.training_attestation(reg, NOW), sdr.vvk_acceptances(reg, NOW))
    assert sorted(s.split(":")[0] for s in sdr.vvk_shortfalls(doc)) == ["KSI-SCR-MIT", "KSI-SCR-MON"]


def test_the_package_maintainer_requires_two_methods_and_the_deploy_supplies_the_vdr_signature():
    wf = REPO / ".github" / "workflows"
    maint = (wf / "package-maintenance.yml").read_text()
    assert "--require-two-methods" in maint and "--vdr-bundle vdr-report.bundle" in maint
    deploy = (wf / "deploy-with-opa.yml").read_text()
    step = deploy[deploy.index("- name: Build Security Decision Record"):]
    step = step[:step.index("- name:", 10)]
    assert "--vdr-bundle vdr-report.bundle" in step
    assert deploy.index("- name: Sign VDR Report") < deploy.index("- name: Build Security Decision Record")
    deploy_jobs = deploy.split("\n  package-maintainer:\n", 1)[1]
    assert "needs: [deploy]" in deploy_jobs.split("\n\n", 1)[0] or "needs: [deploy]" in deploy_jobs[:400]
