"""The assessor guide (IVV-CSO-STE) and the sampling statement (IVV-CSO-DUS):
every rule and KSI, every piece of evidence with a command to reproduce it and
the same check in machine form, generated from the rule records."""
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _freshness  # noqa: E402
import _frr  # noqa: E402
import _rules  # noqa: E402

spec = importlib.util.spec_from_file_location("assessor_guide", REPO / "scripts" / "build-assessor-guide.py")
ag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ag)

FRESH = {x["path"]: x for x in _freshness.load_freshness_config(
    REPO / "infrastructure" / "schemas" / "freshness-config.json")["artifacts"]}
CATALOG = json.loads((REPO / "infrastructure" / "schemas" / "ksi-catalog.json").read_text())
NOW = datetime(2026, 11, 5, tzinfo=timezone.utc)


def _guide():
    return ag.build(_frr.load(_frr.DEFAULT_PATH), _rules.applicable_provider_rules(), CATALOG, FRESH, NOW, "abc")


def test_every_rule_and_ksi_is_in_the_guide_with_a_reproducible_check():
    g = _guide()
    assert {r["rule_id"] for r in g["rules"]} == set(_rules.applicable_provider_rules())
    ksis = {i["id"] for f in CATALOG["KSI"].values() for i in f["indicators"]}
    assert {k["ksi_id"] for k in g["ksis"]} == ksis
    for r in g["rules"]:
        assert r["statement"] and r["explanation"]
        for ev in r["evidence"]:
            assert ev["how_to_reproduce"] and set(ev["check"]) in ({"pytest"}, {"workflow", "step"}, {"artifact"}, {"decision"})


def test_signed_artifacts_name_the_identity_that_signed_them():
    g = _guide()
    checks = [ev["check"]["artifact"] for r in g["rules"] for ev in r["evidence"] if ev["kind"] == "artifact"]
    assert checks
    for c in checks:
        assert c["url"].startswith("https://samaydlette.com/.well-known/")
        assert all(i in g["identities"] for i in c["identities"])
    sim = ag._artifact_check(".well-known/simulated-assessment.json", FRESH)
    assert sim["identities"] == ["assessor"] and sim["bundle_url"]


def test_the_guide_states_that_no_samples_are_used():
    g = _guide()
    assert "No representative samples" in g["sampling"]
    assert "## Sampling (IVV-CSO-DUS)" in ag.render_markdown(g)


def test_known_bad_unknown_evidence_kind_fails():
    records = json.loads((REPO / "tests" / "fixtures" / "assessor-guide" / "unknown-evidence-kind.json").read_text())
    with pytest.raises(SystemExit, match="unknown evidence kind"):
        ag.build(records, _rules.applicable_provider_rules(), CATALOG, FRESH, NOW)


def test_an_artifact_outside_the_freshness_config_fails_closed():
    with pytest.raises(SystemExit, match="not in the freshness config"):
        ag.reproduce({"kind": "artifact", "ref": ".well-known/not-governed.json"}, FRESH)


def test_the_deploy_builds_the_guide_and_the_assessor_follows_it():
    deploy = (REPO / ".github" / "workflows" / "deploy-with-opa.yml").read_text()
    assessor = (REPO / ".github" / "workflows" / "simulated-assessor.yml").read_text()
    assert "- name: Build the assessor guide" in deploy
    assert "build-assessor-guide.py" in assessor and "assess.py --guide assessor-guide.json" in assessor
