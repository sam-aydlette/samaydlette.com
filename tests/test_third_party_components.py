"""Third-party resources are inventory components with upstream identity (REQ-TPR-1).

Each external service names the upstream offering, the upstream component's
identifier, and the split between what the upstream runs and what the provider
configures. Values come from a governed record with a decision; a value without
a decision is published as "not recorded", never invented.
"""
import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "third-party"
spec = importlib.util.spec_from_file_location("bks", REPO / "scripts" / "build-ksi-signal.py")
bks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bks)

FIELDS = ("upstream_offering", "upstream_component_id", "responsibility_split")


def _ext(path):
    return {c["component_id"]: c for c in bks.build_external_components(path)}


def test_every_external_component_publishes_the_tpr1_fields():
    for cid, c in _ext(bks.THIRD_PARTY_PATH).items():
        for f in FIELDS:
            assert f in c["attributes"], (cid, f)
        assert "third_party_record" in c["attributes"], cid


def test_decided_record_is_published():
    c = _ext(FIX / "decided.json")["ext::cisa-kev"]["attributes"]
    assert c["upstream_offering"] == "CISA Known Exploited Vulnerabilities catalog (JSON feed)"
    assert c["upstream_component_id"].startswith("https://www.cisa.gov/")
    assert c["responsibility_split"]["upstream_runs"]
    assert c["responsibility_split"]["provider_configures"]
    assert c["third_party_record"]["decided_by"] == "Operator"


def test_undecided_record_is_not_recorded_not_invented():
    c = _ext(FIX / "undecided.json")["ext::cisa-kev"]["attributes"]
    for f in FIELDS:
        assert c[f] == "not recorded"
    assert c["third_party_record"]["status"] == "drafted; no decision recorded"


def test_component_missing_from_the_record_is_not_recorded():
    c = _ext(FIX / "decided.json")["ext::sigstore-fulcio"]["attributes"]
    assert c["upstream_component_id"] == "not recorded"
    assert c["third_party_record"]["status"] == "no record"


def test_record_for_an_unknown_component_fails_closed():
    with pytest.raises(SystemExit):
        bks.build_external_components(FIX / "unknown-component.json")


def test_malformed_record_fails_closed():
    with pytest.raises(SystemExit):
        bks.build_external_components(FIX / "malformed.json")


def test_committed_record_loads_and_drafts_name_their_evidence():
    doc = json.loads(bks.THIRD_PARTY_PATH.read_text())
    for cid, rec in doc["components"].items():
        assert rec.get("evidence"), cid
