"""The KSI catalog is FedRAMP's: IDs, names, Class C statements and KSI->control
mappings equal the pinned Consolidated Rules (scripts/sync-ksi-catalog.py)."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("sync_ksi", REPO / "scripts" / "sync-ksi-catalog.py")
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)
BEFORE = REPO / "tests" / "fixtures" / "migration" / "ksi-catalog-2026-11-05.json"


def _catalog():
    return json.loads(sync.CATALOG.read_text())


def test_the_committed_catalog_equals_the_pinned_rules():
    assert sync.main(["--check"]) == 0


def test_a_mapping_that_drifts_from_the_rules_fails():
    """Known-bad: the catalog as committed before FedRAMP's 2026-10-13 mapping
    revision was carried (40 of 46 KSIs differ)."""
    stale = json.loads(BEFORE.read_text())
    assert sync.derive(stale) != stale


def test_a_dropped_control_is_detected():
    cat = _catalog()
    bad = copy.deepcopy(cat)
    bad["KSI"]["CED"]["indicators"][0]["controls"].pop()
    assert sync.derive(bad) != bad


def test_class_c_statements_are_used_where_a_ksi_varies_by_class():
    by_id = {i["id"]: i for f in _catalog()["KSI"].values() for i in f["indicators"]}
    assert len(by_id) == 46
    assert not by_id["KSI-CNA-EIS"]["statement"].startswith("**Optional:**")


def test_a_control_outside_the_nist_catalog_fails_closed(monkeypatch):
    monkeypatch.setattr(sync, "_titles", lambda: {})
    with pytest.raises(SystemExit, match="not in the NIST SP 800-53 Rev5 catalog"):
        sync.derive(_catalog())


def test_a_new_ksi_needs_its_impact_set_first():
    cat = _catalog()
    for f in cat["KSI"].values():
        f["indicators"] = [i for i in f["indicators"] if i["id"] != "KSI-CED-RAT"]
    with pytest.raises(SystemExit, match="KSI-CED-RAT is new in the corpus"):
        sync.derive(cat)
