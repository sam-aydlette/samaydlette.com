"""KSI scope cuts (data/ksi-applicability.json): a KSI that does not apply is
recorded with why, who proposed it and the operator's approval, left out of
the inventory's results and the method count, and published with its reason."""

import copy
import importlib.util
import json
import sys
from pathlib import Path

import jsonschema
import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _frr  # noqa: E402
import _ksi_applicability as ka  # noqa: E402

FIX = json.loads((REPO / "tests" / "fixtures" / "ksi-applicability" / "known-bad.json").read_text())
KNOWN = ka.catalog_ids()


def _doc(entries):
    return {"schema": "ksi-applicability/1", "ksis": entries}


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, REPO / path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_the_committed_scope_cut_is_ksi_svc_rud_approved_by_the_operator():
    doc = ka.load()
    na = ka.not_applicable(doc)
    assert set(na) == {"KSI-SVC-RUD"}
    assert na["KSI-SVC-RUD"]["approval"] == {"by": _frr.OPERATOR, "on": "2026-11-06"}
    assert ka.claims(doc) == []


def test_the_committed_file_matches_its_schema():
    schema = json.loads((REPO / "infrastructure" / "schemas" / "ksi-applicability.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(json.loads(ka.DEFAULT_PATH.read_text()), schema)


@pytest.mark.parametrize("case", FIX["cases"], ids=[c["case"] for c in FIX["cases"]])
def test_known_bad_entries_fail(case):
    with pytest.raises(SystemExit) as exc:
        ka.validate(_doc(case["entries"]), KNOWN)
    assert case["expect"] in str(exc.value)


@pytest.mark.parametrize("case", FIX["claims_cases"], ids=[c["case"] for c in FIX["claims_cases"]])
def test_known_bad_an_unapproved_scope_cut_fails_the_claim_check(case, tmp_path):
    doc = ka.validate(_doc(case["entries"]), KNOWN)
    assert [why for _, why in ka.claims(doc)] == [case["expect"]]
    p = tmp_path / "ka.json"
    p.write_text(json.dumps(doc))
    # The deploy gate holds KSI scope cuts to the same rule as rule records:
    # with every rule record supported, the unapproved KSI alone stops it.
    import test_frr_records as tfr
    recs = tmp_path / "frr.json"
    recs.write_text(json.dumps(tfr._supported_doc()))
    assert _frr.main(["--records", str(recs), "--ksi-applicability", str(p), "--claims"]) == 1
    assert _frr.main(["--records", str(recs), "--ksi-applicability", str(ka.DEFAULT_PATH), "--claims"]) == 0


def test_a_not_applicable_ksi_is_left_out_of_the_inventory_results():
    sig = _module("bks_ka", "scripts/build-ksi-signal.py")
    catalog = json.loads(ka.CATALOG_PATH.read_text())
    out = sig.build_ksi_statuses(catalog, [], [], not_applicable={"KSI-SVC-RUD"})
    ids = {k["id"] for k in out}
    assert "KSI-SVC-RUD" not in ids
    assert ids == {k["id"] for k in sig.build_ksi_statuses(catalog, [], [])} - {"KSI-SVC-RUD"}


def test_a_not_applicable_ksi_is_left_out_of_the_assessor_guide():
    guide = _module("bag_ka", "scripts/build-assessor-guide.py")
    import _freshness
    import _rules
    from datetime import datetime, timezone
    catalog = json.loads(ka.CATALOG_PATH.read_text())
    args = (_frr.load(), _rules.applicable_provider_rules(), catalog, {x["path"]: x for x in _freshness.load_freshness_config()["artifacts"]},
            datetime(2026, 11, 5, 12, tzinfo=timezone.utc))
    full = {k["ksi_id"] for k in guide.build(*args)["ksis"]}
    cut = {k["ksi_id"] for k in guide.build(*args, not_applicable={"KSI-SVC-RUD"})["ksis"]}
    assert "KSI-SVC-RUD" in full and cut == full - {"KSI-SVC-RUD"}


def test_the_sdr_publishes_the_scope_cut_without_an_official_status():
    sdr = _module("bsdr_ka", "scripts/build-sdr.py")
    import _controls
    import _rules
    from datetime import datetime, timezone
    catalog = json.loads(ka.CATALOG_PATH.read_text())
    s = json.loads((REPO / "tests" / "fixtures" / "clean" / "ksi-signal.json").read_text())
    s["ksis"] = [{"id": i["id"], "status": "pass", "method": "policy-validation", "evidence": {}}
                 for f in catalog["KSI"].values() for i in f["indicators"] if i["id"] != "KSI-SVC-RUD"]
    na = ka.not_applicable(ka.load())
    doc = sdr.build(catalog, s, _frr.load(), _rules.applicable_provider_rules(), _controls.project(s, catalog),
                    sdr.moderate_ids(), {}, [], "none supplied", [], {"fedramp_class": "C", "impact_level": "Moderate"},
                    {}, {}, datetime(2026, 11, 5, 12, tzinfo=timezone.utc), {}, not_applicable=na)
    k = next(x for x in doc["keySecurityIndicators"] if x["ksiId"] == "KSI-SVC-RUD")
    assert "ksiImplementationStatus" not in k
    assert k["providerExtensions"]["status"] == "Not Applicable"
    assert k["providerExtensions"]["approval"]["by"] == _frr.OPERATOR
    assert "KSI-SVC-RUD" not in " ".join(sdr.vvk_shortfalls(doc))
    with pytest.raises(SystemExit, match="no result for KSI-SVC-RUD"):
        sdr.build(catalog, s, _frr.load(), _rules.applicable_provider_rules(), _controls.project(s, catalog),
                  sdr.moderate_ids(), {}, [], "none supplied", [], {"fedramp_class": "C", "impact_level": "Moderate"},
                  {}, {}, datetime(2026, 11, 5, 12, tzinfo=timezone.utc), {}, not_applicable={})
    assert copy.deepcopy(k)  # published as-is
