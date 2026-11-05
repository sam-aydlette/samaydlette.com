"""The FedRAMP rule records (SDR-CSO-FRR): one per applicable rule, and none
claims more than the repository shows."""

import copy
import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import jsonschema
import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _frr  # noqa: E402
import _rules  # noqa: E402

RECORDS = REPO / "data" / "frr-records.json"
KNOWN_BAD = json.loads((REPO / "tests" / "fixtures" / "frr" / "known-bad.json").read_text())["cases"]

# The 20x-specific rules a first assessment missed; the corpus metadata includes them.
CSX = {"SDR-CSX-KSI", "SDR-CSX-KMT", "CPO-CSX-CPM", "FRC-CSX-VVK", "FRC-CSX-VVR", "FRC-CSX-MAS", "IVV-CSX-AIA"}


@pytest.fixture(scope="module")
def applicable():
    return _rules.applicable_provider_rules()


@pytest.fixture(scope="module")
def resolve():
    return _frr.resolver()


def _committed():
    return json.loads(RECORDS.read_text())


# --- which rules apply -------------------------------------------------------------

def test_applicable_rules_come_from_the_corpus_metadata(applicable):
    assert len(applicable) == 154
    assert CSX <= set(applicable)
    # Rev5 agency path, Class A only, and the Initial Implementation Phase (no class) are out.
    for rid in ("FRC-APS-ATO", "FRC-CLA-ASF", "MKT-IIP-AGU", "FRC-CCL-UCC"):
        assert rid not in applicable
    # Only rules that bind providers.
    assert "AFC-FRP-VRE" not in applicable
    # Class C's own force and statement are used where the rule varies by class.
    assert applicable["FRC-CSX-VVK"]["force"] == "MUST"
    assert "at least 2 automated methods" in applicable["FRC-CSX-VVK"]["statement"]
    assert applicable["FRC-CSX-VVR"]["force"] == "SHOULD"


def _corpus_copy(tmp_path, mutate):
    """A copy of the pinned corpus with one change and a SOURCES.json that
    matches it, so the hash check passes and the change itself is what's tested."""
    d = tmp_path / "rules"
    shutil.copytree(_rules.RULES_DIR, d)
    corpus = json.loads((d / _rules.RULES_FILE).read_text())
    mutate(corpus)
    raw = json.dumps(corpus).encode()
    (d / _rules.RULES_FILE).write_bytes(raw)
    src = json.loads((d / "SOURCES.json").read_text())
    src["sha256"] = hashlib.sha256(raw).hexdigest()
    (d / "SOURCES.json").write_text(json.dumps(src))
    return d


def test_a_subset_without_applicability_metadata_fails_closed(tmp_path):
    def strip(c):
        del c["FRR"]["AFC"]["info"]["subsets"]["CSO"]["applicability"]
    with pytest.raises(SystemExit, match="FRR/AFC/all/CSO has no applicability metadata"):
        _rules.applicable_provider_rules(_corpus_copy(tmp_path, strip))


def test_a_rule_added_to_the_corpus_needs_a_record(tmp_path):
    def add(c):
        c["FRR"]["AFC"]["data"]["all"]["CSO"]["AFC-CSO-NEW"] = {
            "name": "New", "statement": "Providers MUST do something new.", "force": "MUST",
            "affects": ["Providers"], "updated": []}
    rules_dir = _corpus_copy(tmp_path, add)
    with pytest.raises(SystemExit, match="no record for 1 applicable rule.*AFC-CSO-NEW"):
        _frr.load(RECORDS, rules_dir=rules_dir)


# --- the committed records ---------------------------------------------------------

def test_the_committed_records_are_valid(applicable):
    doc = _frr.load()
    assert {r["frr_id"] for r in doc["records"]} == set(applicable)


def test_the_committed_records_match_their_schema():
    schema = json.loads(_frr.SCHEMA_PATH.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(_committed(), schema)


def test_every_implemented_record_cites_evidence_that_resolves(resolve):
    implemented = [r for r in _committed()["records"] if r["status"] == "Implemented"]
    assert implemented
    for r in implemented:
        assert r["evidence"]
        assert all(resolve(ev) is None for ev in r["evidence"]), r["frr_id"]


def test_summary_counts_add_up(applicable):
    s = _frr.summary(_committed(), applicable)
    assert s["rules"] == 154 == sum(s["by_status"].values())
    assert sum(sum(c.values()) for c in s["by_force"].values()) == 154
    assert s["optional_not_exercised"] == sum(
        1 for r in _committed()["records"] if r.get("closes_with") == ["optional"])


# --- known-bad: each invariant fails for its own reason ----------------------------

def _apply(case):
    doc = copy.deepcopy(_committed())
    recs = doc["records"]
    if "drop" in case:
        doc["records"] = [r for r in recs if r["frr_id"] != case["drop"]]
    if "add" in case:
        recs.append(case["add"])
    if "replace" in case:
        rid = case["replace"]["frr_id"]
        doc["records"] = [case["replace"] if r["frr_id"] == rid else r for r in recs]
    return doc


@pytest.mark.parametrize("case", KNOWN_BAD, ids=[c["case"] for c in KNOWN_BAD])
def test_known_bad_records_fail(case, applicable, resolve):
    with pytest.raises(SystemExit) as exc:
        _frr.validate(_apply(case), applicable, resolve)
    assert case["expect"] in str(exc.value)


def test_known_bad_fixture_covers_every_check():
    """A new invariant in _frr.validate needs a known-bad case here."""
    expects = " ".join(c["expect"] for c in KNOWN_BAD)
    for fragment in ("no record for", "is not a rule that applies", "duplicate record",
                     "Implemented needs evidence", "names no test function", "does not exist",
                     "no step named", "freshness-governed", "in-force decision", "has no gap",
                     "gap must be", "closes_with must be", "only a MAY rule", "is not one of",
                     "unknown field", "AWS account ID", "email address outside"):
        assert fragment in expects, fragment


# --- evidence resolution -----------------------------------------------------------

@pytest.mark.parametrize("ref,ok", [
    ("tests/test_frr_records.py::test_summary_counts_add_up", True),
    ("tests/test_frr_records.py::test_known_bad_records_fail[missing record]", True),
    ("tests/test_frr_records.py::_committed", False),           # not a test
    ("tests/test_frr_records.py::applicable", False),           # a fixture
    ("tests/../scripts/_frr.py::main", False),                  # path escape
    ("tests/test_frr_records.py", False),
])
def test_test_references(ref, ok, resolve):
    assert (resolve({"kind": "test", "ref": ref}) is None) is ok


def test_test_methods_in_a_class_resolve(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_k.py").write_text("class TestK:\n    def test_m(self):\n        pass\n")
    assert _frr._resolve_test("tests/test_k.py::TestK::test_m", tmp_path) is None
    assert _frr._resolve_test("tests/test_k.py::TestK::test_n", tmp_path) is not None
    assert _frr._resolve_test("tests/test_k.py::test_m", tmp_path) is not None


@pytest.mark.parametrize("ref,ok", [
    ("deploy-with-opa.yml#Run OPA Compliance Check", True),
    ("deploy-with-opa.yml#Build VDR Report (FedRAMP 20x Class C)", True),
    ("deploy-with-opa.yml#Run OPA Compliance", False),          # a prefix is not a step
    ("nope.yml#Run OPA Compliance Check", False),
    ("../deploy-with-opa.yml#Run OPA Compliance Check", False),
])
def test_step_references(ref, ok, resolve):
    assert (resolve({"kind": "step", "ref": ref}) is None) is ok


def test_cli_prints_the_summary():
    spec = importlib.util.spec_from_file_location("frr_cli", REPO / "scripts" / "_frr.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    assert m.main(["--records", str(RECORDS)]) == 0


def test_the_system_and_fedramp_addresses_are_allowed(applicable, resolve):
    doc = copy.deepcopy(_committed())
    for r in doc["records"]:
        if r["frr_id"] == "AFC-CSO-ACK":
            r["gap"] = "Acknowledge mail from x@fedramp.gov and x@gsa.gov at fedramp-security@samaydlette.com."
    _frr.validate(doc, applicable, resolve)
