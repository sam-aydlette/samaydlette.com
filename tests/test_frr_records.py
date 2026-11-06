"""The FedRAMP rule records (SDR-CSO-FRR): one per applicable rule, and none
claims more than the repository shows."""

import copy
import hashlib
import importlib.util
import json
import re
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
                     "Implemented needs evidence", "Simulated needs evidence", "names no test function",
                     "does not exist", "no step named", "freshness-governed", "in-force decision", "is not one of",
                     "not_applicable must be", "for Not Applicable records only", "not_demonstrated must be",
                     "for Not Demonstrated records only", "unknown field", "AWS account ID", "email address outside",
                     "may_rationale must be", "for MAY rules only", "simulated is for Simulated records only",
                     "simulated must be {counterparty", "needs deploy-time evidence",
                     "stand_in_proof is for Simulated records only", "stand_in_proof must be {bad_input",
                     "approval is for", "approval.by must be the operator", "must be a date", "must be {by, on}"):
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
            r["implementation"] = "Acknowledge mail from x@fedramp.gov and x@gsa.gov at fedramp-security@samaydlette.com."
    _frr.validate(doc, applicable, resolve)


def test_every_may_rule_says_why(applicable):
    for r in _committed()["records"]:
        assert ("may_rationale" in r) is (applicable[r["frr_id"]]["force"] == "MAY"), r["frr_id"]


def test_not_applicable_is_no_longer_limited_to_conditional_subsets(applicable, resolve):
    """The operator approves each scope cut (CLAUDE.md, proof-of-concept
    latitude), so a reasoned Not Applicable on a MUST rule loads; it then
    waits on the claim check for his approval."""
    doc = _doc_with("AFC-CSO-INB", status="Not Applicable", implementation="x", not_applicable="No mail is expected.",
                    proposal={"by": "Claude (AI agent), for the operator's review", "on": "2026-11-06"})
    _frr.validate(doc, applicable, resolve)
    assert ("AFC-CSO-INB", "Not Applicable not approved by the operator (Sam Aydlette)") in _frr.claims(doc, resolve)


# --- the claim check (the deploy gate) ----------------------------------------------

CLAIMS_BAD = json.loads((REPO / "tests" / "fixtures" / "frr" / "claims-known-bad.json").read_text())["cases"]
OPERATOR_SIGNOFF = {"by": _frr.OPERATOR, "on": "2026-11-06"}  # test data, not the operator's decision


def _doc_with(rid, **fields):
    doc = copy.deepcopy(_committed())
    for r in doc["records"]:
        if r["frr_id"] == rid:
            r.clear()
            r.update({"frr_id": rid, **fields})
    return doc


def _supported_doc():
    """The committed records with every claim made supportable in test data:
    each Simulated record says what is real and what stands in and cites a
    stand-in proof on a test that exists, and every record that needs the
    operator's approval carries one. The committed records carry none."""
    test = "tests/test_frr_records.py::test_summary_counts_add_up"
    doc = copy.deepcopy(_committed())
    for r in doc["records"]:
        if r["status"] == "Simulated":
            r["simulated"] = {"real": "x", "stand_in": "x", **r["simulated"]}
            r["stand_in_proof"] = {"bad_input": test, "replaceable": {"statement": "x", "test": test}}
        if r["status"] in _frr.NEEDS_APPROVAL:
            r["approval"] = dict(OPERATOR_SIGNOFF)
    return doc


def _claim_problems(doc, applicable, resolve):
    _frr.validate(doc, applicable, resolve)
    return _frr.claims(doc, resolve)


def test_a_supported_record_set_has_no_unsupported_claim(applicable, resolve):
    assert _claim_problems(_supported_doc(), applicable, resolve) == []


@pytest.mark.parametrize("case", CLAIMS_BAD, ids=[c["case"] for c in CLAIMS_BAD])
def test_known_bad_claims_fail(case, applicable, resolve):
    doc = _supported_doc()
    rid = case["replace"]["frr_id"]
    doc["records"] = [case["replace"] if r["frr_id"] == rid else r for r in doc["records"]]
    if case["stage"] == "load":
        with pytest.raises(SystemExit) as exc:
            _frr.validate(doc, applicable, resolve)
        assert case["expect"] in str(exc.value)
    else:
        problems = _claim_problems(doc, applicable, resolve)
        assert any(f"{r}: {why}".startswith(case["expect"]) for r, why in problems), problems
        assert {r for r, _ in problems} == {rid}


def test_claims_known_bad_fixture_covers_every_check():
    """A new reason in _frr.claims needs a known-bad case."""
    expects = " ".join(c["expect"] for c in CLAIMS_BAD)
    for fragment in ("Implemented with a simulated block", "Simulated without stand_in_proof",
                     "stand_in_proof bad_input test", "stand_in_proof replaceable test",
                     "Simulated not approved", "Simulated without a proposal", "Simulated without saying",
                     "Simulated without a simulated block", "not_applicable must be", "Not Applicable not approved",
                     "replaceable: statement must be a non-empty string",
                     "Not Demonstrated but cites evidence", "Not Demonstrated not approved"):
        assert fragment in expects, fragment


def _write(tmp_path, doc):
    p = tmp_path / "frr.json"
    p.write_text(json.dumps(doc))
    return p


def test_a_replaceability_statement_needs_no_test(applicable, resolve):
    """How a real input would replace the stand-in is a required statement;
    a test that shows it is cited where one exists, and is not required."""
    doc = _supported_doc()
    rec = next(r for r in doc["records"] if r["frr_id"] == "AFC-CSO-INB")
    rec["stand_in_proof"]["replaceable"] = {"statement": "Real mail would arrive through SES receipt; the "
                                                         "simulation step would be removed."}
    assert _claim_problems(doc, applicable, resolve) == []


def test_an_unsupported_claim_keeps_the_deploy_from_proceeding(tmp_path, applicable, resolve):
    doc = _supported_doc()
    rec = next(r for r in doc["records"] if r["frr_id"] == "AFC-CSO-INB")
    rec.pop("approval", None)
    assert rec["status"] == "Simulated"
    assert _claim_problems(doc, applicable, resolve) == [
        ("AFC-CSO-INB", "Simulated not approved by the operator (Sam Aydlette)")]
    assert _frr.main(["--records", str(_write(tmp_path, doc)), "--claims"]) == 1


def test_an_honest_status_never_stops_the_deploy(tmp_path, applicable, resolve):
    """Not Demonstrated, stated and approved, passes: the gate checks claims,
    it never forces a status."""
    doc = _supported_doc()
    rec = next(r for r in doc["records"] if r["frr_id"] == "AFC-CSO-INB")
    rec.clear()
    rec.update({"frr_id": "AFC-CSO-INB", "status": "Not Demonstrated", "implementation": "x",
                "not_demonstrated": "Not built.", "proposal": dict(OPERATOR_SIGNOFF),
                "approval": dict(OPERATOR_SIGNOFF)})
    assert _claim_problems(doc, applicable, resolve) == []
    assert _frr.main(["--records", str(_write(tmp_path, doc)), "--claims"]) == 0


def test_without_claims_the_cli_only_checks_shape(tmp_path):
    """make check loads the register; only the deploy runs --claims."""
    assert _frr.main(["--records", str(RECORDS)]) == 0


def test_the_committed_records_wait_on_the_operator(resolve):
    """Every migrated stand-in and scope cut is proposed and unapproved, so
    the committed register fails the claim check until the operator decides."""
    doc = _committed()
    waiting = [r for r in doc["records"] if r["status"] in _frr.NEEDS_APPROVAL]
    assert waiting and all(r.get("proposal") for r in waiting)
    assert not any(r.get("approval") for r in waiting)
    assert {rid for rid, _ in _frr.claims(doc, resolve)} == {r["frr_id"] for r in waiting}
    assert _frr.main(["--records", str(RECORDS), "--claims"]) == 1


def test_make_check_does_not_run_the_claim_check():
    mk = (REPO / "Makefile").read_text()
    check = re.search(r"^check:.*\n(?:\t.*\n)*", mk, re.M).group(0)
    assert "@$(MAKE) --no-print-directory test\n" in check
    assert "claims" not in check and "_frr.py" not in check
    assert re.search(r"^check-claims:.*\n\t.*scripts/_frr\.py --claims", mk, re.M)


def test_the_summary_counts_simulated_counterparties(applicable, resolve):
    doc = _doc_with("VDR-CSO-MSP", status="Simulated", implementation="x",
                    evidence=[{"kind": "step", "ref": "deploy-with-opa.yml#Run OPA Compliance Check"}],
                    simulated={"counterparty": "assessor", "how": "A plainly fictional assessor."})
    _frr.validate(doc, applicable, resolve)
    before = _frr.summary(_committed(), applicable)["simulated"]
    assert "simulated" not in next(r for r in _committed()["records"] if r["frr_id"] == "VDR-CSO-MSP")
    assert _frr.summary(doc, applicable)["simulated"] == {**before, "assessor": before.get("assessor", 0) + 1}


def test_the_gate_runs_before_anything_is_applied():
    """The claim check is in the job the deploy job needs, so an unsupported
    claim stops the run before terraform apply or any publish."""
    import yaml
    wf = yaml.safe_load((REPO / ".github" / "workflows" / "deploy-with-opa.yml").read_text())
    steps = {s.get("name"): s.get("run", "") for s in wf["jobs"]["test"]["steps"]}
    assert "scripts/_frr.py --claims" in steps["FedRAMP rule claims supported by evidence"]
    assert "test" in wf["jobs"]["deploy"]["needs"]
    assert not any("terraform apply" in s.get("run", "") or "aws s3" in s.get("run", "")
                   for s in wf["jobs"]["test"]["steps"])


def test_personnel_is_a_simulated_counterparty_with_every_rule_of_the_field(applicable, resolve):
    """No process waits on a person (DEC-194): `personnel` stands in for review
    attendees and a trainee, and keeps every rule of the simulated field."""
    assert "personnel" in _frr.SIMULATED_COUNTERPARTIES
    schema = json.loads((REPO / "infrastructure" / "schemas" / "frr-records.schema.json").read_text())
    assert "personnel" in json.dumps(schema)
    ok = _doc_with("VDR-CSO-MSP", status="Simulated", implementation="x",
                   evidence=[{"kind": "step", "ref": "deploy-with-opa.yml#Run OPA Compliance Check"}],
                   simulated={"counterparty": "personnel", "how": "A plainly simulated trainee."})
    _frr.validate(ok, applicable, resolve)
    no_deploy_evidence = _doc_with("VDR-CSO-MSP", status="Simulated", implementation="x",
                                   evidence=[{"kind": "test", "ref": "tests/test_frr_records.py::test_summary_counts_add_up"}],
                                   simulated={"counterparty": "personnel", "how": "A plainly simulated trainee."})
    with pytest.raises(SystemExit, match="needs deploy-time evidence"):
        _frr.validate(no_deploy_evidence, applicable, resolve)


# --- no line-number pointers ---------------------------------------------------------
# A line number goes stale with the next edit to the file it names, and the SDR
# publishes the record text. Records name the function, step or resource.
LINE_POINTER_RES = (
    re.compile(r"[\w./-]+\.(?:py|ya?ml|tf|rego|js|json|md|csv|sh|html):\d+"),
    re.compile(r"(?<![\w-])~?L\d{2,}(?:-\d+)?\b"),
)


def _line_pointers(records):
    found = []
    for r in records:
        for k, v in r.items():
            texts = [v] if isinstance(v, str) else [json.dumps(v, ensure_ascii=False)] if k == "simulated" else []
            for t in texts:
                found += [(r["frr_id"], k, m.group(0)) for rx in LINE_POINTER_RES for m in rx.finditer(t)]
    return found


def test_no_record_cites_a_line_number():
    assert _line_pointers(_committed()["records"]) == []


def test_known_bad_a_line_number_pointer_is_found():
    bad = json.loads((REPO / "tests" / "fixtures" / "frr" / "line-pointer.json").read_text())["records"]
    assert [(rid, p) for rid, _, p in _line_pointers(bad)] == [
        ("VDR-CSO-ADT", "infrastructure/main.tf:809"), ("FRC-APP-FCP", "~L1558-1600"),
        ("VER-EVA-EFP", "triage.rego:262")]
