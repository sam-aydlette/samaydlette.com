"""data/frr-records.json: shape (scripts/_frr.py) and claims (policies/compliance/claims.rego)."""

import copy
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _frr  # noqa: E402
import _rules  # noqa: E402

OP = {"by": _frr.OPERATOR, "on": "2026-11-07"}
GOOD_TEST = "tests/test_frr_records.py::test_the_committed_records_are_valid"


@pytest.fixture(scope="module")
def applicable():
    return _rules.applicable_provider_rules()


@pytest.fixture(scope="module")
def resolve():
    return _frr.resolver()


@pytest.fixture(scope="module")
def committed():
    return _frr.load()


# --- the applicable rule set -----------------------------------------------------

def test_applicable_rules_come_from_the_pinned_corpus(applicable):
    forces = {}
    for r in applicable.values():
        forces[r["force"]] = forces.get(r["force"], 0) + 1
    assert len(applicable) == 154
    assert forces == {"MUST": 90, "SHOULD": 40, "MAY": 15, "MUST NOT": 5, "SHOULD NOT": 4}


# --- the committed register --------------------------------------------------------

def test_the_committed_records_are_valid(committed, applicable):
    assert {r["frr_id"] for r in committed["records"]} == set(applicable)


def test_the_committed_records_match_their_schema(committed):
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(committed, json.loads(_frr.SCHEMA_PATH.read_text()))


def test_every_piece_of_committed_evidence_resolves(committed, resolve):
    bad = [(r["frr_id"], e["ref"], resolve(e)) for r in committed["records"]
           for e in r.get("evidence", []) if resolve(e)]
    assert bad == []


def test_the_committed_records_only_wait_on_the_operator(committed, resolve):
    """Every unsupported claim left is an approval or a cost only the operator
    can supply; nothing else blocks the deploy."""
    waiting = ("not approved by the operator", "without naming the cost")
    other = [c for c in _frr.claims(committed, resolve) if not c[1].endswith(waiting)]
    assert other == []


def test_summary_counts_add_up(committed, applicable):
    s = _frr.summary(committed, applicable)
    assert sum(s["by_status"].values()) == s["rules"] == 154
    assert sum(sum(v.values()) for v in s["by_force"].values()) == 154


# --- shape: known-bad inputs fail closed --------------------------------------------

def _doc(rec):
    return {"schema": "frr-records/2", "basis": "b", "records": [rec]}


def _ok(rid="X-ONE"):
    return {"frr_id": rid, "status": "Implemented", "implementation": "i",
            "evidence": [{"kind": "test", "ref": GOOD_TEST}]}


SMALL = {"X-ONE": {"force": "MUST"}}

BAD_SHAPES = {
    "unknown status": {"status": "Simulated"},
    "unknown field": {"stand_in": "x"},
    "a field of another status": {"not_applicable": "x"},
    "implemented without implementation": {"implementation": None},
    "account id in text": {"implementation": "arn:aws:iam::123456789012:role/x"},
    "outside email": {"implementation": "mail someone@example.org"},
    "may rationale on a MUST rule": {"may_rationale": "r"},
    "bad evidence kind": {"evidence": [{"kind": "hunch", "ref": "x"}]},
    "bad signoff date": {"status": "Not Applicable", "implementation": None, "not_applicable": "t",
                         "proposal": {"by": "x", "on": "yesterday"}},
    "impractical with an unknown field": {"status": "Impractical", "implementation": None,
                                          "impractical": {"reasons": ["one-person"], "excuse": "x"}},
}


@pytest.mark.parametrize("case", sorted(BAD_SHAPES))
def test_known_bad_shapes_fail(case):
    rec = _ok()
    for k, v in BAD_SHAPES[case].items():
        if v is None:
            rec.pop(k, None)
        else:
            rec[k] = v
    with pytest.raises(SystemExit):
        _frr.validate(_doc(rec), SMALL)


def test_a_rule_added_to_the_corpus_needs_a_record():
    with pytest.raises(SystemExit, match="no record for 1"):
        _frr.validate(_doc(_ok()), {**SMALL, "X-TWO": {"force": "MUST"}})


def test_a_record_for_a_rule_that_does_not_apply_fails():
    with pytest.raises(SystemExit, match="extra record"):
        _frr.validate(_doc(_ok("X-TWO")), SMALL)


def test_a_may_rule_says_why():
    with pytest.raises(SystemExit, match="may_rationale"):
        _frr.validate(_doc(_ok()), {"X-ONE": {"force": "MAY"}})


# --- evidence resolution (facts) ------------------------------------------------------

@pytest.mark.parametrize("ev,ok", [
    ({"kind": "test", "ref": GOOD_TEST}, True),
    ({"kind": "test", "ref": "tests/test_frr_records.py::not_a_test"}, False),
    ({"kind": "test", "ref": "tests/nope.py::test_x"}, False),
    ({"kind": "step", "ref": "deploy-with-opa.yml#No such step"}, False),
    ({"kind": "artifact", "ref": ".well-known/ksi-signal.json"}, True),
    ({"kind": "artifact", "ref": ".well-known/made-up.json"}, False),
    ({"kind": "decision", "ref": "DEC-999"}, False),
])
def test_evidence_resolution(ev, ok, resolve):
    assert (resolve(ev) is None) is ok


# --- claims: a bad input changes the decision -----------------------------------------

def test_an_unresolved_reference_is_an_unsupported_claim(resolve):
    doc = _doc(_ok())
    assert _frr.claims(doc, resolve) == []
    doc["records"][0]["evidence"] = [{"kind": "step", "ref": "deploy-with-opa.yml#No such step"}]
    assert [rid for rid, _ in _frr.claims(doc, resolve)] == ["X-ONE"]


def test_an_impractical_record_needs_the_operator(resolve):
    rec = {"frr_id": "X-ONE", "status": "Impractical", "proposal": OP,
           "impractical": {"reasons": ["no-outside-party"], "why": "needs an agency"}}
    assert _frr.claims(_doc(rec), resolve) == [("X-ONE", "Impractical not approved by the operator")]
    rec["approval"] = OP
    assert _frr.claims(_doc(rec), resolve) == []
    rec["approval"] = {"by": "AI-drafted", "on": "2026-11-07"}
    assert _frr.claims(_doc(rec), resolve) == [("X-ONE", 'approved by "AI-drafted": only the operator approves')]


def test_two_methods_is_checked_against_the_ksi_count(resolve):
    rec = {**_ok(), "frr_id": "FRC-CSX-VVK"}
    assert _frr.claims(_doc(rec), resolve, ksi_short=[]) == []
    assert _frr.claims(_doc(rec), resolve, ksi_short=["KSI-CNA-RNT"])[0][0] == "FRC-CSX-VVK"
    assert _frr.claims(_doc(rec), resolve)[0][0] == "FRC-CSX-VVK"


def test_the_cli_claim_gate_exit_code(tmp_path, committed):
    good = copy.deepcopy(committed)
    for r in good["records"]:
        if r["status"] in ("Impractical", "Not Applicable"):
            r["approval"] = OP
            if "no-budget" in r.get("impractical", {}).get("reasons", []):
                r["impractical"]["cost"] = "a stated cost"
    p = tmp_path / "frr.json"
    p.write_text(json.dumps(good))
    assert _frr.main(["--records", str(p), "--claims"]) == 0
    good["records"][0]["status"] = "Implemented"
    good["records"][0].pop("not_demonstrated", None)
    good["records"][0].pop("planned", None)
    good["records"][0]["implementation"] = "claimed"
    good["records"][0].pop("evidence", None)
    good["records"][0].pop("approval", None)
    good["records"][0].pop("proposal", None)
    good["records"][0].pop("impractical", None)
    good["records"][0].pop("not_applicable", None)
    p.write_text(json.dumps(good))
    assert _frr.main(["--records", str(p), "--claims"]) == 1
    assert _frr.main(["--records", str(p)]) == 0
