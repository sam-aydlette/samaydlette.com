"""Assessor records enter through a signed input port (REQ-ASR-1; Appendix B T74).

An assessor's findings and summaries are records the assessor signs. The build
accepts a record only when its signature verifies against the pinned assessor
identity, and fails when any output carries assessor text that differs from the
signed record. With no records, the SDR says so instead of implying an
assessment.

The committed fixtures were signed with throwaway keys whose private halves were
discarded; identity-a.json pins key A.
"""
import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "assessor"
sys.path.insert(0, str(REPO / "scripts"))
import _assessor  # noqa: E402

spec = importlib.util.spec_from_file_location("sdr", REPO / "scripts" / "build-sdr.py")
sdr_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sdr_mod)

PIN = FIX / "identity-a.json"


def _dir_with(tmp_path, *names):
    d = tmp_path / "records"
    d.mkdir()
    for n in names:
        (d / n).write_text((FIX / n).read_text())
    return d


def _rules(*ids):
    return [{"rule_id": i, "assessor_comment_responses": []} for i in ids]


# --- the input port -------------------------------------------------------------

def test_genuine_record_verifies(tmp_path):
    recs = _assessor.load_records(_dir_with(tmp_path, "genuine.json"), PIN)
    assert [r["record_id"] for r in recs] == ["ASR-TEST-1"]


@pytest.mark.parametrize("bad", ["unsigned.json", "tampered.json", "wrong-identity.json", "impersonated.json"])
def test_known_bad_record_fails_the_build(tmp_path, bad):
    with pytest.raises(SystemExit):
        _assessor.load_records(_dir_with(tmp_path, bad), PIN)


def test_one_bad_record_fails_even_beside_a_good_one(tmp_path):
    with pytest.raises(SystemExit):
        _assessor.load_records(_dir_with(tmp_path, "genuine.json", "tampered.json"), PIN)


def test_records_without_a_pinned_identity_fail(tmp_path):
    with pytest.raises(SystemExit):
        _assessor.load_records(_dir_with(tmp_path, "genuine.json"), tmp_path / "absent.json")


def test_pinned_identity_whose_hash_does_not_match_fails(tmp_path):
    pin = json.loads(PIN.read_text())
    pin["public_key_sha256"] = "0" * 64
    p = tmp_path / "pin.json"
    p.write_text(json.dumps(pin))
    with pytest.raises(SystemExit):
        _assessor.load_records(_dir_with(tmp_path, "genuine.json"), p)


def test_no_records_needs_no_identity(tmp_path):
    d = tmp_path / "records"
    d.mkdir()
    assert _assessor.load_records(d, tmp_path / "absent.json") == []
    assert _assessor.load_records(tmp_path / "missing-dir", tmp_path / "absent.json") == []


def test_committed_record_directory_loads():
    _assessor.load_records(REPO / "data" / "assessor-records", REPO / "infrastructure" / "keys" / "assessor-identity.json")


def test_fixtures_match_the_published_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((REPO / "infrastructure" / "schemas" / "assessor-record.schema.json").read_text())
    jsonschema.validate(json.loads((FIX / "genuine.json").read_text()), schema)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(json.loads((FIX / "unsigned.json").read_text()), schema)


# --- the SDR carries them verbatim, with the signature ----------------------------

def test_sdr_attaches_the_record_with_its_signature(tmp_path):
    recs = _assessor.load_records(_dir_with(tmp_path, "genuine.json"), PIN)
    rules = _rules("KSI-TEST-01", "KSI-TEST-02")
    block = _assessor.attach(rules, recs)
    resp = rules[0]["assessor_comment_responses"]
    signed = json.loads((FIX / "genuine.json").read_text())
    assert resp[0]["text"] == signed["text"]
    assert resp[0]["signature"] == signed["signature"]
    assert resp[0]["record_id"] == "ASR-TEST-1"
    assert rules[1]["assessor_comment_responses"] == []
    assert block["status"] == "1 verified assessor record"


def test_record_naming_an_unknown_rule_fails(tmp_path):
    recs = _assessor.load_records(_dir_with(tmp_path, "genuine.json"), PIN)
    with pytest.raises(SystemExit):
        _assessor.attach(_rules("KSI-OTHER"), recs)


def test_no_records_is_stated():
    rules = _rules("KSI-TEST-01")
    block = _assessor.attach(rules, [])
    assert block == {"status": "no assessor record", "records": []}
    assert rules[0]["assessor_comment_responses"] == []


def test_t74_output_text_differing_from_the_signed_record_fails(tmp_path):
    recs = _assessor.load_records(_dir_with(tmp_path, "genuine.json"), PIN)
    rules = _rules("KSI-TEST-01")
    block = _assessor.attach(rules, recs)
    sdr = {"rule_records": rules, "assessor_records": block}
    _assessor.verify_output(sdr, recs)  # untouched: passes
    bad = copy.deepcopy(sdr)
    bad["rule_records"][0]["assessor_comment_responses"][0]["text"] = "Softened wording."
    with pytest.raises(SystemExit):
        _assessor.verify_output(bad, recs)


def test_t74_output_carrying_an_unsigned_assessor_entry_fails(tmp_path):
    recs = _assessor.load_records(_dir_with(tmp_path, "genuine.json"), PIN)
    rules = _rules("KSI-TEST-01")
    sdr = {"rule_records": rules, "assessor_records": _assessor.attach(rules, recs)}
    sdr["rule_records"][0]["assessor_comment_responses"].append({"record_id": "ASR-INVENTED", "text": "x"})
    with pytest.raises(SystemExit):
        _assessor.verify_output(sdr, recs)


def test_t74_output_dropping_a_signed_record_fails(tmp_path):
    recs = _assessor.load_records(_dir_with(tmp_path, "genuine.json"), PIN)
    rules = _rules("KSI-TEST-01")
    sdr = {"rule_records": rules, "assessor_records": _assessor.attach(rules, recs)}
    sdr["rule_records"][0]["assessor_comment_responses"] = []
    with pytest.raises(SystemExit):
        _assessor.verify_output(sdr, recs)


def test_sdr_markdown_states_no_assessor_record():
    sdr = {"note": "n", "class": "C", "impact_level": "low", "ksi_signal_id": "s",
           "metadata": {"version": "v", "last_updated": "t", "source_of_update": "s"},
           "metrics": {"current": {"ksi_in_scope": 0, "controls_in_scope": 0, "signal_validations": 0,
                                   "signal_failing": 0, "vdr_total": 0, "vdr_blocking": 0,
                                   "vdr_accepted": 0, "vdr_kev": 0},
                       "daily_metric_data": []},
           "status_summary": {"rules": {"rules": 0, "by_status": {}, "awaiting_approval": 0},
                              "ksis": {"total": 0, "by_status": {}}},
           "rule_records": [], "assessor_records": {"status": "no assessor record", "records": []}}
    assert "No assessor record" in sdr_mod.render_markdown(sdr)
