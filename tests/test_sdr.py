"""The Security Decision Record in FedRAMP's schema: every applicable rule,
every KSI and every Moderate control, none stronger than what backs it."""

import copy
import importlib.util
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _controls  # noqa: E402
import _fedramp_schema as fs  # noqa: E402
import _frr  # noqa: E402
import _offering  # noqa: E402
import _rules  # noqa: E402

spec = importlib.util.spec_from_file_location("build_sdr", REPO / "scripts" / "build-sdr.py")
sdr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sdr)

CATALOG = REPO / "infrastructure" / "schemas" / "ksi-catalog.json"
FIX_SIGNAL = REPO / "tests" / "fixtures" / "clean" / "ksi-signal.json"
NOW = datetime(2026, 11, 5, 12, tzinfo=timezone.utc)
POLICIES = {"ac": "https://example.invalid/ac-policy.md"}


def _catalog():
    return json.loads(CATALOG.read_text())


def _signal(method="policy-validation", status="pass", overrides=None):
    """The clean fixture inventory plus a result for every KSI."""
    s = json.loads(FIX_SIGNAL.read_text())
    s["ksis"] = []
    for f in _catalog()["KSI"].values():
        for i in f["indicators"]:
            s["ksis"].append({"id": i["id"], "status": status, "method": method,
                              "evidence": {"validation_ids": ["v-1"], "failed_validation_ids": [],
                                           "component_refs": ["aws::function::app"]}})
    for k in s["ksis"]:
        k.update((overrides or {}).get(k["id"], {}))
    return s


def _build(signal=None, prev=None, records=None, irs=None, runtime=(), rules_by_ksi=None):
    signal = signal or _signal()
    return sdr.build(_catalog(), signal, records or _frr.load(), _rules.applicable_provider_rules(),
                     irs if irs is not None else _controls.project(signal, _catalog()),
                     sdr.moderate_ids(), rules_by_ksi or {}, list(runtime), None if runtime else "none supplied",
                     [], {"fedramp_class": "C", "impact_level": "Moderate"}, prev or {}, {}, NOW, POLICIES)


@pytest.fixture(scope="module")
def doc():
    return _build()


# --- shape ---------------------------------------------------------------------------

def test_it_validates_against_fedramps_schema(doc):
    assert fs.validate(doc, "sdr") == []


def test_the_sdr_json_says_the_system_is_not_certified_like_the_cpo(doc):
    cert = doc["providerExtensions"]["certification"]
    assert cert == {"program": "FedRAMP 20x, Program path, Class C", "status": "not certified (proof of concept)"}
    assert cert == _offering.certification()  # one source for the SDR and the CPO
    assert "not certified (proof of concept)" in sdr.render_markdown(doc)


def test_every_applicable_rule_is_listed_once(doc):
    ids = [r["frrID"] for r in doc["fedRampRequirements"]]
    assert sorted(ids) == sorted(_rules.applicable_provider_rules()) and len(ids) == len(set(ids))


def test_not_applicable_rules_carry_no_status_and_say_why(doc):
    na = [r for r in doc["fedRampRequirements"] if r["providerExtensions"]["status"] == "Not Applicable"]
    assert na
    for r in na:
        assert "frrImplementationStatus" not in r
        assert any(line.startswith("Not applicable: ") for line in r["frrImplementation"])


def test_every_ksi_is_listed_with_tests_and_evidence(doc):
    assert len(doc["keySecurityIndicators"]) == 46
    for k in doc["keySecurityIndicators"]:
        assert k["ksiEvidence"] and k["ksiValidation"] and k["ksiAssessment"]


def test_every_moderate_control_is_addressed(doc):
    got = {c["controlId"] for c in doc["securityControls"] if c["providerExtensions"]["inModerateBaseline"]}
    assert got == {sdr.nist_id(c) for c in sdr.moderate_ids()} and len(got) == 323


def test_every_projected_control_is_carried_with_its_parameters(doc):
    irs = _controls.project(_signal(), _catalog())
    assert len(doc["securityControls"]) == len(irs)
    assert sum(len(c.get("parameterValues", [])) for c in doc["securityControls"]) > 200


def test_every_control_names_its_20x_coverage(doc):
    for c in doc["securityControls"]:
        assert "**20x coverage:**" in c["controlImplementationDescription"], c["controlId"]


def test_nist_ids():
    assert sdr.nist_id("ac-2") == "AC-2" and sdr.nist_id("ac-2.12") == "AC-2(12)"


# --- honesty rules -------------------------------------------------------------------

def _ir(cid, status="implemented", origination="sp-system"):
    return {"control-id": cid, "props": [{"name": "implementation-status", "value": status},
                                         {"name": "control-origination", "value": origination}]}


@pytest.mark.parametrize("ir,ksis,ksi_st,frrs,frr_st,want", [
    (_ir("sc-13", origination="inherited"), {}, {}, {}, {}, "Implemented"),
    (_ir("sc-13"), {"sc-13": {"KSI-A"}}, {"KSI-A": "Implemented"}, {}, {}, "Implemented"),
    (_ir("sc-13"), {"sc-13": {"KSI-A"}}, {"KSI-A": "Partially Implemented"}, {}, {}, "Partially Implemented"),
    (_ir("sc-13"), {}, {}, {"sc-13": {"R-1"}}, {"R-1": "Implemented"}, "Implemented"),
    (_ir("sc-13"), {}, {}, {"sc-13": {"R-1"}}, {"R-1": "Partially Implemented"}, "Partially Implemented"),
    (_ir("ac-1"), {}, {}, {}, {}, "Implemented"),                  # policy control, policy published
    (_ir("sc-1"), {}, {}, {}, {}, "Partially Implemented"),        # no sc policy in POLICIES
    (_ir("ac-2"), {}, {}, {}, {}, "Partially Implemented"),        # nothing backs it
    (_ir("ac-2", status="partial"), {}, {}, {}, {}, "Partially Implemented"),
    (_ir("ac-2", status="not-applicable"), {}, {}, {}, {}, None),
])
def test_a_control_is_no_stronger_than_what_backs_it(ir, ksis, ksi_st, frrs, frr_st, want):
    assert sdr.control_basis(ir, ksis, ksi_st, frrs, frr_st, POLICIES)[0] == want


@pytest.mark.parametrize("k,want", [
    ({"status": "pass", "method": "policy-validation", "evidence": {"validation_ids": ["v"]}}, "Implemented"),
    ({"status": "pass", "method": "policy-validation", "evidence": {"validation_ids": []}}, "Partially Implemented"),
    ({"status": "pass", "method": "inventory-attestation", "evidence": {}}, "Partially Implemented"),
    ({"status": "pass", "method": "documentation", "evidence": {}}, "Partially Implemented"),
    ({"status": "fail", "method": "policy-validation", "evidence": {"validation_ids": ["v"]}}, "Not Implemented"),
])
def test_a_ksi_is_implemented_only_when_its_measures_are_checked(k, want):
    assert sdr.ksi_status(k) == want


def test_runtime_revalidation_counts_as_a_second_automated_method():
    rt = [{"validation_id": "r-1", "component_refs": ["aws::function::app"], "result": "pass"}]
    d = _build(runtime=rt)
    assert {k["providerExtensions"]["automatedMethods"] for k in d["keySecurityIndicators"]} == {2}
    d = _build()
    assert {k["providerExtensions"]["automatedMethods"] for k in d["keySecurityIndicators"]} == {1}


# --- known-bad: each fails closed for its own reason --------------------------------

def test_a_moderate_control_missing_from_the_projection_fails():
    irs = [ir for ir in _controls.project(_signal(), _catalog()) if ir["control-id"] != "ac-2"]
    with pytest.raises(SystemExit, match="1 Moderate control.*ac-2"):
        _build(irs=irs)


def test_a_signal_without_a_ksi_result_fails():
    s = _signal()
    s["ksis"] = [k for k in s["ksis"] if k["id"] != "KSI-CED-RAT"]
    with pytest.raises(SystemExit, match="no result for KSI-CED-RAT"):
        _build(signal=s)


def test_an_invalid_record_set_never_reaches_the_sdr(tmp_path):
    bad = json.loads(_frr.DEFAULT_PATH.read_text())
    bad["records"] = bad["records"][1:]
    p = tmp_path / "frr.json"
    p.write_text(json.dumps(bad))
    with pytest.raises(SystemExit, match="no record for 1 applicable rule"):
        _frr.load(p)


def test_a_document_failing_the_schema_is_not_written(tmp_path, doc):
    bad = copy.deepcopy(doc)
    bad["keySecurityIndicators"][0].pop("ksiTests")
    with pytest.raises(SystemExit, match="does not validate"):
        fs.write_validated(bad, "sdr", tmp_path / "sdr.json")
    assert not (tmp_path / "sdr.json").exists()


# --- version and history -------------------------------------------------------------

def test_version_starts_at_1_0_0_after_the_unversioned_record(doc):
    assert _build(prev={"metadata": {"version": "live (regenerated each deploy)"}})["metadata"]["version"] == "1.0.0"


def test_unchanged_content_keeps_its_version_and_a_change_bumps_it(doc):
    again = _build(prev=doc)
    assert again["metadata"]["version"] == doc["metadata"]["version"]
    prev = copy.deepcopy(doc)
    prev["metadata"]["version"] = "1.0.7"
    prev["providerExtensions"]["contentSha256"] = "0" * 64
    assert _build(prev=prev)["metadata"]["version"] == "1.0.8"


def test_daily_metrics_carry_over_from_the_record_before_the_reshape():
    old = {"metrics": {"daily_metric_data": [{"date": "2026-11-01", "vdr_blocking": 0, "signal_failing": 0}]}}
    hist = _build(prev=old)["providerExtensions"]["metrics"]["daily_metric_data"]
    assert [h["date"] for h in hist] == ["2026-11-01", "2026-11-05"]


# --- the human view says the same thing as the JSON ---------------------------------

def test_markdown_counts_match_the_json(doc):
    md = sdr.render_markdown(doc)
    s = doc["providerExtensions"]["summary"]
    assert f"- Rev5 Moderate controls (323): {sdr._summary_line(s['securityControlsModerate'])}" in md
    assert md.count("\n| `") == len(doc["fedRampRequirements"]) + len(doc["keySecurityIndicators"])
    assert "No assessor record" in md


def test_the_builder_runs_end_to_end(tmp_path):
    if not shutil.which("opa"):
        pytest.skip("opa not available")
    sig = tmp_path / "ksi-signal.json"
    sig.write_text(json.dumps(_signal()))
    out = tmp_path / "sdr.json"
    assert sdr.main(["--catalog", str(CATALOG), "--ksi-signal", str(sig), "--runtime-signal", str(tmp_path / "none"),
                     "--vdr", str(tmp_path / "none"), "--profile", str(REPO / "data" / "system-profile.json"),
                     "--output", str(out), "--md-output", str(tmp_path / "sdr.md")]) == 0
    assert fs.validate(json.loads(out.read_text()), "sdr") == []
