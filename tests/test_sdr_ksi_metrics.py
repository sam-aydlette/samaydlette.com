"""The SDR's per-KSI statements (SDR-CSX-KSI), per-KSI historical metrics
(SDR-CSX-KMT), per-rule verification and validation (IVV-CSO-SEI/SEE), the
simulated-counterparty flags, and the FedRAMP ID (CDS-CSO-FID)."""

import copy
import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _controls  # noqa: E402
import _frr  # noqa: E402
import _offering  # noqa: E402
import _rules  # noqa: E402

spec = importlib.util.spec_from_file_location("build_sdr", REPO / "scripts" / "build-sdr.py")
sdr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sdr)

CATALOG = json.loads((REPO / "infrastructure" / "schemas" / "ksi-catalog.json").read_text())
NOW = datetime(2026, 11, 5, 12, tzinfo=timezone.utc)


def _signal():
    s = json.loads((REPO / "tests" / "fixtures" / "clean" / "ksi-signal.json").read_text())
    s["ksis"] = [{"id": i["id"], "status": "pass", "method": "policy-validation",
                  "evidence": {"validation_ids": ["v-1"], "failed_validation_ids": [],
                               "component_refs": ["aws::function::app"]}}
                 for f in CATALOG["KSI"].values() for i in f["indicators"]]
    return s


def _build(prev=None, now=NOW, records=None, rules_by_ksi=None):
    sig = _signal()
    return sdr.build(CATALOG, sig, records or _frr.load(), _rules.applicable_provider_rules(),
                     _controls.project(sig, CATALOG), sdr.moderate_ids(), rules_by_ksi or {}, [], "none supplied",
                     [], {"fedramp_class": "C", "impact_level": "Moderate"}, prev or {}, {}, now,
                     {"ac": "https://example.invalid/ac-policy.md"}, sdr.evidence_context())


@pytest.fixture(scope="module")
def doc():
    return _build()


def test_the_sdr_carries_the_offerings_fedramp_id(doc):
    assert doc["providerExtensions"]["fedRampId"] == _offering.fedramp_id()
    assert f"**FedRAMP ID:** {_offering.fedramp_id()}" in sdr.render_markdown(doc)


# --- SDR-CSX-KMT ---------------------------------------------------------------------

def test_todays_point_carries_every_ksi(doc):
    m = doc["providerExtensions"]["metrics"]
    ksis = m["current"]["ksis"]
    assert set(ksis) == {k["ksiId"] for k in doc["keySecurityIndicators"]}
    assert all(set(v) == {"s", "v", "f", "m", "r"} for v in ksis.values())
    assert set(m["ksi_summaries"]) == set(ksis)
    one = next(iter(m["ksi_summaries"].values()))
    assert one["summary_30d"]["days"] == 1 and one["summary_1y"]["days"] == 1


def test_per_ksi_history_is_carried_forward_and_summarized_over_30_days_and_a_year(doc):
    prev = doc
    for d in range(1, 41):
        prev = _build(prev=prev, now=NOW + timedelta(days=d))
    m = prev["providerExtensions"]["metrics"]
    assert len(m["daily_metric_data"]) == 41
    kid = next(iter(m["ksi_summaries"]))
    assert m["ksi_summaries"][kid]["summary_30d"]["days"] == 30
    assert m["ksi_summaries"][kid]["summary_1y"]["days"] == 41


def test_a_summary_counts_the_days_a_ksi_was_not_implemented():
    hist = [{"date": f"2026-10-{d:02d}", "ksis": {"KSI-X": {"s": "N" if d < 3 else "I", "v": 1, "f": int(d < 3),
                                                          "m": 1, "r": 0}}} for d in range(1, 6)]
    s = sdr.ksi_summaries(hist)["KSI-X"]["summary_1y"]
    assert s == {"days": 5, "daysImplemented": 3, "daysNotImplemented": 2, "maxFailingValidations": 1,
                 "minAutomatedMethods": 1, "daysRuntimeValidated": 0, "current": "Implemented"}


def test_days_before_per_ksi_data_existed_are_not_counted(doc):
    old = {"providerExtensions": {"metrics": {"daily_metric_data": [{"date": "2026-11-01", "vdr_blocking": 0}]}}}
    m = _build(prev=old)["providerExtensions"]["metrics"]
    assert len(m["daily_metric_data"]) == 2
    assert next(iter(m["ksi_summaries"].values()))["summary_1y"]["days"] == 1


# --- SDR-CSX-KSI ---------------------------------------------------------------------

def test_each_ksi_states_its_own_measures_cycle_and_validation():
    rules = {"KSI-CMT-LMC": [{"id": "deny_x", "title": "Deny X", "file": "network.rego"}]}
    d = _build(rules_by_ksi=rules)
    k = next(x for x in d["keySecurityIndicators"] if x["ksiId"] == "KSI-CMT-LMC")
    text = " ".join(k["ksiImplementation"] + k["ksiValidation"])
    for want in ("network.rego#deny_x", "Cycle:", "Verification that the measures demonstrate KSI-CMT-LMC",
                 "network_test.rego", "Validation on this deploy"):
        assert want in text
    assert k["providerExtensions"]["measures"] == ["network.rego#deny_x"]


def test_a_ksi_without_a_measure_says_why_and_the_risk(doc):
    k = doc["keySecurityIndicators"][0]
    text = " ".join(k["ksiImplementation"])
    assert "Reason:" in text and "Risk to customers" in text


def test_no_two_ksis_share_the_same_statement(doc):
    texts = [json.dumps([k["ksiImplementation"], k["ksiValidation"]]) for k in doc["keySecurityIndicators"]]
    assert len(set(texts)) == len(texts)


# --- IVV-CSO-SEI / SEE ----------------------------------------------------------------

def test_each_rule_states_how_each_piece_of_evidence_verifies_it(doc):
    records = {r["frr_id"]: r for r in _frr.load()["records"]}
    for req in doc["fedRampRequirements"]:
        rec = records[req["frrID"]]
        if rec.get("evidence"):
            val = " ".join(req.get("frrValidation") or req["providerExtensions"].get("validation") or [])
            for ev in rec["evidence"]:
                assert ev["ref"] in val, (req["frrID"], ev["ref"])


def test_artifact_evidence_states_its_cycle():
    ctx = sdr.evidence_context()
    line = sdr._evidence_validation({"kind": "artifact", "ref": ".well-known/security-decision-record.json"}, ctx)
    assert "cadence" in line and "hours" in line


# --- simulated counterparties ----------------------------------------------------------

def test_a_simulated_record_is_flagged_and_counted():
    recs = copy.deepcopy(_frr.load())
    target = next(r for r in recs["records"] if r["status"] == "Implemented")
    target["simulated"] = {"counterparty": "fedramp", "how": "a function in this repository"}
    d = _build(records=recs)
    req = next(r for r in d["fedRampRequirements"] if r["frrID"] == target["frr_id"])
    assert req["providerExtensions"]["simulated"] == target["simulated"]
    s = d["providerExtensions"]["summary"]["simulatedCounterparties"]
    base = sum(1 for r in _frr.load()["records"] if r.get("simulated"))
    assert s["records"] == base + (0 if _frr_has_sim(target["frr_id"]) else 1)
    assert "simulated fedramp" in sdr.render_markdown(d)


def _frr_has_sim(rid):
    return any(r["frr_id"] == rid and r.get("simulated") for r in _frr.load()["records"])
