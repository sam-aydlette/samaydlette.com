"""FRC-CSX-VVR: the build fails when a test a rule record cites did not pass,
and the result is published per record."""
import importlib.util
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "frr-evidence"
spec = importlib.util.spec_from_file_location("frr_evidence", REPO / "scripts" / "check-frr-evidence.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

SDR_A = "tests/test_sdr.py::test_every_applicable_rule_is_listed_once"
SDR_B = "tests/test_sdr.py::test_an_invalid_record_set_never_reaches_the_sdr"


def _records(*refs):
    return {"records": [{"frr_id": "SDR-CSO-FRR", "status": "Implemented",
                         "evidence": [{"kind": "test", "ref": r} for r in refs]}]}


def test_all_cited_tests_passing_is_a_pass():
    per, failures = mod.evaluate(_records(SDR_A, SDR_B, "tests/test_other.py::TestThing::test_method"),
                                 mod.junit_outcomes(FIX / "passing.xml"))
    assert failures == []
    assert per["SDR-CSO-FRR"]["result"] == "pass"
    assert set(per["SDR-CSO-FRR"]["tests"].values()) == {"passed"}


def test_known_bad_a_failing_cited_test_fails_the_build():
    per, failures = mod.evaluate(_records(SDR_A, SDR_B), mod.junit_outcomes(FIX / "failing-cited-test.xml"))
    assert failures == [f"SDR-CSO-FRR: cited test {SDR_B} failed"]
    assert per["SDR-CSO-FRR"]["result"] == "fail"


@pytest.mark.parametrize("ref,expected", [
    ("tests/test_other.py::test_skipped", "skipped"),
    ("tests/test_other.py::test_never_ran", "not run"),
])
def test_a_skipped_or_missing_cited_test_is_not_a_pass(ref, expected):
    _, failures = mod.evaluate(_records(ref), mod.junit_outcomes(FIX / "passing.xml"))
    assert failures == [f"SDR-CSO-FRR: cited test {ref} {expected}"]


def test_main_refuses_to_write_results_when_a_cited_test_failed(tmp_path, monkeypatch):
    monkeypatch.setattr(mod._frr, "load", lambda _p: _records(SDR_B))
    out = tmp_path / "frr-evidence.json"
    with pytest.raises(SystemExit):
        mod.main(["--junit", str(FIX / "failing-cited-test.xml"), "--output", str(out)])
    assert not out.exists()


def test_the_unit_test_job_runs_the_check_on_its_own_results():
    wf = (REPO / ".github" / "workflows" / "deploy-with-opa.yml").read_text()
    test_job = wf.split("\n  test:\n", 1)[1].split("\n  compliance-check:\n", 1)[0]
    assert re.search(r"pytest tests/ -q --junitxml=pytest-results\.xml", test_job)
    assert "scripts/check-frr-evidence.py --junit pytest-results.xml" in test_job
    assert test_job.index("--junitxml=pytest-results.xml") < test_job.index("check-frr-evidence.py")
