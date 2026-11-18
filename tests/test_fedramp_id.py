"""The FedRAMP ID in every FedRAMP report and notification (CDS-CSO-FID), and the
publication gate that holds the published reports to it (scripts/check-fedramp-id.py).

CDS-CSO-FID and FRC-CSO-MRA cite these tests.
"""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _common  # noqa: E402
import _freshness  # noqa: E402


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gate = _load("check_fedramp_id", "check-fedramp-id.py")
alerts = _load("gate_alerts", "gate-alerts.py")
OFFERING = json.loads((REPO / "data" / "cds" / "offering.json").read_text())
FID = OFFERING["fedramp_id"]
CERTIFICATION_DATA = {
    "vdr-report.json": "scripts/build-vdr-report.py",
    "vdr-detail-report.json": "scripts/build-cr26-vdr.py",
    "vdr-accepted-vulnerabilities.json": "scripts/build-cr26-vdr.py",
    "vdr-history.json": "scripts/build-cr26-vdr.py",
    "vdr-status.json": ".github/workflows/evidence-nightly.yml",
    "ksi-signal.json": "scripts/build-ksi-signal.py",
    "ongoing-certification-report.json": "scripts/build-ocr.py",
    "ocr-issues.json": "scripts/issue-ocr.py",
    "availability.json": "scripts/build-availability.py",
    "policy-index.json": "scripts/build-policy-index.py",
    "security-decision-record.json": "scripts/build-sdr.py",
    "certification-package-overview.json": "scripts/build-cpo.py",
    "trust-center.json": "scripts/build-trust-center.py",
}


# --- one source ------------------------------------------------------------------------

def test_the_id_comes_from_the_offering_and_says_it_is_not_a_real_one():
    assert _common.fedramp_id() == FID
    assert FID.endswith("PROOF-OF-CONCEPT-NOT-A-REAL-FEDRAMP-ID")


def test_the_placeholder_is_a_recorded_operator_decision():
    dec = OFFERING["fedramp_id_decision"]
    assert dec["by"] == "Sam Aydlette" and dec["on"] == "2026-11-17" and "placeholder" in dec["decision"]


DECISION = {"decision": "d", "by": "Sam Aydlette", "on": "2026-11-17"}


@pytest.mark.parametrize("offering", [
    {}, {"fedramp_id": "", "fedramp_id_decision": DECISION}, {"fedramp_id": "  ", "fedramp_id_decision": DECISION},
    {"fedramp_id": 7, "fedramp_id_decision": DECISION},
    {"fedramp_id": "X"}, {"fedramp_id": "X", "fedramp_id_decision": {**DECISION, "by": ""}},
    {"fedramp_id": "X", "fedramp_id_decision": {"decision": "d", "by": "Sam Aydlette"}},
])
def test_no_report_is_built_without_an_id_and_its_decision(tmp_path, offering):
    p = tmp_path / "offering.json"
    p.write_text(json.dumps(offering))
    with pytest.raises(SystemExit, match="CDS-CSO-FID"):
        _common.fedramp_id(p)


# --- every report ----------------------------------------------------------------------

def test_the_governed_config_marks_exactly_the_certification_data():
    cfg = _freshness.load_freshness_config()
    marked = {Path(a["path"]).name: a["generator"] for a in cfg["artifacts"] if a.get("certification_data")}
    assert marked == CERTIFICATION_DATA


@pytest.mark.parametrize("generator", sorted(set(CERTIFICATION_DATA.values())))
def test_each_certification_data_generator_writes_the_offerings_id(generator):
    src = (REPO / generator).read_text()
    if generator.endswith(".yml"):
        assert "FEDRAMP_ID=\"$(jq -er '.fedramp_id' ../data/cds/offering.json)\"" in src
        assert "fedramp_id: $fedramp_id" in src
    elif generator == "scripts/build-cpo.py":
        assert '"fedramp_id": off["fedramp_id"]' in src
    else:
        assert '"fedramp_id": fedramp_id()' in src or 'report["fedramp_id"] = fedramp_id()' in src


def test_the_availability_feed_carries_the_id(tmp_path):
    out = tmp_path / "availability.json"
    subprocess.run([sys.executable, str(REPO / "scripts" / "build-availability.py"), "--ksi-signal", "absent.json",
                    "--output", str(out), "--md-output", ""], check=True, capture_output=True, cwd=tmp_path)
    assert json.loads(out.read_text())["fedramp_id"] == FID


def test_the_three_cr26_vulnerability_reports_carry_the_id():
    cr26 = _load("build_cr26_vdr", "build-cr26-vdr.py")
    import _decisions
    vdr = {"report_id": "r", "ksi_signal_id": "s", "findings": [], "risk_accepted": []}
    from datetime import datetime, timezone
    for doc in cr26.build(vdr, _decisions.load(), None, None, None, datetime.now(timezone.utc)):
        assert doc["fedramp_id"] == FID


def test_the_cpo_carries_the_same_id_in_fedramps_field_and_ours():
    cpo = _load("build_cpo", "build-cpo.py")
    prof = json.loads((REPO / "data" / "system-profile.json").read_text())
    from datetime import datetime, timezone
    doc = cpo.build(OFFERING, prof, {"signal_id": "s", "components": []}, datetime.now(timezone.utc), "abc", None)
    assert doc["fedramp_id"] == doc["serviceIdentification"]["fedRampPackageId"] == FID


# --- notifications -----------------------------------------------------------------------

@pytest.mark.parametrize("action", ["open", "close"])
def test_every_alert_names_the_id(action):
    body = alerts._body({"action": action, "checks": [("frr.claims", "role:security-officer")]}, "deploy")
    assert f"FedRAMP ID: {FID}" in body


# --- the gate ----------------------------------------------------------------------------

def _write(root, name, doc):
    (root / name).write_text(doc if isinstance(doc, str) else json.dumps(doc))


def test_the_gate_passes_reports_that_carry_the_id(tmp_path):
    _write(tmp_path, "vdr-report.json", {"fedramp_id": FID})
    _write(tmp_path, "certification-package-overview.json",
           {"fedramp_id": FID, "serviceIdentification": {"fedRampPackageId": FID}})
    assert gate.main(["--root", str(tmp_path)]) == 0


@pytest.mark.parametrize("name,doc", [
    ("vdr-report.json", {}),
    ("vdr-report.json", {"fedramp_id": "FR-SOMETHING-ELSE"}),
    ("vdr-report.json", "not json"),
    ("certification-package-overview.json", {"fedramp_id": FID, "serviceIdentification": {"fedRampPackageId": "x"}}),
])
def test_the_gate_fails_a_report_without_the_offerings_id(tmp_path, capsys, name, doc):
    _write(tmp_path, name, doc)
    assert gate.main(["--root", str(tmp_path)]) == 1
    assert name in capsys.readouterr().err


def test_the_gate_with_nothing_to_check_fails(tmp_path):
    _write(tmp_path, "boundary-map.json", {})  # published, but not certification data
    assert gate.main(["--root", str(tmp_path)]) == 2


def test_the_nightly_gate_checks_only_the_files_it_names(tmp_path):
    _write(tmp_path, "vdr-report.json", {"fedramp_id": FID})
    _write(tmp_path, "security-decision-record.json", {})  # downloaded as an input, not published here
    assert gate.main([str(tmp_path / "vdr-report.json")]) == 0
