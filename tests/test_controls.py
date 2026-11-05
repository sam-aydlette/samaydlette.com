"""The control projection (scripts/_controls.py) replaces the OSCAL SSP (CR26).

The SSP was the control hub: every framework view read its implemented
requirements back out of the generated oscal-ssp.json. The projection now lives
in scripts/_controls.py and consumers compute it in memory from the canonical
inventory and the KSI catalog. These tests pin:

- parity: the projection gives every control the status and origination the
  retired SSP builder gave it (against a frozen copy of its output);
- the projection fails closed on a missing input;
- the SDR carries the per-Rev5-control record the SSP used to (SDR-CSF-CTF);
- the SSP is gone: no builder, no consumer reads it, it is not published or
  watched, and the deploy deletes the published copies and fails unless each
  returns 404;
- reconciliation reads the SDR and CPO in the SSP's place and fails closed
  without them.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
FIX_SIGNAL = REPO / "tests" / "fixtures" / "clean" / "ksi-signal.json"
CATALOG = REPO / "infrastructure" / "schemas" / "ksi-catalog.json"
FROZEN = REPO / "tests" / "fixtures" / "migration" / "ssp-control-status-2026-11-05.json"

sys.path.insert(0, str(REPO / "scripts"))
import _controls  # noqa: E402


def _load(name, filename):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _projection():
    return _controls.load(FIX_SIGNAL, CATALOG)


# --- parity with the retired SSP -----------------------------------------------------

def test_the_projection_matches_the_last_ssp_control_for_control():
    frozen = json.loads(FROZEN.read_text())
    irs = _projection()
    assert len(irs) == frozen["implemented_requirements"] == 333
    got = {cid: list(v) for cid, v in _controls.status_map(irs).items()}
    assert got == frozen["controls"]


def test_every_projected_control_has_a_statement_and_a_stable_id():
    for ir in _projection():
        assert ir["statements"][0]["remarks"].strip(), ir["control-id"]
        assert ir["uuid"] == _controls.stable_uuid(f"req:{ir['control-id']}")


@pytest.mark.parametrize("missing", ["signal", "catalog"])
def test_the_projection_fails_closed_on_a_missing_input(tmp_path, missing):
    args = {"signal": FIX_SIGNAL, "catalog": CATALOG, missing: tmp_path / "absent.json"}
    with pytest.raises(SystemExit, match="fail-closed"):
        _controls.load(args["signal"], args["catalog"])


def test_a_failing_contributing_ksi_downgrades_its_controls():
    signal = json.loads(FIX_SIGNAL.read_text())
    catalog = json.loads(CATALOG.read_text())
    ksis, _ = _controls.contributing_ksis(catalog)
    cid, owners = next((c, k) for c, k in sorted(ksis.items())
                       if _controls.status_map(_controls.project(signal, catalog))[c][0] == "implemented")
    signal["ksis"] = [{"id": k, "status": "fail"} for k in owners]
    status = _controls.status_map(_controls.project(signal, catalog))[cid][0]
    assert status == "partial"


# --- the SDR carries the per-control record (SDR-CSF-CTF) ---------------------------

def test_the_sdr_summarizes_every_projected_control():
    sdr = _load("build_sdr", "build-sdr.py")
    irs = _projection()
    rows = sdr.build_rev5_controls(irs, json.loads(CATALOG.read_text()))
    assert [r["control_id"] for r in rows] == [ir["control-id"] for ir in irs]
    vocab = {"Implemented", "Partially Implemented", "Planned", "Alternative Implementation", "Not Applicable"}
    for r, ir in zip(rows, irs, strict=True):
        assert r["implementation_status"] in vocab, r["control_id"]
        assert r["mechanisms"].startswith(ir["statements"][0]["remarks"])
        assert r["parameters"] == [{"param_id": sp["param-id"], "values": sp.get("values", [])}
                                   for sp in ir.get("set-parameters", [])]
        for k in ("verification", "validation", "independent_verification", "independent_validation"):
            assert r[k].strip(), (r["control_id"], k)
    # Parameter values the FedRAMP profile sets are carried, not dropped.
    assert sum(len(r["parameters"]) for r in rows) > 200


def test_sdr_verification_points_at_the_contributing_ksis():
    sdr = _load("build_sdr2", "build-sdr.py")
    rows = sdr.build_rev5_controls(_projection(), json.loads(CATALOG.read_text()))
    claimed = [r for r in rows if r["contributing_ksis"] and r["implementation_status"] != "Not Applicable"
               and r["origination"] != "inherited"]
    assert claimed
    for r in claimed:
        assert all(k in r["verification"] for k in r["contributing_ksis"]), r["control_id"]


def test_the_sdr_builder_fails_closed_without_the_inventory(tmp_path):
    r = subprocess.run([sys.executable, str(REPO / "scripts" / "build-sdr.py"),
                        "--catalog", str(CATALOG), "--ksi-signal", str(tmp_path / "absent.json"),
                        "--output", str(tmp_path / "sdr.json"), "--md-output", ""],
                       cwd=tmp_path, capture_output=True, text=True)
    assert r.returncode != 0 and "fail-closed" in r.stderr
    assert not (tmp_path / "sdr.json").exists()


# --- the SSP is retired ------------------------------------------------------------

CONSUMERS = ["build-sdr.py", "build-coverage.py", "build-cmmc.py", "inject-figures.py", "reconcile.py",
             "build-trust-center.py", "build-cpo.py", "build-ksi-signal.py", "_common.py", "verify-published.sh"]


def test_no_builder_and_no_consumer_reads_an_ssp():
    assert not (REPO / "scripts" / "build-oscal-ssp.py").exists()
    for name in CONSUMERS:
        text = (REPO / "scripts" / name).read_text()
        assert "oscal-ssp" not in text and "system-security-plan" not in text, name
    assert "oscal-ssp" not in (REPO / "website" / "assets" / "js" / "trust.js").read_text()


def test_the_ssp_is_neither_built_nor_published_nor_watched():
    for wf in ("deploy-with-opa.yml", "evidence-nightly.yml"):
        text = (REPO / ".github" / "workflows" / wf).read_text()
        assert "build-oscal-ssp" not in text, wf
        assert "aws s3 cp oscal-ssp" not in text and "--bundle oscal-ssp" not in text, wf
    fresh = json.loads((REPO / "infrastructure" / "schemas" / "freshness-config.json").read_text())
    assert not [a for a in fresh["artifacts"] if "oscal-ssp" in a["path"]]


def _steps():
    jobs = yaml.safe_load((REPO / ".github" / "workflows" / "deploy-with-opa.yml").read_text())["jobs"]
    return [s for job in jobs.values() for s in job.get("steps", [])]


def test_the_deploy_deletes_the_published_ssp_and_fails_if_it_is_still_served():
    steps = _steps()
    retired = "oscal-ssp.json oscal-ssp.bundle oscal-ssp.json.intoto.jsonl"
    publish = next(s for s in steps if 'aws s3 rm "s3://$BUCKET_NAME/.well-known/$retired"' in s.get("run", ""))
    check = next(s for s in steps if "retired artifact still published" in s.get("run", ""))
    assert retired in publish["run"] and retired in check["run"]
    assert "'(404)'" in check["run"]
    assert steps.index(publish) < steps.index(check)


def test_the_sdr_takes_the_ssps_provenance_attestation():
    attest = next(s for s in _steps() if "attest() {" in s.get("run", ""))["run"]
    assert "attest security-decision-record.json scripts/build-sdr.py" in attest
    assert "attest oscal-ssp" not in attest
    check = next(s for s in _steps() if "retired artifact still published" in s.get("run", ""))["run"]
    assert "for a in ksi-signal.json security-decision-record.json vdr-report.json iiw.csv; do" in check


def test_the_nightly_verifies_the_published_sdr_and_cpo_before_reconciling():
    jobs = yaml.safe_load((REPO / ".github" / "workflows" / "evidence-nightly.yml").read_text())["jobs"]
    steps = [s for job in jobs.values() for s in job.get("steps", [])]
    fetch = next(s for s in steps if "for art in security-decision-record certification-package-overview" in s.get("run", ""))
    assert "cosign verify-blob" in fetch["run"] and '--certificate-identity "${DEPLOY_SIGNER_IDENTITY}"' in fetch["run"]
    assert "set -euo pipefail" in fetch["run"]
    gate = next(s for s in steps if "scripts/reconcile.py" in s.get("run", ""))
    assert steps.index(fetch) < steps.index(gate)


def test_external_verification_checks_the_sdr_and_cpo_in_the_ssps_place():
    text = (REPO / "scripts" / "verify-published.sh").read_text()
    assert '"$work/security-decision-record.json.intoto.jsonl"' in text
    assert "for art in security-decision-record certification-package-overview boundary-map" in text
    assert "for art in security-decision-record.json vdr-report.json; do" in text


@pytest.mark.parametrize("missing", ["security-decision-record.json", "certification-package-overview.json"])
def test_reconciliation_fails_closed_without_the_sdr_or_cpo(tmp_path, missing):
    clean = REPO / "tests" / "fixtures" / "clean"
    for f in clean.iterdir():
        if f.is_file() and f.name != missing:
            (tmp_path / f.name).write_bytes(f.read_bytes())
    r = subprocess.run([sys.executable, str(REPO / "scripts" / "reconcile.py"), "--artifacts-dir", str(tmp_path),
                        "--decisions", str(clean / "decisions.json"), "--checkov", str(clean / ".checkov.yaml")],
                       capture_output=True, text=True)
    assert r.returncode == 2 and missing in r.stderr
