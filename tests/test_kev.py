"""Known exploited vulnerabilities (VDR-CSO-AKE, VDR-TFR-KEV).

Pins:
- the deploy runs a KEV gate over every Grype scan and the open Dependabot
  alerts before the Terraform plan, the apply and the website sync, and it
  stops on a KEV (a related CVE of a GHSA match counts) or on a missing input;
- the VDR keeps the catalog's due date for each KEV finding, makes it the
  remediation deadline when it is earlier than the Class C one, publishes it
  even when the finding needs no remediation, and marks it overdue once passed;
- the VDT carries the due date in providerExtensions.
"""
import importlib.util
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "kev"
GATE = REPO / "scripts" / "kev-gate.py"

spec = importlib.util.spec_from_file_location("vdr_kev", REPO / "scripts" / "build-vdr-report.py")
vdr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vdr)


def _gate(*args):
    env = {k: v for k, v in os.environ.items() if k not in ("GATE_MODES_FILE", "GATE_EVENTS_FILE")}
    return subprocess.run([sys.executable, str(GATE), "--kev", str(FIX / "kev-catalog.json"), *args],
                          capture_output=True, text=True, env=env)


def test_a_clean_scan_passes_the_kev_gate():
    r = _gate("--grype", str(FIX / "grype-clean.json"), "--dependabot", str(FIX / "dependabot-none.json"))
    assert r.returncode == 0, r.stderr
    assert "0 known exploited" in r.stdout


def test_a_kev_in_a_grype_scan_stops_the_deploy_with_its_due_date():
    r = _gate("--grype", str(FIX / "grype-clean.json"), str(FIX / "grype-kev.json"),
              "--dependabot", str(FIX / "dependabot-none.json"))
    assert r.returncode == 1
    assert "CVE-2099-1111 in thumbnailer@3.1.0 (grype-kev.json) is in the CISA KEV catalog, due 2026-10-22" in r.stderr


def test_a_kev_in_a_dependabot_alert_stops_the_deploy():
    r = _gate("--grype", str(FIX / "grype-clean.json"), "--dependabot", str(FIX / "dependabot-kev.json"))
    assert r.returncode == 1 and "CVE-2099-2222 in example-lib" in r.stderr


def test_a_missing_input_stops_the_kev_gate():
    r = _gate("--grype", str(FIX / "absent.json"), "--dependabot", str(FIX / "dependabot-none.json"))
    assert r.returncode != 0 and "not found" in r.stderr


def test_the_kev_gate_runs_before_anything_is_activated():
    jobs = yaml.safe_load((REPO / ".github" / "workflows" / "deploy-with-opa.yml").read_text())["jobs"]
    for job in jobs.values():
        names = [s.get("name") for s in job.get("steps", [])]
        if "Terraform Apply" not in names:
            continue
        gate = names.index("KEV gate before apply (VDR-CSO-AKE)")
        assert gate > names.index("Detection gate (G7)")
        for later in ("Generate fresh Terraform plan", "Terraform Apply", "Sync Website Content"):
            assert gate < names.index(later), later
        run = job["steps"][gate]["run"]
        for f in ("grype-python.json", "grype-js.json", "grype-lambda.json", "grype-a11y.json",
                  "dependabot-alerts.json", "kev-catalog.json"):
            assert f in run
        return
    raise AssertionError("no job applies Terraform")


NOW = datetime(2026, 11, 5, 15, 0, tzinfo=timezone.utc)


def _kev_finding(**kw):
    return {"tracking_id": "grype-CVE-2099-1111-thumbnailer", "source": "grype", "tool_id": "CVE-2099-1111",
            "title": "x", "resource": "pkg:npm/thumbnailer@3.1.0", "cve": "CVE-2099-1111",
            "severity": "High", "detected_at": "2026-11-01T00:00:00+00:00", **kw}


def test_the_catalog_due_date_is_kept_and_bounds_the_deadline():
    kev = vdr.ingest_kev(str(FIX / "kev-catalog.json"))
    assert "CVE-2099-1111" in kev and kev.entries["CVE-2099-1111"]["due_date"] == "2026-10-22"
    report, _ = vdr.build_report([_kev_finding()], [], kev, {}, now=NOW)
    f = report["findings"][0]
    assert f["is_kev"] and f["kev_due_at"] == "2026-10-22T00:00:00+00:00"
    assert f["kev_date_added"] == "2026-10-01" and f["kev_overdue"] is True and f["is_overdue"] is True
    assert f["remediation_due_at"] == "2026-10-22T00:00:00+00:00"   # earlier than the Class C deadline
    assert vdr.kev_dates(kev, "CVE-2099-2222", NOW)[0] == "2026-11-05T00:00:00+00:00"
    assert vdr.kev_dates(kev, "CVE-2099-0000", NOW) == (None, None, False)


def test_the_vdt_names_the_kev_due_date():
    spec2 = importlib.util.spec_from_file_location("cr26_kev", REPO / "scripts" / "build-cr26-vdr.py")
    cr26 = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(cr26)
    kev = vdr.ingest_kev(str(FIX / "kev-catalog.json"))
    report, _ = vdr.build_report([_kev_finding()], [], kev, {}, now=NOW)
    rec = cr26.detail(report["findings"][0])
    assert rec["providerExtensions"]["kevDueAt"] == "2026-10-22T00:00:00+00:00"
    assert rec["providerExtensions"]["kevOverdue"] is True
