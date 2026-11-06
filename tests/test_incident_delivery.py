"""Incident reports reach a SIMULATED FedRAMP and agency recipient, and the
publisher's role is proved before the SDR is built (IEC-CSO-IIR/OIR/FIR/AIR).

scripts/deliver-incident-reports.py "delivers" every report the incident log
lists (nothing is sent) and fails the deploy when one cannot be delivered;
scripts/check-incident-role.py assumes the incident publisher's role from the
deploy job. Known-bad fixtures under tests/fixtures/incidents/ each fail for
one reason."""

import importlib.util
import io
import json
import re
import shutil
import subprocess
import sys
import urllib.error
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "incidents"
WORKFLOW = (REPO / ".github" / "workflows" / "deploy-with-opa.yml").read_text()
PUBLISHER = (REPO / ".github" / "workflows" / "incident-reports.yml").read_text()


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


deliver = _load("deliver_incident_reports", "deliver-incident-reports.py")
role = _load("check_incident_role", "check-incident-role.py")


@pytest.fixture
def built(tmp_path):
    """The committed register's reports, built as the deploy builds them."""
    (tmp_path / "vdr.json").write_text('{"findings": []}')
    subprocess.run([sys.executable, str(REPO / "scripts" / "build-incident-report.py"), "--incidents",
                    str(REPO / "data" / "incidents.json"), "--vdr", str(tmp_path / "vdr.json"),
                    "--out-dir", str(tmp_path)], check=True, capture_output=True)
    return tmp_path


def _log(d):
    return json.loads((d / "incident-reports.json").read_text())


# --- delivery -------------------------------------------------------------------

def test_every_report_is_delivered_to_a_simulated_fedramp_and_agency_recipient(built):
    out, problems = deliver.deliver(_log(built), built)
    assert problems == []
    listed = [r["file"] for i in _log(built)["incidents"] for r in i.get("reports", [])]
    assert listed and [d["file"] for d in out["deliveries"]] == listed
    for d in out["deliveries"]:
        assert {r["kind"] for r in d["recipients"]} == {"fedramp", "agency"}
        assert all(r["simulated"] is True and "(simulated)" in r["recipient"] for r in d["recipients"])
        assert all(r["receipt_sha256"] == d["sha256"] for r in d["recipients"])
    assert out["simulation"] is True and out["notice"].startswith("SIMULATION.")
    assert out["summary"]["messages_actually_sent"] == 0


def test_the_cli_writes_the_delivery_log_and_it_carries_no_address(built):
    assert deliver.main(["--dir", str(built)]) == 0
    text = (built / "incident-deliveries.json").read_text()
    assert not re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)
    assert not re.search(r"\b\d{12}\b", text)


def _with_fixture(built, name, keep):
    shutil.copy(FIX / f"{name}.json", built / "incident-reports.json")
    for p in built.glob("incident-INC-*.json"):
        if p.name not in keep:
            p.unlink()
    return deliver.main(["--dir", str(built)])


@pytest.mark.parametrize("name,keep,reason", [
    ("delivery-hash-mismatch", {"incident-INC-2026-001-01-initial.json"}, "bytes differ from the sha256"),
    ("delivery-missing-report", set(), "is listed but missing"),
    ("delivery-not-reportable", {"incident-INC-2026-001-01-initial.json"}, "evaluated not reportable"),
])
def test_known_bad_logs_fail_delivery_and_write_nothing(built, capsys, name, keep, reason):
    assert _with_fixture(built, name, keep) == 1
    out = capsys.readouterr().out
    assert reason in out and not (built / "incident-deliveries.json").exists()
    assert len([ln for ln in out.splitlines() if ln.startswith("::error::")]) == 1, out


def test_an_unlisted_report_file_fails_delivery(built):
    (built / "incident-INC-2099-999-01-initial.json").write_text("{}")
    _, problems = deliver.deliver(_log(built), built)
    assert problems == ["incident-INC-2099-999-01-initial.json: a report file the incident log does not list"]


def test_a_report_that_does_not_validate_against_fedramps_schema_fails_delivery(built):
    log = _log(built)
    r = log["incidents"][0]["reports"][0]
    p = built / r["file"]
    doc = json.loads(p.read_text())
    doc.pop("reportType")
    p.write_text(json.dumps(doc))
    r["sha256"] = deliver.sha256(p)
    _, problems = deliver.deliver(log, built)
    assert len(problems) == 1 and "does not validate" in problems[0]


def test_delivery_runs_before_signing_in_the_deploy_and_before_publishing_in_the_publisher():
    build = WORKFLOW[WORKFLOW.index("- name: Build incident reports (IIR, OIR, FIR)"):]
    build = build[:build.index("\n    - name: ")]
    assert build.index("deliver-incident-reports.py --dir .") < build.index("cosign sign-blob")
    assert "|| true" not in build
    assert WORKFLOW.index("- name: Build incident reports") < WORKFLOW.index("- name: Build Security Decision Record")
    for f in ("incident-deliveries.json", "incident-deliveries.bundle"):
        assert f'aws s3 cp {f} "s3://$BUCKET_NAME/.well-known/{f}"' in WORKFLOW
        assert f'put {f} "application/json"' in PUBLISHER
    step = PUBLISHER.index("- name: Deliver incident reports (simulated recipients; nothing sent)")
    assert PUBLISHER.index("- name: Build incident reports") < step < PUBLISHER.index("- name: Sign incident reports")
    cfg = json.loads((REPO / "infrastructure" / "schemas" / "freshness-config.json").read_text())
    e = [a for a in cfg["artifacts"] if a["path"] == ".well-known/incident-deliveries.json"]
    assert len(e) == 1 and e[0]["signed"] and e[0]["note"].startswith("SIMULATION")


# --- the role, proved from the deploy job -------------------------------------------

@pytest.mark.parametrize("fixture,ok", [("sts-assumed.xml", True), ("sts-access-denied.xml", False),
                                        ("sts-wrong-role.xml", False)])
def test_sts_responses(fixture, ok):
    status = 403 if "denied" in fixture else 200
    problems = role.parse_sts(status, (FIX / fixture).read_text())
    assert (problems == []) is ok, problems


class _Resp(io.BytesIO):
    def __init__(self, body, status=200):
        super().__init__(body.encode())
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _opener(sts_fixture):
    calls = []

    def opener(req, timeout=None):
        calls.append(req)
        if req.full_url.startswith("https://token.example/"):
            assert "audience=sts.amazonaws.com" in req.full_url
            return _Resp(json.dumps({"value": "oidc-token"}))
        assert req.full_url == "https://sts.us-east-2.amazonaws.com/" and b"AssumeRoleWithWebIdentity" in req.data
        body = (FIX / sts_fixture).read_text()
        if "denied" in sts_fixture:
            raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, io.BytesIO(body.encode()))
        return _Resp(body)
    return opener, calls


ENV = {"INCIDENT_REPORTS_ROLE_ARN": "arn:aws:iam::000000000000:role/github-actions-incident-reports-oidc",
       "ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.example/?x=1", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "t",
       "AWS_REGION": "us-east-2"}


def test_the_deploy_proves_the_role_by_assuming_it(capsys):
    opener, calls = _opener("sts-assumed.xml")
    assert role.main(env=ENV, opener=opener) == 0 and len(calls) == 2
    out = capsys.readouterr().out
    assert "000000000000" not in out and "oidc-token" not in out and "EXAMPLE" not in out


@pytest.mark.parametrize("fixture", ["sts-access-denied.xml", "sts-wrong-role.xml"])
def test_a_role_that_cannot_be_assumed_fails_the_deploy(capsys, fixture):
    opener, _ = _opener(fixture)
    assert role.main(env=ENV, opener=opener) == 1
    assert "000000000000" not in capsys.readouterr().out


def test_no_variable_or_no_oidc_token_fails_the_deploy():
    assert role.main(env={**ENV, "INCIDENT_REPORTS_ROLE_ARN": ""}, opener=None) == 1
    env = {k: v for k, v in ENV.items() if not k.startswith("ACTIONS_")}
    assert role.main(env=env, opener=_opener("sts-assumed.xml")[0]) == 1


def test_the_role_check_runs_in_the_deploy_job_before_the_sdr_build():
    deploy_job = WORKFLOW[WORKFLOW.index("\n  deploy:\n"):]
    deploy_job = deploy_job[:re.search(r"\n  [a-z][\w-]*:\n", deploy_job[1:]).start() + 1]
    i = deploy_job.index("- name: Incident report publisher role can be assumed")
    assert i < deploy_job.index("- name: Build Security Decision Record")
    step = deploy_job[i:deploy_job.index("\n    - name: ", i)]
    assert "python3 scripts/check-incident-role.py" in step and "continue-on-error" not in step
    assert "vars.AWS_INCIDENT_REPORTS_ROLE_ARN" in step


def test_the_role_trusts_the_deploy_environment():
    tf = (REPO / "infrastructure" / "bootstrap" / "incident-reports.tf").read_text()
    assert "environment:${var.deploy_environment}" in tf
    assert "environment:${var.incident_reports_environment}" in tf


def test_the_region_cannot_redirect_the_token_to_another_host():
    opener, calls = _opener("sts-assumed.xml")
    assert role.main(env={**ENV, "AWS_REGION": "evil.example/x"}, opener=opener) == 1 and calls == []
