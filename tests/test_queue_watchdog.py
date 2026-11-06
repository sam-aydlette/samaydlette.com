"""The deploy's queue watchdog cancels a run only for a job that never got a
runner, never for one correctly waiting on its dependencies (any job with
`needs:`, including the jobs of a called workflow, which GitHub names
"<caller job name> / <called job name>"). Its exclusion list is derived here
from the workflow's own jobs, so a new dependent job cannot be forgotten, and
the deploy's failure alert covers every job that can stop a deploy on main."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "deploy-with-opa.yml"
FIX = REPO / "tests" / "fixtures" / "queue-watchdog"


def _watchdog_step(text):
    jobs = yaml.safe_load(text)["jobs"]
    return next(s["run"] for s in jobs["queue-watchdog"]["steps"] if "DEPENDENT=" in s.get("run", ""))


def excluded(text):
    return set(json.loads(re.search(r"DEPENDENT='(\[.*?\])'", _watchdog_step(text)).group(1)))


def unexcluded_dependents(text):
    """Names of jobs that wait on others (or are the watchdog) but are not excluded."""
    jobs = yaml.safe_load(text)["jobs"]
    dependent = {j.get("name", k) for k, j in jobs.items() if j.get("needs")} | {jobs["queue-watchdog"]["name"]}
    return sorted(dependent - excluded(text))


def test_every_dependent_job_is_excluded():
    assert unexcluded_dependents(WORKFLOW.read_text()) == []


def test_no_independent_job_is_excluded():
    jobs = yaml.safe_load(WORKFLOW.read_text())["jobs"]
    independent = {j.get("name", k) for k, j in jobs.items() if not j.get("needs") and k != "queue-watchdog"}
    assert independent and not (independent & excluded(WORKFLOW.read_text()))


def test_known_bad_a_dependent_job_left_out_is_reported():
    assert unexcluded_dependents((FIX / "missing-dependent.yml").read_text()) == ["Prove the publisher"]


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq is on every GitHub runner; not installed here")
def test_the_filter_ignores_called_workflow_jobs_and_finds_a_stuck_one():
    step = _watchdog_step(WORKFLOW.read_text())
    dependent = re.search(r"DEPENDENT='(\[.*?\])'", step).group(1)
    filt = re.search(r"FILTER='(.*?)'\"\$DEPENDENT\"'(.*?)'\n", step)
    program = filt.group(1) + dependent + filt.group(2)
    out = subprocess.run(["jq", "-r", program], input=(FIX / "jobs.json").read_text(),
                         capture_output=True, text=True, check=True).stdout.strip()
    # Only the job with no runner, and a name that merely starts like a
    # dependent one (no " / ") is still watched.
    assert out == "Security Scan, Simulated assessorX"


def test_notify_fires_on_every_job_that_can_stop_a_deploy_on_main():
    jobs = yaml.safe_load(WORKFLOW.read_text())["jobs"]
    notify = jobs["notify"]
    dependent = {k for k, j in jobs.items() if j.get("needs") and k != "notify"}
    for need in {"test", "security-scan", "compliance-check", "simulated-assessor", "deploy", "package-maintainer", "incident-publisher",
                 "post-deploy-assessor", "post-deploy-binding"} | dependent:
        assert need in notify["needs"], need
        assert f"needs.{need}.result == 'failure'" in notify["if"], need


def test_the_test_job_gets_no_oidc_token():
    jobs = yaml.safe_load(WORKFLOW.read_text())["jobs"]
    assert jobs["test"]["permissions"] == {"contents": "read"}
