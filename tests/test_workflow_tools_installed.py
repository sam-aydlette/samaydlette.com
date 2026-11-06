"""Every job that runs cosign installs it first.

GitHub's ubuntu runner image does not ship cosign. A job that calls it (directly,
or through tools/simulated-assessor/assess.py, whose cosign_verify shells out to
it) without the installer step crashes with FileNotFoundError. The unit tests of
assess.py stub cosign_verify, so only the workflow can show the binary is there.
"""
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO / ".github" / "workflows"
FIXTURE = REPO / "tests" / "fixtures" / "workflows" / "cosign-not-installed.yml"

# Scripts that shell out to cosign.
_COSIGN_CALLERS = ("tools/simulated-assessor/assess.py",)


def _needs_cosign(run):
    return "cosign " in run or any(c in run for c in _COSIGN_CALLERS)


def jobs_missing_cosign(workflow):
    """Names of jobs that use cosign in a step before any installer step."""
    missing = []
    for name, job in (workflow.get("jobs") or {}).items():
        installed = False
        for step in job.get("steps") or []:
            if "sigstore/cosign-installer@" in str(step.get("uses", "")):
                installed = True
            elif _needs_cosign(str(step.get("run", ""))) and not installed:
                missing.append(name)
                break
    return missing


def test_every_job_that_runs_cosign_installs_it_first():
    bad = {}
    for path in sorted(WORKFLOWS.glob("*.yml")):
        missing = jobs_missing_cosign(yaml.safe_load(path.read_text()))
        if missing:
            bad[path.name] = missing
    assert bad == {}


def test_the_simulated_assessor_job_installs_cosign():
    wf = yaml.safe_load((WORKFLOWS / "simulated-assessor.yml").read_text())
    uses = [str(s.get("uses", "")) for s in wf["jobs"]["assess"]["steps"]]
    assert any("sigstore/cosign-installer@" in u for u in uses)


def test_known_bad_an_assessor_job_without_cosign_is_caught():
    assert jobs_missing_cosign(yaml.safe_load(FIXTURE.read_text())) == ["assess"]
