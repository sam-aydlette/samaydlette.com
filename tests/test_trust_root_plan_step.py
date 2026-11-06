"""The trust-root plan step reports drift; it must never fail compliance-check.

GitHub Actions runs `run:` scripts with `bash -e`. `terraform plan
-detailed-exitcode` exits 2 when changes are pending, so an uncaptured call ends
the step with a failure exactly when there is drift to report, and blocks every
deploy while a merged bootstrap change awaits its operator apply.
"""

import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "deploy-with-opa.yml"


def step_script() -> str:
    wf = yaml.safe_load(WORKFLOW.read_text())
    steps = wf["jobs"]["compliance-check"]["steps"]
    return next(s["run"] for s in steps if s.get("name") == "Plan the trust root (bootstrap stack)")


def test_plan_exit_code_is_captured():
    script = step_script()
    plan_line = next(line for line in script.splitlines() if "terraform plan" in line)
    assert "|| rc=$?" in plan_line


def _stub_gate(root, code):
    """A stand-in for scripts/opa-gate-plan.sh at the step's relative path."""
    (root / "scripts").mkdir(exist_ok=True)
    gate = root / "scripts" / "opa-gate-plan.sh"
    gate.write_text(f"#!/bin/sh\necho gated \"$1\" > \"$2\"\nexit {code}\n")
    gate.chmod(0o755)


def test_script_survives_bash_e_when_changes_are_pending(tmp_path):
    # Replace terraform/python with stubs: plan reports changes (exit 2), show and
    # the summarizer succeed. Under `bash -e` the script must still exit 0.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "terraform").write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        "  plan) exit 2 ;;\n"
        "  state) echo aws_iam_role.deploy ;;\n"
        "  show) echo '{}' ;;\n"
        "esac\n"
        "exit 0\n"
    )
    (bin_dir / "python3").write_text("#!/bin/sh\necho changes_pending\nexit 0\n")
    for f in bin_dir.iterdir():
        f.chmod(0o755)
    work = tmp_path / "infrastructure" / "bootstrap"
    work.mkdir(parents=True)
    (tmp_path / "infrastructure" / "trust-root-plan.json").write_text('{"status": "changes_pending"}')
    _stub_gate(tmp_path, 0)
    result = subprocess.run(
        ["bash", "-e", "-c", step_script()],
        cwd=work,
        env={"PATH": f"{bin_dir}:/usr/bin:/bin", "GITHUB_SHA": "abc"},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


# ---------------------------------------------------------------------------
# One bootstrap snapshot per deploy (2026-10-05). The plan above runs before the
# approval gate; the deploy job reads the state after it. The plan records the
# state version it read, the deploy job reads the state once and checks that
# version, and the snapshot it writes is cleaned up whatever happens.
# ---------------------------------------------------------------------------
import shutil  # noqa: E402

import pytest  # noqa: E402

LINEAGE = "7a1c0f2e-0000-4000-8000-000000000000"
STATE_PULL = '{"version": 4, "serial": %d, "lineage": "' + LINEAGE + '", "resources": []}'


def deploy_steps():
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]["deploy"]["steps"]


def deploy_step(name):
    return next(s for s in deploy_steps() if s.get("name") == name)


def stubs(tmp_path, serial):
    """terraform that reports a state at `serial`; python3 that records its args."""
    if not shutil.which("jq"):
        pytest.skip("jq not installed (the GitHub runner has it)")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "terraform").write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        "  plan) exit 2 ;;\n"
        '  state) if [ "$2" = pull ]; then echo \'' + STATE_PULL % serial + "'; else echo aws_iam_role.deploy; fi ;;\n"
        "  show) echo '{\"values\": {}}' ;;\n"
        "esac\n"
        "exit 0\n"
    )
    (bin_dir / "python3").write_text(
        '#!/bin/sh\necho "$@" >> "$ARGS_LOG"\necho \'{"status": "changes_pending"}\'\nexit 0\n')
    for f in bin_dir.iterdir():
        f.chmod(0o755)
    work = tmp_path / "infrastructure" / "bootstrap"
    work.mkdir(parents=True)
    (tmp_path / "infrastructure" / "trust-root-plan.json").write_text('{"status": "changes_pending"}')
    _stub_gate(tmp_path, 0)
    return bin_dir, work


def run(script, bin_dir, work, tmp_path):
    log = tmp_path / "args.log"
    result = subprocess.run(
        ["bash", "-e", "-c", script], cwd=work,
        env={"PATH": f"{bin_dir}:/usr/bin:/bin", "GITHUB_SHA": "abc", "ARGS_LOG": str(log)},
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    return log.read_text() if log.exists() else ""


def test_the_plan_records_the_state_version_it_read(tmp_path):
    bin_dir, work = stubs(tmp_path, 41)
    args = run(step_script(), bin_dir, work, tmp_path)
    assert f"--state-serial 41 --state-lineage {LINEAGE}" in args


def test_the_deploy_reads_the_state_once_and_checks_the_plan_against_it(tmp_path):
    bin_dir, work = stubs(tmp_path, 42)
    step = deploy_step("Read the trust-root state (bootstrap stack, read-only)")
    args = run(step["run"], bin_dir, work, tmp_path)
    assert f"--reconcile-state 42 {LINEAGE} --in ../trust-root-plan.json" in args
    snapshot = tmp_path / "infrastructure" / "tfstate-bootstrap.json"
    assert snapshot.read_text().strip() == '{"values": {}}'
    assert snapshot.stat().st_mode & 0o077 == 0  # owner-only: state can hold secrets


def test_the_inventory_and_the_boundary_map_use_that_one_snapshot():
    ksi = deploy_step("Build deploy-time KSI signal")
    assert ksi["env"]["BOOTSTRAP_STATE_JSON"] == "tfstate-bootstrap.json"
    boundary = deploy_step("Build the boundary map")["run"]
    assert "-chdir=bootstrap" not in boundary and "tfstate-bootstrap.json" in boundary


def test_the_snapshot_is_removed_whatever_happens():
    last = deploy_steps()[-1]
    assert last.get("if") == "always()" and "rm -f infrastructure/tfstate-bootstrap.json" in last["run"]


# ---------------------------------------------------------------------------
# The trust root faces the deploy's OPA gate (KSI-IAM-SNU, KSI-SVC-VCM): its
# plan is written as JSON and gated by scripts/opa-gate-plan.sh; a violation
# stops the job, its per-resource results feed the KSI signal's plan credit.
# ---------------------------------------------------------------------------


def _run_step(tmp_path, plan_json, gate=None):
    """Run the step with terraform stubbed to plan `plan_json` (a path whose
    text `terraform show -json` prints) and either the real gate (gate=None,
    copied with the policy into the temporary tree) or a stub exiting `gate`."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "terraform").write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        "  plan) exit 2 ;;\n"
        "  state) echo aws_iam_role.deploy ;;\n"
        f"  show) cat '{plan_json}' ;;\n"
        "esac\n"
        "exit 0\n"
    )
    (bin_dir / "python3").write_text("#!/bin/sh\necho changes_pending\nexit 0\n")
    for f in bin_dir.iterdir():
        f.chmod(0o755)
    work = tmp_path / "infrastructure" / "bootstrap"
    work.mkdir(parents=True)
    (tmp_path / "infrastructure" / "trust-root-plan.json").write_text('{"status": "changes_pending"}')
    if gate is None:
        (tmp_path / "scripts").mkdir()
        shutil.copy(REPO / "scripts" / "opa-gate-plan.sh", tmp_path / "scripts" / "opa-gate-plan.sh")
        shutil.copytree(REPO / "infrastructure" / "policy", tmp_path / "infrastructure" / "policy")
        path = f"{bin_dir}:{Path(shutil.which('opa')).parent}:/usr/bin:/bin"
    else:
        _stub_gate(tmp_path, gate)
        path = f"{bin_dir}:/usr/bin:/bin"
    return subprocess.run(["bash", "-e", "-c", step_script()], cwd=work,
                          env={"PATH": path, "GITHUB_SHA": "abc"}, capture_output=True, text=True)


def test_trust_root_plan_is_gated_and_its_results_kept(tmp_path):
    plan = tmp_path / "plan.json"
    plan.write_text("{}")
    result = _run_step(tmp_path, plan, gate=0)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "infrastructure" / "trust-root-validations.ndjson").read_text().startswith("gated")
    assert not (tmp_path / "infrastructure" / "bootstrap" / "trust-root-plan-full.json").exists()


def test_a_trust_root_violation_stops_the_job(tmp_path):
    plan = tmp_path / "plan.json"
    plan.write_text("{}")
    result = _run_step(tmp_path, plan, gate=1)
    assert result.returncode != 0
    assert "violates policy" in result.stdout
    # The full plan (account identifiers) is removed even when the gate fails.
    assert not (tmp_path / "infrastructure" / "bootstrap" / "trust-root-plan-full.json").exists()


def _opa1():
    opa = shutil.which("opa")
    return bool(opa) and "Rego Version: v1" in subprocess.run([opa, "version"], capture_output=True, text=True).stdout


@pytest.mark.skipif(not _opa1(), reason="requires the pinned OPA >= 1.x on PATH")
def test_the_real_gate_stops_curious_carl_in_the_trust_root(tmp_path):
    """The committed known-bad plan, offered as the trust root's plan, fails the step."""
    result = _run_step(tmp_path, REPO / "tests" / "fixtures" / "plans" / "log-read-grant-curious-carl.json")
    assert result.returncode != 0, result.stdout
    assert "log_read_grant_unexpected" in result.stdout


@pytest.mark.skipif(not _opa1(), reason="requires the pinned OPA >= 1.x on PATH")
def test_the_real_gate_passes_a_compliant_trust_root(tmp_path):
    result = _run_step(tmp_path, REPO / "tests" / "fixtures" / "plans" / "compliant-stack.json")
    assert result.returncode == 0, result.stdout + result.stderr
    rows = (tmp_path / "infrastructure" / "trust-root-validations.ndjson").read_text().splitlines()
    assert rows and all('"kind":"infrastructure"' in r for r in rows)


def test_the_compliance_check_reads_the_trust_root_results():
    wf = yaml.safe_load(WORKFLOW.read_text())
    step = next(s for s in wf["jobs"]["compliance-check"]["steps"] if s.get("name") == "Run OPA Compliance Check")
    assert step["env"]["TRUST_ROOT_VALIDATIONS"] == "trust-root-validations.ndjson"
    assert "TRUST_ROOT_VALIDATIONS" in (REPO / "scripts" / "terraform-plan.sh").read_text()
