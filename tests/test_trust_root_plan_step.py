"""The trust-root plan step reports drift; it must never fail compliance-check.

GitHub Actions runs `run:` scripts with `bash -e`. `terraform plan
-detailed-exitcode` exits 2 when changes are pending, so an uncaptured call ends
the step with a failure exactly when there is drift to report, and blocks every
deploy while a merged bootstrap change awaits its operator apply.
"""

import subprocess
from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "deploy-with-opa.yml"


def step_script() -> str:
    wf = yaml.safe_load(WORKFLOW.read_text())
    steps = wf["jobs"]["compliance-check"]["steps"]
    return next(s["run"] for s in steps if s.get("name") == "Plan the trust root (bootstrap stack)")


def test_plan_exit_code_is_captured():
    script = step_script()
    plan_line = next(line for line in script.splitlines() if "terraform plan" in line)
    assert "|| rc=$?" in plan_line


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
    result = subprocess.run(
        ["bash", "-e", "-c", step_script()],
        cwd=work,
        env={"PATH": f"{bin_dir}:/usr/bin:/bin", "GITHUB_SHA": "abc"},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
