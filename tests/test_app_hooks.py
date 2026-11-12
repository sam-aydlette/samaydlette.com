"""Each app's deploy hooks: scripts/app-hooks.sh and scripts/apps/<id>/{import,runtime-check}.sh.

The manifest names each app's hooks, and the deploy runs every app's through
app-hooks.sh, so the workflow names no app. terraform, aws and the runtime
check's endpoint are stubbed: each test is about what runs and what fails.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _apps  # noqa: E402

DEPLOY = REPO / ".github" / "workflows" / "deploy-with-opa.yml"

# Logs each call; `terraform output` prints $TF_OUTPUT (or fails when TF_FAIL is set).
TERRAFORM = """#!/bin/bash
echo "terraform $*" >> "$HOOK_LOG"
[ -n "${TF_FAIL:-}" ] && exit 1
case "$1" in
  output) printf '%s' "${TF_OUTPUT:-}" ;;
  state) exit 1 ;;
esac
exit 0
"""
# Only `iam get-role` finds anything; every other lookup comes back empty.
AWS = """#!/bin/bash
echo "aws $*" >> "$HOOK_LOG"
[ "$1 $2" = "iam get-role" ] && exit 0
exit 1
"""


def factory(tmp_path, manifest=None):
    root = tmp_path / "repo"
    (root / "scripts" / "apps").mkdir(parents=True)
    for f in ("app-hooks.sh", "_apps.py", "check-silk-runtime-config.py"):
        shutil.copy(REPO / "scripts" / f, root / "scripts" / f)
    shutil.copytree(REPO / "scripts" / "apps" / "silk-reeling", root / "scripts" / "apps" / "silk-reeling")
    (root / "data").mkdir()
    doc = manifest if manifest is not None else json.loads(_apps.MANIFEST.read_text())
    (root / "data" / "apps.json").write_text(json.dumps(doc))
    (root / "infrastructure").mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("terraform", TERRAFORM), ("aws", AWS)):
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    return root, bin_dir


def run(tmp_path, *args, manifest=None, **env):
    root, bin_dir = factory(tmp_path, manifest)
    log = tmp_path / "hook.log"
    log.touch()
    e = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "HOOK_LOG": str(log), **env}
    r = subprocess.run(["bash", str(root / "scripts" / "app-hooks.sh"), *args],
                       cwd=root / "infrastructure", env=e, capture_output=True, text=True, check=False)
    return r, log.read_text().splitlines(), root


def two_apps():
    """The real manifest plus a second app whose hooks are stubs that log and may fail."""
    doc = json.loads(_apps.MANIFEST.read_text())
    doc["apps"].append({"id": "second-app", "deploy": {
        "import": "scripts/apps/second-app/import.sh",
        "runtime-check": "scripts/apps/second-app/runtime-check.sh"}})
    return doc


def add_second_app(root, fail=False):
    d = root / "scripts" / "apps" / "second-app"
    d.mkdir()
    for f in ("import.sh", "runtime-check.sh"):
        (d / f).write_text(f'echo "second-app {f} cwd=$(basename "$PWD")" >> "$HOOK_LOG"\n'
                           + ("exit 1\n" if fail else ""))


def test_the_manifest_names_each_hook_by_its_fixed_path():
    doc = _apps.load()
    assert _apps.hooks(doc, "import") == [("silk-reeling", "scripts/apps/silk-reeling/import.sh")]
    assert _apps.hooks(doc, "runtime-check") == [("silk-reeling", "scripts/apps/silk-reeling/runtime-check.sh")]


@pytest.mark.parametrize("deploy", [
    {"import": "scripts/apps/other/import.sh"},
    {"import": "scripts/apps/silk-reeling/../../evil.sh"},
    {"runtime-check": "scripts/apps/silk-reeling/import.sh"},
    {"publish": "scripts/apps/silk-reeling/publish.sh"},
    {},
    "scripts/apps/silk-reeling/import.sh",
])
def test_a_malformed_hook_is_refused(tmp_path, deploy):
    doc = json.loads(_apps.MANIFEST.read_text())
    doc["apps"][1]["deploy"] = deploy
    p = tmp_path / "apps.json"
    p.write_text(json.dumps(doc))
    with pytest.raises(SystemExit, match="hook"):
        _apps.load(p)


@pytest.mark.parametrize("args", [[], ["apply"], ["import", "a", "b"]])
def test_an_unknown_kind_is_refused(tmp_path, args):
    r, log, _ = run(tmp_path, *args)
    assert r.returncode == 2 and log == []


def test_every_apps_hook_runs_from_infrastructure(tmp_path):
    root, _ = factory(tmp_path, two_apps())
    add_second_app(root)
    log = tmp_path / "hook.log"
    log.touch()
    e = {**os.environ, "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}", "HOOK_LOG": str(log)}
    r = subprocess.run(["bash", str(root / "scripts" / "app-hooks.sh"), "import"],
                       cwd=root / "infrastructure", env=e, capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stderr
    lines = log.read_text().splitlines()
    assert "second-app import.sh cwd=infrastructure" in lines
    assert "ran 2 import hook(s)" in r.stdout


def test_a_failed_hook_fails_the_run_and_stops_later_hooks(tmp_path):
    doc = two_apps()
    doc["apps"].append({"id": "third-app", "deploy": {"runtime-check": "scripts/apps/third-app/runtime-check.sh"}})
    root, _ = factory(tmp_path, doc)
    add_second_app(root, fail=True)
    (root / "scripts" / "apps" / "third-app").mkdir()
    (root / "scripts" / "apps" / "third-app" / "runtime-check.sh").write_text('echo third >> "$HOOK_LOG"\n')
    log = tmp_path / "hook.log"
    log.touch()
    e = {**os.environ, "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}", "HOOK_LOG": str(log),
         "TF_OUTPUT": ""}
    r = subprocess.run(["bash", str(root / "scripts" / "app-hooks.sh"), "runtime-check"],
                       cwd=root / "infrastructure", env=e, capture_output=True, text=True, check=False)
    assert r.returncode != 0
    assert "third" not in log.read_text().splitlines()


def test_a_manifest_with_no_hooks_runs_nothing(tmp_path):
    doc = json.loads(_apps.MANIFEST.read_text())
    doc["apps"] = [a for a in doc["apps"] if not a.get("deploy")]
    r, log, _ = run(tmp_path, "runtime-check", manifest=doc)
    assert r.returncode == 0 and log == [] and "ran 0 runtime-check hook(s)" in r.stdout


def test_a_bad_manifest_runs_no_hook(tmp_path):
    doc = json.loads(_apps.MANIFEST.read_text())
    doc["apps"][1]["deploy"]["import"] = "scripts/elsewhere.sh"
    r, log, _ = run(tmp_path, "import", manifest=doc)
    assert r.returncode != 0 and log == []


def test_the_runtime_check_fails_when_terraform_output_fails(tmp_path):
    # An empty output means "not deployed" and passes; a failed one must not read as empty.
    r, log, _ = run(tmp_path, "runtime-check", TF_FAIL="1")
    assert r.returncode != 0
    assert "terraform output -raw silk_reeling_auth_config_json" in log


def test_the_runtime_check_passes_when_the_app_is_not_deployed(tmp_path):
    r, _, _ = run(tmp_path, "runtime-check", TF_OUTPUT="")
    assert r.returncode == 0, r.stderr
    assert "Silk Reeling not deployed" in r.stdout


def test_the_import_hook_adopts_only_what_exists(tmp_path):
    r, log, _ = run(tmp_path, "import")
    assert r.returncode == 0, r.stderr
    imports = [line for line in log if line.startswith("terraform import")]
    assert imports == ["terraform import aws_iam_role.silk_reeling[0] samaydlette-com-silk-reeling-role"]


def _steps():
    jobs = yaml.safe_load(DEPLOY.read_text())["jobs"]
    return [s for s in jobs["deploy"]["steps"]]


def test_the_deploy_runs_app_hooks_and_names_no_app():
    steps = _steps()
    names = [s.get("name") for s in steps]
    imp = next(s for s in steps if "app-hooks.sh import" in s.get("run", ""))
    chk = next(s for s in steps if "app-hooks.sh runtime-check" in s.get("run", ""))
    assert imp["if"] == "${{ env.REBUILD_STATE == 'true' }}"
    for s in (imp, chk):
        assert s["working-directory"] == "infrastructure"
        assert "silk" not in (s["name"] + s["run"]).lower()
    # Import before the plan; the runtime check after apply, before anything is published.
    i = names.index
    assert names.index(imp["name"]) < i("Generate fresh Terraform plan")
    assert i("Terraform Apply") < names.index(chk["name"]) < i("Cache-bust website assets")
    assert not any("check-silk-runtime-config" in s.get("run", "") or "import_silk" in s.get("run", "")
                   for s in steps)
