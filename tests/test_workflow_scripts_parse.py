"""Every argparse script a workflow runs builds its parser: `--help` exits 0.
A merge that declares one option twice (argparse raises at parse-build time)
otherwise fails only in the deploy, after earlier steps have run."""
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"


def _workflow_scripts():
    names = set()
    for wf in WORKFLOWS.glob("*.yml"):
        names |= set(re.findall(r"scripts/([a-z0-9_-]+\.py)", wf.read_text()))
    return sorted(n for n in names if (REPO / "scripts" / n).is_file()
                  and "argparse" in (REPO / "scripts" / n).read_text())


def test_the_workflows_run_argparse_scripts():
    assert "build-ocr.py" in _workflow_scripts()


@pytest.mark.parametrize("script", _workflow_scripts())
def test_each_workflow_script_builds_its_parser(script):
    r = subprocess.run([sys.executable, str(REPO / "scripts" / script), "--help"], capture_output=True, text=True,
                       timeout=60, cwd=REPO)
    assert r.returncode == 0, r.stderr[-500:]


def test_known_bad_a_twice_declared_option_fails(tmp_path):
    bad = tmp_path / "twice.py"
    bad.write_text((REPO / "tests" / "fixtures" / "argparse-twice.py.txt").read_text())
    assert subprocess.run([sys.executable, str(bad), "--help"], capture_output=True).returncode != 0
