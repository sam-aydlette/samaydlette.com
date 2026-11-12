"""The per-app build: scripts/build-apps.sh and scripts/apps/<id>/build.sh.

The deploy builds every app in full and the nightly resolves only the dependency
trees the SCA scans, through the same scripts. build-apps.sh checks every app out
first, drops the repository token, and only then runs any build, because builds
run third-party install scripts. The checkout, npm, pip and aws are stubbed: each
test is about what runs, in which mode and with which environment.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _apps  # noqa: E402

pytestmark = pytest.mark.skipif(not shutil.which("zip"), reason="needs zip")

# Records the token's presence for each stubbed command, then does the minimum.
CHECKOUT = """#!/bin/bash
echo "checkout $1 $2 token=${APP_REPO_TOKEN:+set}" >> "$BUILD_LOG"
mkdir -p "$2/frontend" "$2/backend" "$2/reference_data"
echo 'fastapi' > "$2/backend/requirements-lambda.txt"
echo 'def handler(e, c): pass' > "$2/lambda_handler.py"
"""
NPM = """#!/bin/bash
echo "npm $* token=${APP_REPO_TOKEN:+set}" >> "$BUILD_LOG"
[ -n "${FAIL_NPM:-}" ] && exit 1
[ "$1" = run ] && mkdir -p dist && echo '<html></html>' > dist/index.html
exit 0
"""
PYTHON = """#!/bin/bash
if [ "$1" = -m ] && [ "$2" = pip ]; then
  echo "pip $* token=${APP_REPO_TOKEN:+set}" >> "$BUILD_LOG"
  mkdir -p _pkg/fastapi && echo x > _pkg/fastapi/__init__.py
  exit 0
fi
exec "$REAL_PYTHON" "$@"
"""
AWS = """#!/bin/bash
echo "aws $1 $2" >> "$BUILD_LOG"
echo stub-id
"""


def factory(tmp_path):
    """A copy of the build scripts with the checkout stubbed, and stubs on PATH."""
    root = tmp_path / "repo"
    (root / "scripts" / "apps").mkdir(parents=True)
    for f in ("build-apps.sh", "_apps.py", "zip-deterministic.sh"):
        shutil.copy(REPO / "scripts" / f, root / "scripts" / f)
    shutil.copytree(REPO / "scripts" / "apps" / "silk-reeling", root / "scripts" / "apps" / "silk-reeling")
    (root / "scripts" / "app-source.sh").write_text(CHECKOUT)
    (root / "data").mkdir()
    shutil.copy(_apps.MANIFEST, root / "data" / "apps.json")
    (root / "infrastructure").mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("npm", NPM), ("python3", PYTHON), ("aws", AWS)):
        (bin_dir / name).write_text(body)
    for p in [*bin_dir.iterdir(), root / "scripts" / "app-source.sh"]:
        p.chmod(0o755)
    return root, bin_dir


def build(tmp_path, *args, **env):
    root, bin_dir = factory(tmp_path)
    log = tmp_path / "build.log"
    log.touch()
    e = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "BUILD_LOG": str(log),
         "REAL_PYTHON": sys.executable, "APP_REPO_TOKEN": "secret-token", **env}
    r = subprocess.run(["bash", str(root / "scripts" / "build-apps.sh"), *args],
                       cwd=root / "infrastructure", env=e, capture_output=True, text=True, check=False)
    return r, log.read_text().splitlines(), root / "infrastructure"


def test_deps_resolves_the_scanned_trees_and_builds_no_package(tmp_path):
    r, log, infra = build(tmp_path, "deps")
    assert r.returncode == 0, r.stderr
    assert (infra / "_pkg").is_dir() and (infra / "_silk_src" / "frontend").is_dir()
    assert not (infra / "silk-reeling.zip").exists()
    assert not any(ln.startswith(("aws", "npm run")) for ln in log), log
    pip = next(ln for ln in log if ln.startswith("pip"))
    for flag in ("--no-compile", "--platform manylinux2014_x86_64", "--python-version 3.13", "--only-binary=:all:"):
        assert flag in pip, pip


def test_full_builds_the_package(tmp_path):
    r, log, infra = build(tmp_path, "full")
    assert r.returncode == 0, r.stderr
    assert (infra / "silk-reeling.zip").stat().st_size > 0
    assert any(ln.startswith("aws cognito-idp") for ln in log)
    assert "npm run build -- --base=/silk-reeling/ token=" in log


def test_deps_and_full_resolve_the_trees_the_same_way(tmp_path):
    installs = []
    for mode in ("deps", "full"):
        _, log, _ = build(tmp_path / mode, mode)
        installs.append([ln for ln in log if ln.startswith(("pip", "npm ci"))])
    assert installs[0] == installs[1] and len(installs[0]) == 2


@pytest.mark.parametrize("mode", ["deps", "full"])
def test_only_the_checkout_sees_the_token(tmp_path, mode):
    _, log, _ = build(tmp_path, mode)
    assert log[0] == "checkout silk-reeling _silk_src token=set"
    assert all(ln.endswith("token=") for ln in log[1:] if "token=" in ln), log


def test_a_failed_build_fails_the_run(tmp_path):
    r, _, infra = build(tmp_path, "full", FAIL_NPM="1")
    assert r.returncode != 0
    assert not (infra / "silk-reeling.zip").exists()


@pytest.mark.parametrize("args", [[], ["nightly"], ["deps", "a", "b"]])
def test_an_unknown_mode_is_refused(tmp_path, args):
    r, log, _ = build(tmp_path, *args)
    assert r.returncode == 2 and log == []


@pytest.mark.parametrize("build_field, msg", [
    ({"script": "scripts/evil.sh", "src": "_silk_src"}, "must be scripts/apps/silk-reeling/build.sh"),
    ({"script": "scripts/apps/silk-reeling/build.sh", "src": "../outside"}, "must be _<name>"),
    ({"script": "scripts/apps/silk-reeling/build.sh"}, "exactly a script and a src"),
])
def test_a_malformed_build_checks_nothing_out(tmp_path, build_field, msg):
    doc = json.loads(_apps.MANIFEST.read_text())
    doc["apps"][1]["build"] = build_field
    bad = tmp_path / "apps.json"
    bad.write_text(json.dumps(doc))
    r, log, _ = build(tmp_path, "deps", str(bad))
    assert r.returncode != 0 and msg in r.stderr, r.stderr
    assert log == []


def test_a_build_needs_a_source(tmp_path):
    doc = json.loads(_apps.MANIFEST.read_text())
    doc["apps"][0]["build"] = {"script": "scripts/apps/website/build.sh", "src": "_web"}
    bad = tmp_path / "apps.json"
    bad.write_text(json.dumps(doc))
    with pytest.raises(SystemExit, match="has a build but no source"):
        _apps.load(bad)


def test_a_manifest_with_nothing_to_build_builds_nothing(tmp_path):
    doc = json.loads(_apps.MANIFEST.read_text())
    doc["apps"][1]["build"] = None
    none = tmp_path / "apps.json"
    none.write_text(json.dumps(doc))
    r, log, _ = build(tmp_path, "deps", str(none))
    assert r.returncode == 0 and log == [] and "built 0 app(s)" in r.stdout
