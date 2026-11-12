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
import yaml

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
         "REAL_PYTHON": sys.executable, "APP_REPO_TOKEN": "secret-token",
         "SILK_COGNITO_CLIENT_ID": "abc123clientid", **env}
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
    assert not any(ln.startswith("aws") for ln in log), "the build needs no cloud credentials"
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


@pytest.mark.parametrize("client_id", ["", "None x", "abc;rm -rf /", "a" * 129])
def test_full_refuses_a_missing_or_malformed_client_id(tmp_path, client_id):
    r, _, infra = build(tmp_path, "full", SILK_COGNITO_CLIENT_ID=client_id)
    assert r.returncode != 0 and "SILK_COGNITO_CLIENT_ID" in r.stderr
    assert not (infra / "silk-reeling.zip").exists()


def test_deps_needs_no_client_id(tmp_path):
    r, _, _ = build(tmp_path, "deps", SILK_COGNITO_CLIENT_ID="")
    assert r.returncode == 0, r.stderr


WF = REPO / ".github" / "workflows"


def _on(doc):
    # PyYAML reads the bare key `on` as True.
    return doc.get("on", doc.get(True))


def test_apps_build_and_scan_without_cloud_credentials():
    doc = yaml.safe_load((WF / "app-build.yml").read_text())
    assert doc["permissions"] == {"contents": "read"}
    assert "workflow_call" in _on(doc)
    for job in doc["jobs"].values():
        assert job["permissions"] == {"contents": "read"}
        assert "environment" not in job
        uses = [st.get("uses", "") for st in job["steps"]]
        assert not any("configure-aws-credentials" in u for u in uses)
        checkout = next(st for st in job["steps"] if "actions/checkout" in st.get("uses", ""))
        assert checkout["with"]["persist-credentials"] is False
        runs = " ".join(st.get("run", "") for st in job["steps"])
        assert "build-apps.sh" in runs and "scan-sca.sh" in runs and "aws " not in runs


def test_app_build_uses_the_deploys_node_version():
    deploy = yaml.safe_load((WF / "deploy-with-opa.yml").read_text())
    job = yaml.safe_load((WF / "app-build.yml").read_text())["jobs"]["build"]
    node = next(st for st in job["steps"] if "setup-node" in st.get("uses", ""))
    assert str(node["with"]["node-version"]) == str(deploy["env"]["NODE_VERSION"])


def test_the_deploy_ships_what_the_credential_free_job_built_and_scanned():
    doc = yaml.safe_load((WF / "deploy-with-opa.yml").read_text())
    jobs = doc["jobs"]
    apps = jobs["apps"]
    assert apps["uses"] == "./.github/workflows/app-build.yml"
    assert apps["with"]["mode"] == "full" and apps["permissions"] == {"contents": "read"}
    assert "compliance-check" in apps["needs"] and "steps.appcfg" in jobs["compliance-check"]["outputs"]["silk_cognito_client_id"]
    assert apps["if"] == jobs["deploy"]["if"]
    assert "apps" in jobs["deploy"]["needs"] and "apps" in jobs["notify"]["needs"]
    steps = jobs["deploy"]["steps"]
    names = [st.get("name", "") for st in steps]
    runs = " ".join(st.get("run", "") for st in steps)
    for direct in ("build-apps.sh", "scan-sca.sh", "app-source.sh", "npm run build"):
        assert direct not in runs, f"the deploy job runs {direct} itself"
    download = names.index("Download the app packages and scans")
    # The artifact lands apart, and only the expected names are taken from it.
    assert steps[download]["with"] == {"name": "app-build", "path": "infrastructure/_app-build"}
    take = names.index("Take the expected app files")
    assert steps[take]["run"] == "bash ../scripts/take-app-build.sh full _app-build"
    assert download < take < names.index("Detection gate (G7)") < names.index("Terraform Apply")
    app_build = (WF / "app-build.yml").read_text()
    assert "infrastructure/*.zip" not in app_build, "upload only the packages the deploy ships"


# --- taking the expected files out of the artifact (scripts/take-app-build.sh)

TAKE = REPO / "scripts" / "take-app-build.sh"
SCANS = [n for t in _apps.trees(_apps.load()) for n in (t["sbom"], _apps.grype_file(t))] + ["grype.json"]


def take(tmp_path, mode, files, manifest=None):
    work = tmp_path / "infrastructure"
    art = work / "_app-build"
    art.mkdir(parents=True)
    for name, body in files.items():
        (art / name).write_text(body)
    args = ["bash", str(TAKE), mode, "_app-build"] + ([str(manifest)] if manifest else [])
    r = subprocess.run(args, cwd=work, capture_output=True, text=True, check=False)
    return r, work


def test_take_copies_the_expected_files_and_nothing_else(tmp_path):
    files = {n: "scan" for n in SCANS} | {"silk-reeling.zip": "pkg", "opa-compliance.zip": "planted",
                                          "build.sh": "planted"}
    r, work = take(tmp_path, "full", files)
    assert r.returncode == 0, r.stderr
    assert (work / "silk-reeling.zip").read_text() == "pkg"
    assert all((work / n).read_text() == "scan" for n in SCANS)
    assert not (work / "opa-compliance.zip").exists() and not (work / "build.sh").exists()
    assert not (work / "_app-build").exists()


def test_take_leaves_a_missing_scan_missing(tmp_path):
    work = tmp_path / "infrastructure"
    work.mkdir()
    (work / "grype-python.json").write_text("stale")
    files = {n: "scan" for n in SCANS if n != "grype-python.json"}
    r, work = take(tmp_path, "deps", files)
    assert r.returncode == 0 and "grype-python.json is missing" in r.stdout
    assert not (work / "grype-python.json").exists(), "a stale local copy must not stand in"


def test_take_full_fails_without_the_package(tmp_path):
    r, _ = take(tmp_path, "full", {n: "scan" for n in SCANS})
    assert r.returncode != 0 and "silk-reeling.zip" in r.stderr


def test_take_deps_needs_no_package(tmp_path):
    r, work = take(tmp_path, "deps", {n: "scan" for n in SCANS})
    assert r.returncode == 0 and not (work / "silk-reeling.zip").exists()


def test_take_refuses_a_symlink(tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("secret")
    work = tmp_path / "infrastructure"
    (work / "_app-build").mkdir(parents=True)
    for n in SCANS:
        (work / "_app-build" / n).write_text("scan")
    (work / "_app-build" / "grype.json").unlink()
    (work / "_app-build" / "grype.json").symlink_to(secret)
    r = subprocess.run(["bash", str(TAKE), "deps", "_app-build"], cwd=work, capture_output=True, text=True, check=False)
    assert r.returncode == 0 and not (work / "grype.json").exists()


@pytest.mark.parametrize("pkg", ["../evil.zip", "/tmp/x.zip", "./a/b.zip", "./x.tar"])
def test_a_malformed_package_path_is_refused(tmp_path, pkg):
    doc = json.loads(_apps.MANIFEST.read_text())
    doc["apps"][1]["package_path"] = pkg
    bad = tmp_path / "apps.json"
    bad.write_text(json.dumps(doc))
    with pytest.raises(SystemExit, match="package_path must be"):
        _apps.load(bad)
    r, _ = take(tmp_path / "t", "full", {n: "scan" for n in SCANS}, manifest=bad)
    assert r.returncode != 0


# --- the nightly: pin and apps hold no credentials; refresh only downloads

def test_the_nightly_builds_and_scans_without_cloud_credentials():
    jobs = yaml.safe_load((WF / "evidence-nightly.yml").read_text())["jobs"]
    for name in ("pin", "apps"):
        job = jobs[name]
        assert job["permissions"] == {"contents": "read"}, name
        assert "environment" not in job, name
        for st in job.get("steps", []):
            assert "configure-aws-credentials" not in st.get("uses", ""), name
    assert jobs["apps"]["uses"] == "./.github/workflows/app-build.yml"
    assert jobs["apps"]["needs"] == ["pin"] and jobs["pin"]["needs"] == ["sast"]
    checkout = next(st for st in jobs["pin"]["steps"] if "actions/checkout" in st.get("uses", ""))
    assert checkout["with"]["persist-credentials"] is False
    refresh = jobs["refresh"]
    assert {"pin", "apps"} <= set(refresh["needs"])
    runs = " ".join(st.get("run", "") for st in refresh["steps"])
    for direct in ("build-apps.sh", "scan-sca.sh", "app-source.sh", "npm ci", "pip install", "curl -sfL --retry 3 --retry-delay 5 -o ksi-signal.json"):
        assert direct not in runs, f"the refresh job runs {direct} itself"
    assert not any("setup-node" in st.get("uses", "") for st in refresh["steps"])
    assert set(jobs["alert"]["needs"]) == {"sast", "pin", "apps", "refresh"}


def test_the_refresh_binds_to_the_inventory_the_pin_job_verified():
    jobs = yaml.safe_load((WF / "evidence-nightly.yml").read_text())["jobs"]
    steps = jobs["refresh"]["steps"]
    names = [st.get("name", "") for st in steps]
    verify = steps[names.index("Verify the pinned inventory")]
    assert "cosign verify-blob" in verify["run"] and '"$SIGNAL_COMMIT" != "$PINNED_COMMIT"' in verify["run"]
    assert verify["env"]["PINNED_COMMIT"] == "${{ needs.pin.outputs.commit }}"
    assert (names.index("Download the pinned inventory") < names.index("Verify the pinned inventory")
            < names.index("Take the expected scan files") < names.index("Detection gate (G7)"))
    pin_runs = " ".join(st.get("run", "") for st in jobs["pin"]["steps"])
    assert "cosign verify-blob" in pin_runs and "merge-base --is-ancestor" in pin_runs
    assert 'echo "commit=${SIGNAL_COMMIT}" >> "$GITHUB_OUTPUT"' in pin_runs


def test_app_build_reads_the_manifest_only_at_a_full_commit():
    job = yaml.safe_load((WF / "app-build.yml").read_text())["jobs"]["build"]
    step = next(st for st in job["steps"] if st.get("name") == "Choose the app manifest")
    assert "^[0-9a-f]{40}$" in step["run"] and step["env"]["REF"] == "${{ inputs.manifest-ref }}"
