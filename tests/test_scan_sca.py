"""The manifest-driven dependency scan and gate inputs.

scripts/_apps.py is the one reader of data/apps.json. scripts/scan-sca.sh scans
every tree it lists, and scripts/run-gates.sh hands each tree's Grype result to
the detection gate, so a new app's trees are scanned and gated with no workflow
edit. The scanners are stubbed here: each test is about which trees are scanned
and what happens when a scan fails, not about Syft or Grype.
"""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _apps  # noqa: E402

SCAN = REPO / "scripts" / "scan-sca.sh"
GATES = REPO / "scripts" / "run-gates.sh"
WORKFLOWS = [REPO / ".github" / "workflows" / n for n in ("deploy-with-opa.yml", "evidence-nightly.yml")]
SYFT, GRYPE = (re.search(rf"^{k}=(v\S+)$", SCAN.read_text(), re.M).group(1) for k in ("SYFT_VERSION", "GRYPE_VERSION"))

# Local mode: CI would install the real scanners and ignore the stubs.
LOCAL = {k: v for k, v in os.environ.items() if k != "CI"}

pytestmark = pytest.mark.skipif(not shutil.which("jq"), reason="needs jq")


def stubs(tmp_path, fail_dir=None):
    """syft and grype that record what they were asked and report the pinned versions."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    syft = f"""#!/bin/bash
if [ "$1" = version ]; then echo "Version:           {SYFT[1:]}"; exit 0; fi
echo "$1 $5" >> "$SCAN_LOG"
[ "$1" = "dir:{fail_dir}" ] && exit 1
out="${{3#cyclonedx-json=}}"; echo '{{"components": []}}' > "$out"
"""
    grype = f"""#!/bin/bash
if [ "$1" = version ]; then echo "Version:           {GRYPE[1:]}"; exit 0; fi
echo '{{"matches": [{{"vulnerability": {{"id": "CVE-1"}}}}]}}'
"""
    for name, body in (("syft", syft), ("grype", grype)):
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    return bin_dir


def manifest_with(tmp_path, extra_tree=None):
    doc = json.loads(_apps.MANIFEST.read_text())
    if extra_tree:
        doc["apps"][0]["sbom_trees"] = [extra_tree]
    p = tmp_path / "apps.json"
    p.write_text(json.dumps(doc))
    return p, doc


def run_scan(tmp_path, manifest, fail_dir=None):
    work = tmp_path / "infrastructure"
    work.mkdir(exist_ok=True)
    for t in _apps.trees(_apps.load(manifest)):
        (work / t["dir"]).mkdir(parents=True, exist_ok=True)
    env = {**LOCAL, "PATH": f"{stubs(tmp_path, fail_dir)}:{os.environ['PATH']}",
           "APPS_MANIFEST": str(manifest), "SCAN_LOG": str(tmp_path / "scan.log")}
    r = subprocess.run(["bash", str(SCAN)], cwd=work, env=env, capture_output=True, text=True, check=False)
    return r, work


def test_every_tree_in_the_manifest_is_scanned_with_its_cataloger(tmp_path):
    # A new app's tree is scanned without any change to the script or a workflow.
    manifest, doc = manifest_with(tmp_path, {"dir": "_site_deps", "cataloger": "javascript", "sbom": "sbom-site.json"})
    r, work = run_scan(tmp_path, manifest)
    assert r.returncode == 0, r.stdout + r.stderr
    scanned = (tmp_path / "scan.log").read_text().splitlines()
    assert scanned == [f"dir:{t['dir']} {t['cataloger']}" for t in _apps.trees(doc)]
    assert "dir:_site_deps javascript" in scanned
    for t in _apps.trees(doc):
        assert (work / t["sbom"]).exists() and (work / _apps.grype_file(t)).exists()
    assert len(json.loads((work / "grype.json").read_text())["matches"]) == len(scanned)


def test_a_failed_scan_leaves_its_result_missing_and_no_merged_file(tmp_path):
    manifest, _ = manifest_with(tmp_path)
    r, work = run_scan(tmp_path, manifest, fail_dir="lambda")
    assert r.returncode == 0, "the scan step never fails; the detection gate does"
    assert not (work / "grype-lambda.json").exists()
    assert (work / "grype-python.json").exists()
    assert not (work / "grype.json").exists(), "no merged file stands in for a missing scan"
    assert "the scan of lambda did not complete" in r.stdout


def test_a_tree_that_was_not_built_is_left_missing(tmp_path):
    manifest, _ = manifest_with(tmp_path)
    r, work = run_scan(tmp_path, manifest)
    shutil.rmtree(work / "_pkg")
    r = subprocess.run(["bash", str(SCAN)], cwd=work, capture_output=True, text=True, check=False,
                       env={**LOCAL, "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}",
                            "APPS_MANIFEST": str(manifest), "SCAN_LOG": str(tmp_path / "scan2.log")})
    assert r.returncode == 0 and "_pkg was not built" in r.stdout
    assert not (work / "grype-python.json").exists() and not (work / "grype.json").exists()


def test_a_malformed_manifest_scans_nothing(tmp_path):
    p = tmp_path / "apps.json"
    p.write_text("{}")
    r = subprocess.run(["bash", str(SCAN)], cwd=tmp_path, capture_output=True, text=True, check=False,
                       env={**os.environ, "APPS_MANIFEST": str(p)})
    assert r.returncode == 1 and "nothing was scanned" in r.stdout


def test_the_detection_gate_gets_one_result_per_manifest_tree(tmp_path):
    manifest, doc = manifest_with(tmp_path, {"dir": "_site_deps", "cataloger": "javascript", "sbom": "sbom-site.json"})
    # A python3 that records the detection gate's arguments and runs anything else for real.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "python3").write_text(f"""#!/bin/bash
case "$1" in *detection-gate.py) shift; printf '%s\\n' "$@" > "{tmp_path}/args"; exit 0;; esac
exec {sys.executable} "$@"
""")
    (bin_dir / "python3").chmod(0o755)
    r = subprocess.run(["bash", str(GATES), "detection"], cwd=tmp_path, capture_output=True, text=True, check=False,
                       env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "APPS_MANIFEST": str(manifest)})
    assert r.returncode == 0, r.stderr
    args = (tmp_path / "args").read_text().split()
    grype = args[args.index("--grype") + 1:args.index("--dependabot")]
    assert grype == [_apps.grype_file(t) for t in _apps.trees(doc)]
    assert "grype-site.json" in grype


@pytest.mark.parametrize("mutate, msg", [
    (lambda d: d["platform_sbom_trees"][0].update(dir="../../etc"), "malformed tree dir"),
    (lambda d: d["platform_sbom_trees"][0].update(cataloger="go"), "cataloger must be one of"),
    (lambda d: d["platform_sbom_trees"][0].update(sbom="out.json"), "sbom must be named"),
    (lambda d: d["platform_sbom_trees"].append(dict(d["platform_sbom_trees"][0])), "same SBOM file"),
    (lambda d: d["apps"].append(dict(d["apps"][0])), "duplicate app id"),
    (lambda d: d.pop("review_by"), "has no review_by"),
])
def test_the_loader_refuses_a_malformed_manifest(tmp_path, mutate, msg):
    d = json.loads(_apps.MANIFEST.read_text())
    mutate(d)
    p = tmp_path / "apps.json"
    p.write_text(json.dumps(d))
    with pytest.raises(SystemExit, match=msg):
        _apps.load(p)


@pytest.mark.parametrize("wf", WORKFLOWS, ids=lambda p: p.name)
def test_the_workflows_scan_and_gate_only_through_the_shared_scripts(wf):
    text = wf.read_text()
    # Both scan in the credential-free app-build workflow they call.
    assert "run: bash ../scripts/scan-sca.sh" in (REPO / ".github" / "workflows" / "app-build.yml").read_text()
    assert "scan-sca.sh" not in text and "uses: ./.github/workflows/app-build.yml" in text
    assert "run: bash ../scripts/run-gates.sh detection" in text
    assert "bash ../scripts/run-gates.sh vdr" in text
    for direct in ("syft dir:", "grype sbom:", "SYFT_VERSION", "GRYPE_VERSION", "scripts/detection-gate.py",
                   "python3 ../scripts/build-vdr-report.py"):
        assert direct not in text, f"{wf.name} still runs {direct!r} itself"


def test_the_nightly_scans_and_gates_the_deployed_manifest():
    text = WORKFLOWS[1].read_text()
    step = text[text.index("- name: Detection gate (G7)"):]
    step = step[:step.index("\n\n")]
    assert "APPS_MANIFEST: deployed-apps.json" in step
    assert "manifest-ref: ${{ needs.pin.outputs.commit }}" in text
    app_build = (REPO / ".github" / "workflows" / "app-build.yml").read_text()
    assert "APPS_MANIFEST: app-manifest.json" in app_build and 'git show "$REF:data/apps.json" > app-manifest.json' in app_build


def test_the_inventory_reads_the_app_sboms_from_the_manifest():
    src = (REPO / "scripts" / "build-ksi-signal.py").read_text()
    assert "_apps.app_sboms(_apps.load())" in src
    assert '"sbom-python.json"' not in src and '"sbom-js.json"' not in src
    assert _apps.app_sboms(_apps.load()) == ["sbom-python.json", "sbom-js.json"]


def test_ci_runs_the_pinned_scanners_by_absolute_path():
    text = SCAN.read_text()
    assert "SYFT=/usr/local/bin/syft GRYPE=/usr/local/bin/grype" in text
    assert '"$SYFT" "dir:$dir"' in text and '"$GRYPE" "sbom:$sbom"' in text
    assert 'if [ -n "${CI:-}" ] || ! installed' in text


def test_the_manifest_keeps_every_tree_that_reaches_production_in_the_scan():
    # Removing a tree from the manifest would drop it from the scan and from G7's
    # required inputs; these are the trees that ship or feed a gate today.
    dirs = {t["dir"] for t in _apps.trees(_apps.load())}
    assert {"_pkg", "_silk_src/frontend", "lambda", "../tools/a11y"} <= dirs
