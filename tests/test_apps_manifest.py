"""The app manifest (data/apps.json) and the pinned app source.

Each app in the factory names its governance domain, its service in the offering,
the Terraform flag that enables it and, when it builds from another repository,
the exact commit. The manifest must agree with the governance registry, the
offering and both workflows, and the workflows build apps only through
scripts/build-apps.sh, which checks each one out through scripts/app-source.sh
at that commit.
"""

import json
import shutil
import sys
import subprocess
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import _apps  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "data" / "apps.json"
BAD = REPO / "tests" / "fixtures" / "apps" / "apps-bad.json"
SCRIPT = REPO / "scripts" / "app-source.sh"
DOMAINS = REPO / "docs" / "governance" / "domains.json"
OFFERING = REPO / "data" / "cds" / "offering.json"
DEPLOY = REPO / ".github" / "workflows" / "deploy-with-opa.yml"
NIGHTLY = REPO / ".github" / "workflows" / "evidence-nightly.yml"
APP_BUILD = REPO / ".github" / "workflows" / "app-build.yml"


def problems(manifest_path):
    """Every way the manifest disagrees with the wiring it describes."""
    try:
        doc = _apps.load(manifest_path)
    except SystemExit as e:
        return [str(e)]
    domains = {d["id"]: d for d in json.loads(DOMAINS.read_text())["domains"]}
    components = {c["name"] for c in json.loads(OFFERING.read_text())["services"]}
    deploy, nightly = DEPLOY.read_text(), NIGHTLY.read_text()
    out = []
    for a in doc["apps"]:
        i = a["id"]
        dom = domains.get(a["domain"])
        if dom is None:
            out.append(f"{i}: domain {a['domain']!r} is not in the governance registry")
        elif dom["owner_role"] != a["owner_role"]:
            out.append(f"{i}: owner {a['owner_role']!r} differs from the registry's {dom['owner_role']!r}")
        if a["component"] not in components:
            out.append(f"{i}: component {a['component']!r} is not in the offering")
        if a["source"] is not None:
            # An app from another repository is checked out and built by build-apps.sh,
            # which runs only the apps that name a build.
            if not a.get("build"):
                out.append(f"{i}: it has a source but no build, so no workflow would check it out")
            elif not (REPO / a["build"]["script"]).is_file():
                out.append(f"{i}: build script {a['build']['script']} does not exist")
        flag = a["terraform_flag"]
        if flag is not None:
            # The plan job and the deploy job each write a tfvars block; both must enable the app.
            if deploy.count(f"{flag} = true") != 2:
                out.append(f"{i}: {flag} is not set true in both tfvars blocks")
            if deploy.count(f'"{a["package_path"]}"') < 2:
                out.append(f"{i}: package {a['package_path']!r} is not in both tfvars blocks")
    # The deploy builds through the credential-free app-build workflow, which runs build-apps.sh.
    if ("uses: ./.github/workflows/app-build.yml" not in deploy or 'bash ../scripts/build-apps.sh "$MODE"' not in APP_BUILD.read_text()
            or "scripts/build-apps.sh deps deployed-apps.json" not in nightly):
        out.append("both workflows must build the apps through build-apps.sh")
    return out


def test_the_manifest_agrees_with_the_registry_offering_and_workflows():
    assert problems(MANIFEST) == []


def test_a_broken_manifest_fails(tmp_path):
    # The loader stops at the unpinned commit before anything else is read.
    assert any("must pin a full 40-character commit" in p for p in problems(BAD))
    doc = json.loads(BAD.read_text())
    doc["apps"][1]["source"]["commit"] = "0" * 40
    fixed = tmp_path / "apps.json"
    fixed.write_text(json.dumps(doc))
    assert any("'silk-reeling-app' is not in the governance registry" in p for p in problems(fixed))


def test_every_offering_component_is_an_app():
    components = {c["name"] for c in json.loads(OFFERING.read_text())["services"]}
    assert components == {a["component"] for a in json.loads(MANIFEST.read_text())["apps"]}


def test_no_workflow_clones_app_source_by_branch():
    for wf in (REPO / ".github" / "workflows").glob("*.yml"):
        text = wf.read_text()
        assert "git clone" not in text, f"{wf.name} clones a repository; use scripts/app-source.sh"
        assert "SILK_REELING_REF" not in text, f"{wf.name} still reads a branch for app source"


@pytest.mark.skipif(not shutil.which("git"), reason="needs git")
@pytest.mark.parametrize("app, manifest, msg", [
    ("website", MANIFEST, "builds from this repository"),
    ("nope", MANIFEST, "no app 'nope'"),
    ("silk-reeling", BAD, "must pin a full 40-character commit"),
    ("silk-reeling", {"repo": "../x"}, "malformed repo"),
    ("silk-reeling", {"branch": "../main"}, "malformed branch"),
])
def test_the_script_refuses_anything_but_a_pinned_commit(tmp_path, app, manifest, msg):
    if isinstance(manifest, dict):
        doc = json.loads(MANIFEST.read_text())
        doc["apps"][1]["source"].update(manifest)
        manifest = tmp_path / "apps.json"
        manifest.write_text(json.dumps(doc))
    r = subprocess.run(["bash", str(SCRIPT), app, str(tmp_path / "src"), str(manifest)],
                       capture_output=True, text=True, check=False)
    assert r.returncode != 0 and msg in r.stderr, r.stderr
    assert not (tmp_path / "src").exists()


def test_the_nightly_scans_the_deployed_pin_not_mains():
    step = NIGHTLY.read_text().split("- name: Resolve app dependency trees", 1)[1].split("- name:", 1)[0]
    assert 'git show "${SIGNAL_COMMIT}:data/apps.json" > deployed-apps.json' in step
    assert "build-apps.sh deps deployed-apps.json" in step
    assert "cp ../data/apps.json" not in step, "no fallback to main's pin"


def test_only_the_checkout_sees_the_repository_token():
    # The workflows hand the token only to build-apps.sh, which drops it after the
    # checkouts and before any build (tests/test_app_build.py runs it).
    assert "APP_REPO_TOKEN:" not in DEPLOY.read_text(), "the deploy job builds nothing itself"
    for wf in (APP_BUILD, NIGHTLY):
        text = wf.read_text()
        assert text.count("APP_REPO_TOKEN:") == 1, wf.name
        step = "\n".join(ln for ln in text[text.index("APP_REPO_TOKEN:"):].split("- name:", 1)[0].splitlines()
                         if not ln.strip().startswith("#"))
        assert "scripts/build-apps.sh" in step and "npm " not in step and "pip " not in step, wf.name
    script = (REPO / "scripts" / "build-apps.sh").read_text()
    assert script.index("app-source.sh") < script.index("unset APP_REPO_TOKEN") < script.index('bash "$here/../$script"')
