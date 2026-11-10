"""The app manifest (data/apps.json) and the pinned app source.

Each app in the factory names its governance domain, its service in the offering,
the Terraform flag that enables it and, when it builds from another repository,
the exact commit. The manifest must agree with the governance registry, the
offering and both workflows, and the workflows check app source out only
through scripts/app-source.sh at that commit.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "data" / "apps.json"
BAD = REPO / "tests" / "fixtures" / "apps" / "apps-bad.json"
SCRIPT = REPO / "scripts" / "app-source.sh"
DOMAINS = REPO / "docs" / "governance" / "domains.json"
OFFERING = REPO / "data" / "cds" / "offering.json"
DEPLOY = REPO / ".github" / "workflows" / "deploy-with-opa.yml"
NIGHTLY = REPO / ".github" / "workflows" / "evidence-nightly.yml"


def problems(manifest_path):
    """Every way the manifest disagrees with the wiring it describes."""
    doc = json.loads(manifest_path.read_text())
    domains = {d["id"]: d for d in json.loads(DOMAINS.read_text())["domains"]}
    components = {c["name"] for c in json.loads(OFFERING.read_text())["services"]}
    deploy, nightly = DEPLOY.read_text(), NIGHTLY.read_text()
    out = []
    for field in ("decided_by", "decided_on", "review_by"):
        if not doc.get(field):
            out.append(f"manifest has no {field}")
    ids = [a["id"] for a in doc["apps"]]
    if len(ids) != len(set(ids)):
        out.append("duplicate app id")
    for a in doc["apps"]:
        i = a["id"]
        dom = domains.get(a["domain"])
        if dom is None:
            out.append(f"{i}: domain {a['domain']!r} is not in the governance registry")
        elif dom["owner_role"] != a["owner_role"]:
            out.append(f"{i}: owner {a['owner_role']!r} differs from the registry's {dom['owner_role']!r}")
        if a["component"] not in components:
            out.append(f"{i}: component {a['component']!r} is not in the offering")
        src = a["source"]
        if src is not None:
            if not re.fullmatch(r"[0-9a-f]{40}", src.get("commit", "")):
                out.append(f"{i}: source must pin a full commit")
            if f"scripts/app-source.sh {i} " not in deploy or f"scripts/app-source.sh {i} " not in nightly:
                out.append(f"{i}: both workflows must check its source out through app-source.sh")
        flag = a["terraform_flag"]
        if flag is not None:
            # The plan job and the deploy job each write a tfvars block; both must enable the app.
            if deploy.count(f"{flag} = true") != 2:
                out.append(f"{i}: {flag} is not set true in both tfvars blocks")
            if deploy.count(f'"{a["package_path"]}"') < 2:
                out.append(f"{i}: package {a['package_path']!r} is not in both tfvars blocks")
        for tree in a["sbom_trees"]:
            for name, text in (("deploy", deploy), ("nightly", nightly)):
                if f"syft dir:{tree} " not in text:
                    out.append(f"{i}: the {name} workflow does not scan {tree}")
    return out


def test_the_manifest_agrees_with_the_registry_offering_and_workflows():
    assert problems(MANIFEST) == []


def test_a_broken_manifest_fails():
    found = problems(BAD)
    assert any("'silk-reeling-app' is not in the governance registry" in p for p in found)
    assert any("source must pin a full commit" in p for p in found)


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
])
def test_the_script_refuses_anything_but_a_pinned_commit(tmp_path, app, manifest, msg):
    r = subprocess.run(["bash", str(SCRIPT), app, str(tmp_path / "src"), str(manifest)],
                       capture_output=True, text=True, check=False)
    assert r.returncode != 0 and msg in r.stderr, r.stderr
    assert not (tmp_path / "src").exists()


def test_the_nightly_scans_the_deployed_pin_not_mains():
    step = NIGHTLY.read_text().split("- name: Resolve Silk Reeling dependency trees", 1)[1].split("- name:", 1)[0]
    assert 'git show "${SIGNAL_COMMIT}:data/apps.json" > deployed-apps.json' in step
    assert "app-source.sh silk-reeling _silk_src deployed-apps.json" in step
