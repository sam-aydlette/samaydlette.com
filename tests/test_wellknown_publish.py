"""Everything under /.well-known/ must be published deliberately, not swept.

The content sync used to run `aws s3 sync website/ --delete` over the whole
bucket. Generated artifacts are gitignored, so they are absent from website/ and
`--delete` removed 48 published objects on every deploy; the explicit upload
steps put them back about three minutes later. For those minutes a third party
got a 404 for the compliance artifacts and for runtime-signing-pubkey.pem -- the
key needed to verify the runtime signal. A system whose claim is "verify this
yourself, any time" should not be unverifiable for several minutes a day.

The prefix is now excluded from the sync, which moves the risk: anything
genuinely served from .well-known/ must be published by an explicit step, and
forgetting one would silently stop serving it. This file is that guard.
"""

import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "deploy-with-opa.yml"
WELL_KNOWN = REPO / "website" / ".well-known"

# The accumulating ledger is deliberately never uploaded from website/: its
# history lives in the published object and the trend step republishes it.
LEDGER = "vdr-trend.json"


def workflow_text():
    return WORKFLOW.read_text()


def sync_step_body():
    wf = yaml.safe_load(workflow_text())
    for job in wf["jobs"].values():
        for step in job.get("steps", []):
            if "aws s3 sync website/" in (step.get("run") or ""):
                return step["run"]
    pytest.fail("no step running `aws s3 sync website/` was found")


def tracked_well_known_files():
    if not WELL_KNOWN.is_dir():
        return []
    return sorted(p.name for p in WELL_KNOWN.iterdir() if p.is_file())


def test_sync_excludes_the_whole_well_known_prefix():
    assert '--exclude ".well-known/*"' in sync_step_body(), (
        "`aws s3 sync website/ ... --delete` must exclude .well-known/*; without "
        "it, every generated artifact is deleted and re-uploaded on each deploy, "
        "leaving a window where published evidence 404s."
    )


@pytest.mark.parametrize("name", tracked_well_known_files())
def test_every_committed_well_known_file_has_a_publish_step(name):
    """A file in website/.well-known/ is no longer published by the sync.

    If it is committed there, some step must copy it explicitly, or it silently
    stops being served the next time the site deploys.
    """
    if name == LEDGER:
        pytest.skip("the trend ledger is republished by the RA-5(6) trend step, not from website/")
    text = workflow_text()
    assert f".well-known/{name}" in text, (
        f"website/.well-known/{name} is committed but no workflow step publishes "
        f"it, and the content sync now skips the whole prefix, so it would stop "
        f"being served. Add an explicit `aws s3 cp` for it."
    )


def test_security_txt_is_published_with_the_content_type_rfc9116_requires():
    body = sync_step_body()
    assert ".well-known/security.txt" in body
    assert "text/plain" in body, "RFC 9116 requires security.txt to be served as text/plain"


def test_website_files_publish_only_after_every_gate():
    """A failed gate must leave the pages and their evidence from the same deploy."""
    wf = yaml.safe_load(workflow_text())
    steps = wf["jobs"]["deploy"]["steps"]
    sync = next(i for i, st in enumerate(steps) if "aws s3 sync website/" in (st.get("run") or ""))
    gates = [i for i, st in enumerate(steps)
             if "gate" in (st.get("name") or "").lower() or "rule claims" in (st.get("name") or "").lower()]
    assert gates and max(gates) < sync


@pytest.mark.parametrize("verifies", [True, False])
def test_the_deploy_keeps_the_nightly_beacon_only_if_its_signature_verifies(tmp_path, verifies):
    text = workflow_text()
    start = text.index("rm -f vdr-status-nightly.json vdr-status-nightly.bundle")
    end = text.index("        fi\n", start) + len("        fi\n")
    script = "\n".join(line[8:] if line.startswith(" " * 8) else line
                       for line in ("        " + text[start:end]).splitlines())
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fakes = {"curl": 'while [ $# -gt 0 ]; do [ "$1" = -o ] && touch "$2"; shift; done',
             "cosign": "exit 0" if verifies else "exit 1"}
    for name, body in fakes.items():
        (bin_dir / name).write_text(f"#!/bin/bash\n{body}\n")
        (bin_dir / name).chmod(0o755)
    subprocess.run(["bash", "-euo", "pipefail", "-c", script], cwd=tmp_path,
                   env={"PATH": f"{bin_dir}:/usr/bin:/bin"}, check=True)
    assert (tmp_path / "vdr-status-nightly.json").exists() is verifies
