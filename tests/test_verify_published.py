"""The external verifier checks every signature in the governed publish list.

scripts/verify-published.sh reads the list through published-set.py and accepts
each signature only from a workflow the config says publishes the artifact.
These tests run the real script over a local copy of the site with a fake
cosign that accepts exactly the identity each bundle was "signed" with.
"""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "verify-published.sh"
DEPLOY = "https://github.com/sam-aydlette/samaydlette.com/.github/workflows/deploy-with-opa.yml@refs/heads/main"
NIGHTLY = "https://github.com/sam-aydlette/samaydlette.com/.github/workflows/evidence-nightly.yml@refs/heads/main"

pytestmark = pytest.mark.skipif(not (shutil.which("jq") and shutil.which("curl")), reason="needs jq and curl")


def _signed():
    out = subprocess.run([sys.executable, str(REPO / "scripts" / "published-set.py"), "signed"],
                         capture_output=True, text=True, check=True).stdout
    return [line.split("\t") for line in out.splitlines()]


def _site(tmp_path, signer=None, skip=()):
    """Every signed artifact and its signature. A signature file holds the
    identity that 'signed' it: the first workflow that publishes it, unless
    `signer` overrides it for that artifact."""
    site = tmp_path / "site"
    site.mkdir()
    for art, sig, _kind, signers, _need in _signed():
        if art in skip:
            continue
        (site / art).write_text("{}")
        who = (signer or {}).get(art) or signers.split(",")[0]
        (site / sig).write_text(DEPLOY if who == "deploy" else NIGHTLY)
    return site


def _run(tmp_path, site):
    b = tmp_path / "bin"
    b.mkdir()
    (b / "cosign").write_text("""#!/bin/bash
while [ $# -gt 0 ]; do
  case "$1" in --bundle) bundle=$2; shift ;; --certificate-identity) id=$2; shift ;; esac; shift
done
[ "$(cat "$bundle")" = "$id" ]
""")
    (b / "cosign").chmod(0o755)
    env = {"PATH": f"{b}:/usr/local/bin:/usr/bin:/bin", "HOME": str(tmp_path)}
    out = subprocess.run(["bash", str(SCRIPT), f"file://{site}"], capture_output=True, text=True, env=env, check=False)
    section = out.stdout.split("== 1.", 1)[-1].split("== 2.", 1)[0]
    return out, [line.strip() for line in section.splitlines() if line.strip().startswith(("PASS", "FAIL", "SKIP"))]


def test_every_listed_signature_is_checked_against_its_publisher(tmp_path):
    rows = _signed()
    assert len(rows) == 24
    _, lines = _run(tmp_path, _site(tmp_path))
    sig_lines = [line for line in lines if "bound to the published inventory" not in line]
    assert len(sig_lines) == 24 and all(line.startswith("PASS") for line in sig_lines), sig_lines
    assert "PASS  vdr-status.json signed by the pinned nightly workflow on main" in sig_lines


def test_the_vdr_family_verifies_whichever_workflow_signed_it_last(tmp_path):
    site = _site(tmp_path, signer={"vdr-report.json": "nightly", "vdr-trend.json": "deploy"})
    _, lines = _run(tmp_path, site)
    assert not [line for line in lines if line.startswith("FAIL") and "bound" not in line]


@pytest.mark.parametrize("art, wrong", [
    ("vdr-status.json", "deploy"),       # the beacon earns KSI credit: nightly only
    ("trust-center.json", "nightly"),    # deploy-only artifacts: deploy only
    ("availability.json", "nightly"),    # one the verifier did not check before
])
def test_a_signature_from_a_workflow_that_does_not_publish_it_fails(tmp_path, art, wrong):
    out, lines = _run(tmp_path, _site(tmp_path, signer={art: wrong}))
    assert f"FAIL  {art} signature" in lines
    assert out.returncode == 1


def test_an_unpublished_corroboration_is_skipped_not_passed(tmp_path):
    _, lines = _run(tmp_path, _site(tmp_path, skip={"boundary-corroboration.json"}))
    assert "SKIP  boundary-corroboration.json (not published)" in lines
    assert not any("boundary-corroboration.json signed" in line for line in lines)


def test_a_missing_required_artifact_stops_the_verifier(tmp_path):
    out, _ = _run(tmp_path, _site(tmp_path, skip={"policy-index.json"}))
    assert out.returncode == 1 and "could not fetch" in out.stderr and "policy-index.json" in out.stderr
