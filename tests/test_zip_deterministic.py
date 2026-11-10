"""Reproducible Lambda packages (scripts/zip-deterministic.sh).

Terraform updates a Lambda whenever its package hash changes. The same contents
must give the same bytes, whatever the files' modification times or the order
they were written in, so an unchanged function is not updated on every deploy.
"""

import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "zip-deterministic.sh"
WORKFLOW = REPO / ".github" / "workflows" / "deploy-with-opa.yml"

pytestmark = pytest.mark.skipif(not shutil.which("zip"), reason="needs zip")

FILES = {"index.js": "exports.handler = 1\n", "policy-data.json": "{}\n",
         "node_modules/a/package.json": '{"name": "a"}\n', "node_modules/a/index.js": "module.exports = 2\n"}


def _tree(root, mtime, reverse=False):
    for name in sorted(FILES, reverse=reverse):
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(FILES[name])
    for p in [root, *root.rglob("*")]:
        os.utime(p, (mtime, mtime))
    return root


def _zip(src, out):
    subprocess.run(["bash", str(SCRIPT), str(src), str(out)], check=True)
    return out.read_bytes()


def test_the_same_contents_give_the_same_bytes(tmp_path):
    a = _zip(_tree(tmp_path / "a", 1_700_000_000), tmp_path / "a.zip")
    b = _zip(_tree(tmp_path / "b", 1_760_000_000, reverse=True), tmp_path / "b.zip")
    assert a == b


def test_a_plain_recursive_zip_of_the_same_contents_does_not(tmp_path):
    # The behaviour being fixed: a fresh checkout's timestamps changed the hash.
    for name, t in (("a", 1_700_000_000), ("b", 1_760_000_000)):
        subprocess.run(["zip", "-qr", str(tmp_path / f"{name}.zip"), "."],
                       cwd=_tree(tmp_path / name, t), check=True)
    assert (tmp_path / "a.zip").read_bytes() != (tmp_path / "b.zip").read_bytes()


def test_a_content_change_changes_the_bytes(tmp_path):
    a = _zip(_tree(tmp_path / "a", 1_700_000_000), tmp_path / "a.zip")
    src = _tree(tmp_path / "b", 1_700_000_000)
    (src / "index.js").write_text("exports.handler = 3\n")
    assert _zip(src, tmp_path / "b.zip") != a


def test_every_file_is_packaged_unchanged(tmp_path):
    src = _tree(tmp_path / "a", 1_700_000_000)
    (src / "node_modules" / ".bin").mkdir()
    (src / "node_modules" / ".bin" / "a").symlink_to("../a/index.js")
    _zip(src, tmp_path / "a.zip")
    with zipfile.ZipFile(tmp_path / "a.zip") as z:
        files = {i.filename: z.read(i).decode() for i in z.infolist() if not i.is_dir()}
    assert files == {**FILES, "node_modules/.bin/a": FILES["node_modules/a/index.js"]}


def test_a_missing_source_fails(tmp_path):
    out = subprocess.run(["bash", str(SCRIPT), str(tmp_path / "nope"), str(tmp_path / "x.zip")],
                         capture_output=True, text=True, check=False)
    assert out.returncode != 0 and not (tmp_path / "x.zip").exists()


def test_the_deploy_packages_every_lambda_it_builds_with_it():
    text = WORKFLOW.read_text()
    assert text.count("../scripts/zip-deterministic.sh lambda opa-compliance.zip") == 2
    assert text.count("../scripts/zip-deterministic.sh _pkg silk-reeling.zip") == 1
    assert "zip -r ../opa-compliance.zip" not in text
    # The one plain zip of silk-reeling.zip left is the plan-only placeholder, never applied.
    assert text.count("zip -qr ../silk-reeling.zip") == 1 and "( cd _silk_stub && zip -qr" in text
    assert "--no-compile --target _pkg" in text
