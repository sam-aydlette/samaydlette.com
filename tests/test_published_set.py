"""One publish list (scripts/published-set.py).

The deploy's redaction gate, upload and round-trip check all read the governed
freshness config through published-set.py. These tests run the real workflow
steps against a fake `aws`, so a step that stops reading the list, or a list
that names a file the build did not make, fails here.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "deploy-with-opa.yml"
sys.path.insert(0, str(REPO / "scripts"))
import _freshness  # noqa: E402

GATE = "Publication redaction gate (no AWS account ID)"
UPLOAD = "Publish all signed artifacts to /.well-known/"
ROUND_TRIP = "Post-publish round-trip verify"


def _run_block(name):
    text = WORKFLOW.read_text()
    step = text[text.index(f"- name: {name}"):]
    step = step[:step.find("\n    - name:")]
    lines = []
    for line in step.split("run: |", 1)[1].splitlines()[1:]:
        if line.strip() and not line.startswith(" " * 8):
            break
        lines.append(line[8:])
    return "\n".join(lines) + "\n"


def _build(tmp_path, skip=()):
    """A build directory holding every file the deploy publishes, as the
    workflow lays it out: infrastructure/ beside scripts/."""
    infra = tmp_path / "infrastructure"
    (infra / "schemas").mkdir(parents=True)
    (tmp_path / "scripts").symlink_to(REPO / "scripts")
    cfg = _freshness.load_freshness_config()
    for a in cfg["artifacts"]:
        if "deploy" not in a["published_by"]:
            continue
        name = a["path"].rsplit("/", 1)[-1]
        names = [name, (a.get("signature") or "").rsplit("/", 1)[-1]]
        names += [name.removesuffix(".json") + ".md"] if a.get("markdown") else []
        names += [a["json_schema"]] if "json_schema" in a else []
        for n in filter(None, names):
            if n not in skip:
                (infra / n).write_text(json.dumps({"file": n}))
    return infra


def _bin(tmp_path, served=None):
    """Fake aws and terraform. `aws s3 cp SRC s3://...` records the upload;
    `aws s3 cp s3://B/KEY -` prints `served[KEY]` (the round trip)."""
    b = tmp_path / "bin"
    b.mkdir()
    (b / "terraform").write_text("#!/bin/bash\necho B\n")
    (b / "aws").write_text(f"""#!/bin/bash
if [ "$1 $2" = "s3 cp" ] && [ "$4" = "-" ]; then cat "{tmp_path}/served/${{3#s3://B/}}"; exit; fi
if [ "$1 $2" = "s3 cp" ]; then printf '%s\\t%s\\t%s\\t%s\\n' "$3" "${{4#s3://B/}}" "$6" "$8" >> "{tmp_path}/uploads"; fi
if [ "$1" = "s3api" ]; then echo "An error occurred (404) when calling the HeadObject operation" >&2; exit 254; fi
exit 0
""")
    for f in b.iterdir():
        f.chmod(0o755)
    return {**os.environ, "PATH": f"{b}:{os.environ['PATH']}"}


def _step(name, cwd, env, replace=()):
    script = _run_block(name)
    for old, new in replace:
        script = script.replace(old, new)
    return subprocess.run(["bash", "-eo", "pipefail", "-c", script], cwd=cwd, env=env,
                          capture_output=True, text=True, check=False)


def _rows(text):
    return [line.split("\t") for line in text.splitlines() if line]


# --- the list ------------------------------------------------------------------

def test_the_deploy_uploads_every_listed_object_with_its_type(tmp_path):
    infra = _build(tmp_path)
    env = _bin(tmp_path)
    out = _step(UPLOAD, infra, env)
    assert out.returncode == 0, out.stderr
    uploaded = _rows((tmp_path / "uploads").read_text())
    keys = {r[1] for r in uploaded}
    assert len(uploaded) == len(keys) == 48
    assert {".well-known/ksi-signal.json", ".well-known/ksi-signal.schema.json", ".well-known/vdr-history.json",
            ".well-known/trust-center.bundle", ".well-known/certification-package-overview.md"} <= keys
    by_key = {r[1]: r for r in uploaded}
    assert by_key[".well-known/ksi-signal.schema.json"][2:] == ["application/schema+json", "public, max-age=3600"]
    assert by_key[".well-known/iiw.csv"][2:] == ["text/csv", "public, max-age=300"]
    assert by_key[".well-known/vdr-report.md"][2] == "text/markdown; charset=utf-8"
    assert by_key[".well-known/opa-policy-bundle.tar.gz"][2] == "application/gzip"
    # The nightly's beacon and the runtime Lambda's signal are not the deploy's to publish.
    assert not keys & {".well-known/vdr-status.json", ".well-known/ksi-signal-runtime.json"}
    # The attest step publishes the attestations after the upload.
    assert not any(k.endswith(".intoto.jsonl") for k in keys)


def test_the_gate_scans_exactly_the_text_the_deploy_uploads(tmp_path):
    infra = _build(tmp_path)
    env = _bin(tmp_path)
    assert _step(UPLOAD, infra, env).returncode == 0
    text = {r[0] for r in _rows((tmp_path / "uploads").read_text())
            if not r[0].endswith((".bundle", ".tar.gz"))}
    gate = _step(GATE, infra, env, [("python3 ../scripts/check-published-redaction.py", "echo")])
    assert gate.returncode == 0, gate.stderr
    assert set(gate.stdout.split()) == text and len(text) == 28
    # Never a directory scan: the deploy downloads live files it does not publish.
    assert "--root" not in _run_block(GATE)


def test_an_absent_corroboration_is_neither_scanned_nor_uploaded(tmp_path):
    infra = _build(tmp_path, skip={"boundary-corroboration.json", "boundary-corroboration.bundle"})
    env = _bin(tmp_path)
    assert _step(UPLOAD, infra, env).returncode == 0
    keys = {r[1] for r in _rows((tmp_path / "uploads").read_text())}
    assert len(keys) == 46 and not any("corroboration" in k for k in keys)
    gate = _step(GATE, infra, env, [("python3 ../scripts/check-published-redaction.py", "echo")])
    assert "boundary-corroboration.json" not in gate.stdout.split()


@pytest.mark.parametrize("absent", ["trust-center.json", "boundary-map.bundle", "vdr-report.md",
                                    "schemas/ksi-signal.schema.json"])
def test_a_listed_file_the_build_did_not_make_stops_the_upload(tmp_path, absent):
    infra = _build(tmp_path, skip={absent})
    env = _bin(tmp_path)
    out = _step(UPLOAD, infra, env)
    assert out.returncode != 0 and absent in out.stderr
    assert not (tmp_path / "uploads").exists(), "nothing is uploaded when the list is incomplete"
    gate = _step(GATE, infra, env, [("python3 ../scripts/check-published-redaction.py", "echo")])
    # The gate scans text only, so a missing signature is the upload's to catch.
    assert (gate.returncode != 0) is (not absent.endswith(".bundle"))


def test_the_round_trip_compares_every_uploaded_object_and_attestation(tmp_path):
    infra = _build(tmp_path)
    for a in ("ksi-signal.json", "security-decision-record.json", "vdr-report.json", "iiw.csv"):
        (infra / f"{a}.intoto.jsonl").write_text("{}")
    env = _bin(tmp_path)
    served = tmp_path / "served" / ".well-known"
    served.mkdir(parents=True)
    rows = _rows(subprocess.run([sys.executable, str(REPO / "scripts" / "published-set.py"), "served", "--by", "deploy"],
                                cwd=infra, capture_output=True, text=True, check=True).stdout)
    assert len(rows) == 52
    for f, key in rows:
        (tmp_path / "served" / key).write_bytes((infra / f).read_bytes())
    ok = _step(ROUND_TRIP, infra, env)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert sum(line.startswith("ok: ") for line in ok.stdout.splitlines()) == 52
    # A served Markdown rendering that differs from the build is caught.
    (served / "vdr-report.md").write_text("stale")
    bad = _step(ROUND_TRIP, infra, env)
    assert bad.returncode != 0 and "vdr-report.md" in bad.stdout


def test_attestations_the_deploy_makes_are_the_ones_listed():
    attested = set(re.findall(r"^\s*attest (\S+)\s+scripts/", WORKFLOW.read_text(), re.M))
    listed = {a["path"].rsplit("/", 1)[-1].removesuffix(".intoto.jsonl")
              for a in _freshness.load_freshness_config()["artifacts"]
              if a["path"].endswith(".intoto.jsonl") and "deploy" in a["published_by"]}
    assert attested == listed and len(listed) == 4


# --- the config fields -----------------------------------------------------------

@pytest.mark.parametrize("field, value", [
    ("published_by", []), ("published_by", ["someone"]), ("published_by", ["deploy", "deploy"]),
    ("markdown", "yes"), ("json_schema", "../ksi.schema.json"), ("optional", 1),
])
def test_a_bad_publish_field_fails_closed(tmp_path, field, value):
    cfg = json.loads(_freshness.DEFAULT_PATH.read_text())
    cfg["artifacts"][0][field] = value
    p = tmp_path / "c.json"
    p.write_text(json.dumps(cfg))
    with pytest.raises(SystemExit):
        _freshness.load_freshness_config(p)


def test_every_artifact_names_who_publishes_it(tmp_path):
    cfg = json.loads(_freshness.DEFAULT_PATH.read_text())
    del cfg["artifacts"][0]["published_by"]
    p = tmp_path / "c.json"
    p.write_text(json.dumps(cfg))
    with pytest.raises(SystemExit, match="published_by"):
        _freshness.load_freshness_config(p)
