"""No published file names an IAM user. The decision register names users as
`aws-iam-user::<name>`; every builder that publishes a decision's resources
withholds the name, and the publication gate fails on one that remains."""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _decisions  # noqa: E402
import _redact  # noqa: E402

FIX = REPO / "tests" / "fixtures" / "redaction" / "iam-user-named.json"


def _load(name, script):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / script)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


gate = _load("cpr_iam", "check-published-redaction.py")


def test_the_name_is_withheld_and_the_kind_kept():
    out = _redact.withhold_iam_users(["aws-iam-user::someone", "aws-account::root",
                                      _redact.IAM_USER_WITHHELD])
    assert out == [_redact.IAM_USER_WITHHELD, "aws-account::root", _redact.IAM_USER_WITHHELD]
    assert _redact.find_iam_users(json.dumps(out)) == 0


def test_known_bad_the_gate_fails_on_a_published_iam_user_name(tmp_path):
    assert gate.violations([FIX]) and "IAM user name" in gate.violations([FIX])[0]
    assert "example-operator" not in " ".join(gate.violations([FIX]))
    clean = tmp_path / "clean.json"
    clean.write_text(json.dumps({"r": _redact.withhold_iam_users(json.loads(FIX.read_text())["affectedResources"])}))
    assert gate.violations([clean]) == []


def test_the_register_names_users_and_the_history_withholds_them(tmp_path):
    """The history backfills closed decisions (DEC-001 names the former deploy
    user), so a build over any VDR publishes their resources."""
    assert "aws-iam-user::" in json.dumps(_decisions.load())  # the source, kept in the repo
    vdr = REPO / "tests" / "fixtures" / "cr26" / "vdr-report.json"
    subprocess.run([sys.executable, str(REPO / "scripts" / "build-cr26-vdr.py"), "--vdr", str(vdr),
                    "--decisions", str(REPO / "data" / "decisions.json"), "--out-dir", str(tmp_path)], check=True, capture_output=True)
    history = (tmp_path / "vdr-history.json").read_text()
    assert _redact.IAM_USER_WITHHELD in history
    for f in tmp_path.glob("vdr-*"):
        assert _redact.find_iam_users(f.read_text()) == 0, f.name


def test_the_trust_center_register_withholds_them():
    tc = _load("tc_iam", "build-trust-center.py")
    items = tc.register_items(_decisions.load()["decisions"])
    assert _redact.find_iam_users(json.dumps(items)) == 0
    assert any(_redact.IAM_USER_WITHHELD in (i["applies_to"].get("resources") or []) for i in items)


# --- GitHub run IDs: a build is named by its commit and workflow ------------------------

def test_known_bad_the_gate_fails_on_a_github_run_url_or_run_id():
    for name in ("github-run-named.json", "github-run-id-field.json"):
        v = gate.violations([REPO / "tests" / "fixtures" / "redaction" / name])
        assert v and "GitHub run ID" in v[0], name
        assert "12345678901" not in " ".join(v)


def test_a_lambda_log_stream_and_a_commit_are_not_run_ids(tmp_path):
    ok = tmp_path / "ok.json"
    ok.write_text(json.dumps({"run_id": "2026/11/02/[$LATEST]71ea293dac7a486fa964c38397b531a3",
                              "run": {"workflow": "evidence-nightly.yml", "commit": "a" * 40}}))
    assert gate.violations([ok]) == []


def test_the_nightly_beacon_names_its_run_by_workflow_and_commit():
    nightly = (REPO / ".github" / "workflows" / "evidence-nightly.yml").read_text()
    assert "run_url" not in nightly
    assert 'run: {workflow: "evidence-nightly.yml", commit: $run_commit}' in nightly


def test_the_ksi_signal_provenance_carries_no_run_id(monkeypatch):
    bks = _load("bks_runs", "build-ksi-signal.py")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    monkeypatch.setenv("GITHUB_WORKFLOW_REF", "o/r/.github/workflows/deploy-with-opa.yml@refs/heads/main")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_RUN_ID", "12345678901")
    prov = bks.build_provenance()
    assert "run_id" not in prov["builder"] and "12345678901" not in json.dumps(prov)
    assert prov["source"]["commit"] == "a" * 40
