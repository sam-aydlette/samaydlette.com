"""G7 Detection (T52, VDR-CSO-FAV): the run fails when detection itself failed.

Each known-bad input under tests/fixtures/detection/ fails the gate for its own
reason; the all-good set passes. The workflows no longer substitute empty
documents, so these are the inputs a failed scanner or feed now produces.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "detection"
CONFIG = REPO / "infrastructure" / "schemas" / "detection-feeds.json"
SCHEMA = REPO / "infrastructure" / "schemas" / "detection-feeds.schema.json"
NOW = "2026-11-04T12:00:00+00:00"

GOOD = {"kev": "kev.json", "epss": "epss.csv", "grype": "grype.json", "dependabot": "dependabot.json",
        "previous-vdr": "previous-vdr.json", "checkov": "checkov.sarif", "tfsec": "tfsec.json",
        "codeql": "codeql.json", "zap-api": "zap-api.json"}


def _load():
    spec = importlib.util.spec_from_file_location("detection_gate", REPO / "scripts" / "detection-gate.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run(tmp_path, **swap):
    """Run the gate on the good set with some inputs swapped; returns (rc, summary, stderr)."""
    files = {**GOOD, **swap}
    work = tmp_path / "w"
    work.mkdir()
    for name in set(files.values()):
        for src in FIX.glob(name + "*"):
            shutil.copy(src, work / src.name)
    args = [sys.executable, str(REPO / "scripts" / "detection-gate.py"), "--now", NOW, "--output", "detection.json"]
    for feed, name in files.items():
        args += [f"--{feed}", name]
    env = {k: v for k, v in os.environ.items() if k not in ("GATE_EVENTS_FILE", "GATE_MODES_FILE")}
    r = subprocess.run(args, cwd=work, capture_output=True, text=True, env=env)
    summary = json.loads((work / "detection.json").read_text()) if (work / "detection.json").exists() else None
    return r.returncode, summary, r.stderr


def test_committed_config_matches_its_schema():
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(json.loads(CONFIG.read_text()), json.loads(SCHEMA.read_text()))
    assert _load().load_config()["feeds"]["grype"]["max_age_hours"] == 120


def test_all_good_inputs_pass(tmp_path):
    rc, summary, err = run(tmp_path)
    assert rc == 0, err
    assert summary["result"] == "ok" and {f["feed"] for f in summary["feeds"]} == set(GOOD)
    assert all(f["status"] == "ok" and f["mode"] == "block" for f in summary["feeds"])
    assert {f["feed"]: f["age_hours"] for f in summary["feeds"] if f["age_hours"] is not None} == \
        {"kev": 19.0, "epss": 12.0, "grype": 5.7, "codeql": 6.3, "zap-api": 6.0}


@pytest.mark.parametrize("feed,bad,reason", [
    ("kev", "kev-stale.json", "dateReleased is 811.0h old (max 336h)"),
    ("kev", "kev-empty.json", "no vulnerabilities[]"),
    ("kev", "absent.json", "missing (no file produced)"),
    ("epss", "epss-stale.csv", "score_date is 180.0h old (max 72h)"),
    ("epss", "epss-empty.csv", "no scores"),
    ("grype", "grype-old-db.json", "vulnerability database is 365.7h old (max 120h)"),
    ("grype", "grype-invalid-db.json", "not reported valid"),
    ("grype", "grype-incomplete.json", "no matches[]"),
    ("dependabot", "dependabot-missing.json", "HTTP 403: Resource not accessible by integration"),
    ("dependabot", "dependabot-object.json", "not a JSON array"),
    ("previous-vdr", "previous-vdr-bad.json", "no findings[]"),
    ("checkov", "checkov-fallback.sarif", "the empty fallback document"),
    ("tfsec", "absent.json", "missing"),
    ("codeql", "codeql-missing.json", "no analysis found (HTTP 404)"),
    ("codeql", "codeql-stale.json", "oldest required analysis is 100.0h old (max 72h)"),
    ("codeql", "codeql-missing-category.json", "no analysis on main for /silk-reeling/language:javascript-typescript"),
    ("codeql", "codeql-error.json", "the latest analysis for /language:actions reported an error"),
    ("codeql", "codeql-no-alerts-key.json", "no alerts[] and analyses[]"),
    ("zap-api", "zap-api-stale.json", "@generated is 102.0h old (max 72h)"),
    ("zap-api", "zap-api-empty.json", "no site[]"),
    ("zap-api", "zap-api-undated.json", "@generated absent or unparseable"),
    ("zap-api", "absent.json", "missing (no file produced)"),
])
def test_t52_each_failed_input_fails_the_gate_for_its_reason(tmp_path, feed, bad, reason):
    rc, summary, err = run(tmp_path, **{feed: bad})
    assert rc == 1
    failed = [f for f in summary["feeds"] if f["status"] == "failed"]
    assert [f["feed"] for f in failed] == [feed]
    assert reason in failed[0]["problem"]
    assert f"G7 detection.{feed}" in err


def test_every_failure_is_reported_not_only_the_first(tmp_path):
    rc, summary, _ = run(tmp_path, kev="kev-stale.json", dependabot="dependabot-missing.json",
                         checkov="checkov-fallback.sarif")
    assert rc == 1
    assert sorted(f["feed"] for f in summary["feeds"] if f["status"] == "failed") == ["checkov", "dependabot", "kev"]


def test_each_grype_scan_is_checked_separately(tmp_path):
    work = tmp_path / "w"
    work.mkdir()
    for n in ("grype.json", "grype-old-db.json"):
        shutil.copy(FIX / n, work / n)
    gate = _load()
    cfg = gate.load_config()
    from datetime import datetime
    res = gate.check_grype([work / "grype.json", work / "grype-old-db.json", work / "absent.json"], cfg,
                           datetime.fromisoformat(NOW))
    assert [bool(r.get("problem")) for r in res] == [False, True, True]


def test_every_detection_feed_has_a_governed_mode():
    sys.path.insert(0, str(REPO / "scripts"))
    import _gates
    reg = _gates.load_gate_modes()
    for feed in _load().FEEDS:
        assert _gates.blocks(reg, f"detection.{feed}")
    assert _gates.blocks(reg, "detection.zap.missing") and _gates.blocks(reg, "detection.zap.stale")


def test_a_missing_or_invalid_config_fails_closed(tmp_path):
    gate = _load()
    with pytest.raises(SystemExit, match="not found"):
        gate.load_config(tmp_path / "absent.json")
    cfg = json.loads(CONFIG.read_text())
    del cfg["feeds"]["epss"]
    p = tmp_path / "c.json"
    p.write_text(json.dumps(cfg))
    with pytest.raises(SystemExit, match="feeds must list exactly"):
        gate.load_config(p)


def test_the_workflows_no_longer_substitute_empty_documents():
    for wf in ("deploy-with-opa.yml", "evidence-nightly.yml"):
        text = (REPO / ".github" / "workflows" / wf).read_text()
        for stand_in in ("echo '{\"matches\":[]}'", "echo '[]' > dependabot-alerts.json",
                         "echo '{\"vulnerabilities\":[]}'", "printf 'cve,epss,percentile\\n'",
                         "echo '{\"findings\":[]}'", "\"version\": \"fallback\"", "\"version\":\"fallback\"",
                         "echo '{\"results\": []}'", "> grype-python.json || true"):
            assert stand_in not in text, f"{wf} still writes {stand_in}"
        assert "scripts/detection-gate.py" in text and "fetch-detection-feeds.sh" in text


def test_the_deploy_checks_detection_before_it_applies():
    text = (REPO / ".github" / "workflows" / "deploy-with-opa.yml").read_text()
    assert text.index("name: Detection gate (G7)") < text.index("name: Terraform Apply")


def test_the_fetch_script_never_writes_a_stand_in():
    text = (REPO / "scripts" / "fetch-detection-feeds.sh").read_text()
    assert "fail()" in text and ".error" in text
    for stand_in in ("echo '[]'", "{\"vulnerabilities\":[]}", "{\"findings\":[]}"):
        assert stand_in not in text


def test_the_fetch_script_keeps_error_text_on_one_line(tmp_path):
    r = subprocess.run(["bash", "-c", f"source <(sed -n '/^fail() {{/,/^}}/p' {REPO / 'scripts' / 'fetch-detection-feeds.sh'}); "
                        "cd " + str(tmp_path) + " && fail x.json $'bad\\n::error::forged'"],
                       capture_output=True, text=True)
    assert r.stdout.count("\n") == 1 and "::error::" not in r.stdout
    assert "\n" not in (tmp_path / "x.json.error").read_text()


def test_a_missing_dast_report_now_blocks_the_build(tmp_path):
    work = tmp_path / "w"
    shutil.copytree(REPO / "tests" / "fixtures" / "gates" / "g1-kev", work)
    (work / "kev.json").write_text('{"vulnerabilities": []}')
    (work / "zap-report.json.error").write_text("no zap-dast-report artifact")
    env = {k: v for k, v in os.environ.items() if k not in ("GATE_EVENTS_FILE", "GATE_MODES_FILE")}
    r = subprocess.run([sys.executable, str(REPO / "scripts" / "build-vdr-report.py"), "--grype", "grype.json",
                        "--kev", "kev.json", "--zap", "zap-report.json", "--ksi-signal", "absent.json",
                        "--checkov-yaml", "absent.yaml", "--opa", "absent.json", "--md-output", "",
                        "--output", "out.json"], cwd=work, capture_output=True, text=True, env=env)
    assert r.returncode == 1 and "No ZAP report at zap-report.json (no zap-dast-report artifact)" in r.stderr
    assert not (work / "out.json").exists()


def test_codeql_requires_every_category_the_workflow_produces():
    """The gate's required categories are exactly the ones codeql.yml uploads,
    so a language dropped from the workflow (or added without a window) fails here."""
    import yaml
    wf = yaml.safe_load((REPO / ".github" / "workflows" / "codeql.yml").read_text())
    produced = set()
    for job in wf["jobs"].values():
        analyze = next(st for st in job["steps"] if "codeql-action/analyze@" in st.get("uses", ""))
        for lang in job["strategy"]["matrix"]["language"]:
            produced.add(analyze["with"]["category"].replace("${{ matrix.language }}", lang))
    assert set(_load().load_config()["feeds"]["codeql"]["categories"]) == produced


def test_codeql_and_zap_api_windows_are_the_class_c_three_days():
    cfg = _load().load_config()
    assert cfg["feeds"]["codeql"]["max_age_hours"] == 72
    assert cfg["feeds"]["zap-api"]["max_age_hours"] == 72


def test_codeql_config_without_categories_fails_closed(tmp_path):
    cfg = json.loads(CONFIG.read_text())
    cfg["feeds"]["codeql"]["categories"] = []
    p = tmp_path / "c.json"
    p.write_text(json.dumps(cfg))
    with pytest.raises(SystemExit, match="codeql.categories"):
        _load().load_config(p)
