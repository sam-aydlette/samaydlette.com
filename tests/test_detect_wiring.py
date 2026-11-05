"""Detection wiring for VDR-CSO-DAC, VDR-CSO-DET and VDR-TFR-PSD/PCD (SAST + DAST).

CodeQL analyses first-party code on change, after each deploy and daily; ZAP
scans the site and, authenticated, the Silk Reeling API daily and after each
deploy; both reach the VDR through the detection feeds, the detection gate and
the builder in the deploy and the nightly; and a missed DAST scan blocks after
three days. These tests read the workflows as data, and run the feed fetcher
against a scripted `gh`, so a change that unwires any of it fails here.
"""
import json
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
WF = REPO / ".github" / "workflows"
DEPLOY = "Deploy Website with OPA Compliance"
PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
SECRETS = ("SILK_DAST_USERNAME", "SILK_DAST_PASSWORD", "SILK_DAST_TOTP_SECRET", "SILK_DAST_USER_POOL_ID")


def _wf(name):
    return yaml.safe_load((WF / name).read_text())


def _on(wf):
    return wf.get("on", wf.get(True))  # PyYAML reads the bare key `on` as True


def _steps(wf, job=None):
    jobs = _wf(wf)["jobs"]
    return [s for name, j in jobs.items() if job in (None, name) for s in j.get("steps", [])]


def _step(wf, name, job=None):
    return next(s for s in _steps(wf, job) if s.get("name") == name)


def _guarded(job):
    cond = " ".join(str(job.get("if", "")).split())
    return ("github.event.workflow_run.conclusion == 'success'" in cond
            and "github.event.workflow_run.event != 'pull_request'" in cond)


@pytest.mark.parametrize("name", ["codeql.yml", "zap-dast.yml"])
def test_every_action_is_pinned_by_commit(name):
    for s in _steps(name):
        if "uses" in s:
            assert PIN.match(s["uses"]), s["uses"]


def test_codeql_runs_on_change_after_deploy_and_daily():
    on = _on(_wf("codeql.yml"))
    assert on["push"]["branches"] == ["main"] and on["pull_request"]["branches"] == ["main"]
    assert on["schedule"] and on["workflow_run"] == {"workflows": [DEPLOY], "types": ["completed"],
                                                     "branches": ["main"]}
    assert _wf("codeql.yml")["permissions"] == {"contents": "read"}


def test_codeql_covers_this_repos_code_and_the_silk_reeling_app():
    jobs = _wf("codeql.yml")["jobs"]
    assert set(jobs["repo"]["strategy"]["matrix"]["language"]) == {"python", "javascript-typescript", "actions"}
    assert set(jobs["silk-reeling"]["strategy"]["matrix"]["language"]) == {"python", "javascript-typescript"}
    for job in jobs.values():
        assert _guarded(job)
        assert job["permissions"] == {"contents": "read", "security-events": "write"}
    silk = jobs["silk-reeling"]
    assert "github.event_name != 'pull_request'" in silk["if"]
    init = next(s for s in silk["steps"] if "codeql-action/init@" in s.get("uses", ""))
    analyze = next(s for s in silk["steps"] if "codeql-action/analyze@" in s.get("uses", ""))
    assert init["with"]["source-root"] == "silk-reeling"
    # The database holds the private source; it is never uploaded.
    assert analyze["with"]["upload-database"] is False
    fetch = _step("codeql.yml", "Fetch the Silk Reeling source (the ref the deploy builds)")
    assert "vars.SILK_REELING_REF" in fetch["env"]["SILK_REELING_REF"]
    assert "rm -rf silk-reeling/.git" in fetch["run"]


def test_zap_runs_at_least_every_three_days_and_after_each_deploy():
    on = _on(_wf("zap-dast.yml"))
    for entry in on["schedule"]:
        minute, hour, dom, month, dow = entry["cron"].split()
        assert (dom, month, dow) == ("*", "*", "*"), entry  # daily
    assert on["workflow_run"] == {"workflows": [DEPLOY], "types": ["completed"], "branches": ["main"]}
    assert all(_guarded(j) for j in _wf("zap-dast.yml")["jobs"].values())


def test_api_scan_is_authenticated_and_never_prints_the_token():
    jobs = _wf("zap-dast.yml")["jobs"]
    assert set(jobs) == {"zap_baseline", "zap_api"}
    assert jobs["zap_api"]["permissions"] == {"contents": "read"}
    names = [s.get("name") for s in jobs["zap_api"]["steps"]]
    sign_in = _step("zap-dast.yml", "Sign in the DAST scanner user (Cognito SRP + TOTP)")
    assert set(sign_in["env"]) == set(SECRETS)
    run = sign_in["run"]
    assert run.index("::add-mask::${token}") < run.index("GITHUB_ENV")
    assert "echo \"$token\"" not in run and "echo $token" not in run
    scan = _step("zap-dast.yml", "ZAP API Scan (authenticated)")
    assert scan["uses"].startswith("zaproxy/action-api-scan@")
    assert scan["env"]["ZAP_AUTH_HEADER_SITE"] == "samaydlette.com"
    assert scan["with"]["artifact_name"] == "zap-api-report"
    assert re.search(r"@sha256:[0-9a-f]{64}$", _wf("zap-dast.yml")["env"]["ZAP_IMAGE"])
    # The token is proven accepted, and the API proven closed without it, around the scan.
    check = names.index("Verify the token is accepted and the API refuses without it")
    after = names.index("Verify the token still held after the scan")
    assert check < names.index("ZAP API Scan (authenticated)") < after
    assert '"$without" = 401' in jobs["zap_api"]["steps"][check]["run"]
    base = _step("zap-dast.yml", "ZAP Baseline Scan")
    assert base["with"]["artifact_name"] == "zap-dast-report"


@pytest.mark.parametrize("wf,job", [("deploy-with-opa.yml", "deploy"), ("evidence-nightly.yml", "refresh")])
def test_publishers_fetch_gate_and_build_with_codeql_and_the_api_scan(wf, job):
    perms = _wf(wf)["jobs"][job]["permissions"]
    assert perms.get("security-events") == "read" and perms.get("actions") == "read"
    steps = _steps(wf, job)
    names = [s.get("name") for s in steps]
    fetch = steps[names.index("Fetch detection feeds")]
    assert fetch["env"]["ACTIONS_TOKEN"] == "${{ secrets.GITHUB_TOKEN }}"
    gate = steps[names.index("Detection gate (G7)")]["run"]
    assert "--codeql codeql-alerts.json" in gate and "--zap-api zap-api-report.json" in gate
    build = steps[names.index("Build VDR Report (FedRAMP 20x Class C)")]["run"]
    for arg in ("--codeql codeql-alerts.json", "--zap-api zap-api-report.json", "--zap zap-report.json",
                "--zap-max-age-days 3"):
        assert arg in build, arg
    assert names.index("Fetch detection feeds") < names.index("Detection gate (G7)") \
        < names.index("Build VDR Report (FedRAMP 20x Class C)")


def test_deploy_stops_before_apply_without_the_scanner_credentials():
    steps = _steps("deploy-with-opa.yml", "deploy")
    names = [s.get("name") for s in steps]
    req = steps[names.index("Require the DAST scanner credentials")]
    assert set(req["env"]) == set(SECRETS)
    assert all(req["env"][k] == "${{ secrets.%s }}" % k for k in SECRETS)
    assert "exit 1" in req["run"] and "echo \"${!k" not in req["run"]
    assert names.index("Require the DAST scanner credentials") < names.index("Terraform Apply")


def _bad_secrets_check(tmp_path, env):
    req = _step("deploy-with-opa.yml", "Require the DAST scanner credentials", "deploy")
    script = tmp_path / "check.sh"
    script.write_text(req["run"])
    base = {k: v for k, v in os.environ.items() if not k.startswith("SILK_DAST_")}
    return subprocess.run(["bash", "-e", str(script)], env={**base, **env}, capture_output=True, text=True)


def test_the_credentials_check_fails_on_a_missing_secret_and_passes_with_all(tmp_path):
    full = {k: "x" for k in SECRETS}
    assert _bad_secrets_check(tmp_path, full).returncode == 0
    r = _bad_secrets_check(tmp_path, {**full, "SILK_DAST_TOTP_SECRET": ""})
    assert r.returncode == 1 and "SILK_DAST_TOTP_SECRET" in r.stdout


# ---------------------------------------------------------------- feed fetcher

FAKE_GH = r"""#!/usr/bin/env bash
# Scripted gh: answers from $FAKE_DIR, logs every call.
echo "$*" >> "$FAKE_DIR/calls.log"
case "$1 $2" in
  "run list") echo "${FAKE_RUN_ID:-}"; exit 0 ;;
  "run download")
    shift 2; name=""; dir=""
    while [ $# -gt 0 ]; do case "$1" in -n) name=$2; shift 2;; -D) dir=$2; shift 2;; *) shift;; esac; done
    [ -f "$FAKE_DIR/$name.json" ] || exit 1
    mkdir -p "$dir" && cp "$FAKE_DIR/$name.json" "$dir/report_json.json"; exit 0 ;;
esac
if [ "$1" = api ]; then
  for a in "$@"; do
    case "$a" in
      */code-scanning/analyses*) [ -f "$FAKE_DIR/analyses.json" ] || { echo "gh: no analysis found (HTTP 404)" >&2; exit 1; }
                                 cat "$FAKE_DIR/analyses.json"; exit 0 ;;
      */code-scanning/alerts*) cat "$FAKE_DIR/alerts-p1.json" "$FAKE_DIR/alerts-p2.json"; exit 0 ;;
      */dependabot/alerts*) echo '[]'; exit 0 ;;
    esac
  done
fi
exit 1
"""


def _fetch(tmp_path, *, run_id="42", analyses=True, artifacts=("zap-dast-report", "zap-api-report")):
    fake = tmp_path / "fake"
    (fake / "bin").mkdir(parents=True)
    gh = fake / "bin" / "gh"
    gh.write_text(FAKE_GH)
    gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
    curl = fake / "bin" / "curl"
    curl.write_text("#!/usr/bin/env bash\nexit 22\n")  # every public feed unreachable: not under test here
    curl.chmod(curl.stat().st_mode | stat.S_IEXEC)
    if analyses:
        (fake / "analyses.json").write_text(json.dumps([
            {"category": "/language:python", "created_at": "2026-11-04T05:41:00Z", "error": "",
             "results_count": 1, "commit_sha": "a" * 40, "tool": {"name": "CodeQL", "version": "2.23"},
             "url": "https://api.github.com/x", "sarif_id": "zzz"}]))
    alert = {"number": 9, "state": "open", "created_at": "2026-11-03T00:00:00Z", "html_url": "https://github.com/x",
             "rule": {"id": "js/xss", "name": "js/xss", "description": "XSS", "severity": "error",
                      "security_severity_level": "high", "tags": ["security"]},
             "most_recent_instance": {"ref": "refs/heads/main", "category": "/language:javascript-typescript",
                                      "location": {"path": "website/assets/js/trust.js", "start_line": 3},
                                      "message": {"text": "m"}}}
    (fake / "alerts-p1.json").write_text(json.dumps([alert]))
    (fake / "alerts-p2.json").write_text(json.dumps([{**alert, "number": 10}]))
    for a in artifacts:
        (fake / f"{a}.json").write_text(json.dumps({"@generated": "Wed, 4 Nov 2026 06:00:00", "site": [], "a": a}))
    work = tmp_path / "work"
    work.mkdir()
    env = {**os.environ, "PATH": f"{fake / 'bin'}:{os.environ['PATH']}", "FAKE_DIR": str(fake),
           "FAKE_RUN_ID": run_id, "SITE_ORIGIN": "https://example.invalid", "GITHUB_REPOSITORY": "o/r",
           "DEPENDABOT_TOKEN": "d", "ACTIONS_TOKEN": "t"}
    r = subprocess.run(["bash", str(REPO / "scripts" / "fetch-detection-feeds.sh")], cwd=work, env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return work, (fake / "calls.log").read_text()


def test_fetcher_takes_codeql_alerts_and_both_zap_reports(tmp_path):
    work, calls = _fetch(tmp_path)
    doc = json.loads((work / "codeql-alerts.json").read_text())
    assert [a["number"] for a in doc["alerts"]] == [9, 10]  # every page
    assert set(doc["alerts"][0]) == {"number", "state", "created_at", "rule", "most_recent_instance"}
    assert "html_url" not in json.dumps(doc) and "sarif_id" not in json.dumps(doc)
    assert doc["analyses"][0]["category"] == "/language:python"
    assert "tool_name=CodeQL" in calls and "state=open" in calls and "ref=refs/heads/main" in calls
    assert json.loads((work / "zap-report.json").read_text())["a"] == "zap-dast-report"
    assert json.loads((work / "zap-api-report.json").read_text())["a"] == "zap-api-report"
    # The latest successful main-branch run, whatever its trigger: no --event filter.
    run_list = next(line for line in calls.splitlines() if line.startswith("run list"))
    assert "--branch main" in run_list and "--status success" in run_list and "--event" not in run_list
    assert run_list.count("zap-dast.yml") == 1 and calls.count("run download 42") == 2


def test_fetcher_never_substitutes_a_missing_codeql_or_api_report(tmp_path):
    work, _ = _fetch(tmp_path, analyses=False, artifacts=("zap-dast-report",))
    assert not (work / "codeql-alerts.json").exists()
    assert "no analysis found" in (work / "codeql-alerts.json.error").read_text()
    assert not (work / "zap-api-report.json").exists()
    assert "zap-api-report" in (work / "zap-api-report.json.error").read_text()
    assert (work / "zap-report.json").exists()
