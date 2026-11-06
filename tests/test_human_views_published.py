"""Every JSON or CSV a workflow publishes has its complete human-readable view
published beside it (CDS-TRC-HMR, CDS-CSO-CBF).

The trust manifest says so, and lists each view from the publisher table in
scripts/_signers.py, so the claim is checked here against what the workflows
actually do: each publisher's view step and publish steps are run as written,
in a scratch directory holding the files a run builds, with `aws`, `curl`,
`cosign` and `terraform` replaced by stubs that record every key put under
/.well-known/. Globs and read-loops expand for real, so a report named by an
incident or an issue date counts as much as a literal name. Then, for each
publisher, every JSON or CSV key it puts must have its `.view.md` put too, and
its redaction gate must scan each view it puts.

A committed known-bad publish step (tests/fixtures/human-views/publish-without-
view.sh) puts incident reports without their views and must fail for exactly
that reason.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"
FIX = REPO / "tests" / "fixtures" / "human-views"
sys.path.insert(0, str(REPO / "scripts"))
import _freshness  # noqa: E402
import _signers  # noqa: E402

# Stand-ins for the commands that would reach AWS, the site or Sigstore. Each
# key a step puts under .well-known/ is appended to $PUTS; reading a key back
# ("aws s3 cp s3://.../.well-known/x -") prints the local file of that name.
STUBS = r'''
aws() {
  local key=""
  if [ "$1 $2" = "s3 cp" ]; then
    if [ "$4" = "-" ]; then cat "${3#s3://*/.well-known/}"; return 0; fi
    case "$4" in s3://*) key="${4#s3://*/.well-known/}" ;; esac
  elif [ "$1 $2" = "s3api put-object" ]; then
    while [ $# -gt 0 ]; do [ "$1" = "--key" ] && key="${2#.well-known/}"; shift; done
  fi
  if [ -n "$key" ]; then echo "$key" >> "$PUTS"; fi
  return 0
}
terraform() { echo stub-bucket; }
cosign() { :; }
curl() { echo 404; }
'''


def _step(text, name):
    body = text[text.index(f"- name: {name}"):]
    end = body.find("\n    - name:")
    return body if end < 0 else body[:end]


def _script(step):
    """The step's shell, from its `run: |` or `run: >-` block or one-line `run:`."""
    one = re.search(r"^      run: (?![|>])(.+)$", step, re.M)
    if one:
        return one.group(1)
    head, block = re.split(r"run: [|>]-?\n", step, maxsplit=1)
    lines = []
    for line in block.splitlines():
        if line.strip() and not line.startswith(" " * 8):
            break
        lines.append(line[8:])
    script = "\n".join(lines)
    if "run: >-" in step:
        script = " ".join(x.strip() for x in lines if x.strip())
    return script


def _run(script, cwd, puts, gated):
    script = (script.replace("python3 ../scripts/check-published-redaction.py", "gate")
              .replace("python3 ../../scripts/check-published-redaction.py", "gate")
              .replace("python3 ../../scripts/check-fedramp-id.py", "true"))
    prog = STUBS + f'gate() {{ for f in "$@"; do echo "$f" >> "{gated}"; done; }}\n' + script
    r = subprocess.run(["bash", "-euo", "pipefail", "-c", prog], cwd=cwd, capture_output=True, text=True,
                       env={"PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin", "PUTS": str(puts),
                            "HOME": str(cwd), "GITHUB_SHA": "0" * 40, "SITE_BUCKET": "stub-bucket",
                            "SITE_ORIGIN": "https://stub.invalid"})
    assert r.returncode == 0, r.stderr[-2000:]


def _fill(d, names):
    for n in names:
        p = d / n
        p.parent.mkdir(parents=True, exist_ok=True)
        if not p.exists():
            p.write_text("a,b\n1,2\n" if n.endswith(".csv") else "{}" if n.endswith(".json") else "x\n")


def _tree(tmp_path, work):
    """tmp/scripts -> the real scripts; the work directory below it."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "scripts").symlink_to(REPO / "scripts")
    d = tmp_path / work
    d.mkdir(parents=True)
    return d


def _lines(p):
    return {x for x in p.read_text().split() if x} if p.exists() else set()


def missing_views(puts):
    """Every JSON or CSV key put without its view."""
    return sorted(k for k in puts if _signers.view(k) and _signers.view(k) not in puts)


GOVERNED = [a["path"].rsplit("/", 1)[1] for a in _freshness.load_freshness_config(
    REPO / "infrastructure" / "schemas" / "freshness-config.json")["artifacts"]]


def run_deploy(tmp_path):
    text = (WORKFLOWS / "deploy-with-opa.yml").read_text()
    d = _tree(tmp_path, "infrastructure")
    (d / "schemas").symlink_to(REPO / "infrastructure" / "schemas")
    _fill(d, GOVERNED + ["policies/ac-policy.md", "incident-INC-2026-001-01-initial.json",
                         "incident-INC-2026-001-02-final.json", "incident-reports.md",
                         "fedramp-certification-reports/2026-11-06-sim-x-simulated-certification-report.json"])
    (d / "policy-index.json").write_text(json.dumps({"entries": []}))
    for f in GOVERNED:  # the curated summaries the generators write beside their JSON
        if f.endswith(".json"):
            _fill(d, [f[:-5] + ".md"])
    rep = d / "fedramp-certification-reports" / "2026-11-06-sim-x-simulated-certification-report.json"
    import hashlib
    (d / "fedramp-certification-reports.json").write_text(json.dumps({"reports": [
        {"file": rep.name, "sha256": hashlib.sha256(rep.read_bytes()).hexdigest()}]}))
    puts, gated = tmp_path / "puts.txt", tmp_path / "gated.txt"
    for name in ("Build the human-readable views and the trust manifest (format parity)",
                 "Publication redaction gate (no AWS account ID)",
                 "Publish all signed artifacts to /.well-known/",
                 "Publish FedRAMP Certification Reports byte-identical"):
        script = _script(_step(text, name))
        if name.startswith("Publish FedRAMP"):
            # its own gate scans the report folder; record what it names
            script = script.replace("python3 ../scripts/check-published-redaction.py fedramp-certification-reports/*",
                                    "gate fedramp-certification-reports/*")
        _run(script, d, puts, gated)
    return _lines(puts), _lines(gated)


def run_maintenance(tmp_path):
    text = (WORKFLOWS / "package-maintenance.yml").read_text()
    d = _tree(tmp_path, "infrastructure/out")
    issued = ["ocr-issue-2026-12-01.json", "ocr-issue-2026-12-01.md", "snapshots/2026-12-01/ksi-signal.json",
              "snapshots/2026-12-01/ksi-signal.bundle", "snapshots/2026-12-01/iiw.csv", "snapshot-2026-12-01.json",
              "quarterly-review-2026-12-08.json", "quarterly-review-2026-12-08.md"]
    base = [f"{a}.{x}" for a in ("security-decision-record", "certification-package-overview",
                                 "ongoing-certification-report") for x in ("json", "md", "bundle")]
    _fill(d, base + issued + ["ocr-issues.json", "ocr-issues.bundle", "quarterly-reviews.json",
                              "quarterly-reviews.bundle", "quarterly-review.ics",
                              "security-decision-record.json.intoto.jsonl"])
    (d / "issued.txt").write_text("".join(f + "\n" for f in issued))
    puts, gated = tmp_path / "puts.txt", tmp_path / "gated.txt"
    for name in ("Rebuild the human-readable views (format parity)", "Gates (FedRAMP ID, redaction)",
                 "Publish the certification package to /.well-known/"):
        _run(_script(_step(text, name)), d, puts, gated)
    return _lines(puts), _lines(gated)


def run_incident(tmp_path, publish_step=None):
    text = (WORKFLOWS / "incident-reports.yml").read_text()
    d = _tree(tmp_path, "out")
    _fill(d, ["incident-reports.json", "incident-reports.md", "incident-deliveries.json",
              "incident-INC-2026-001-01-initial.json", "incident-INC-2026-001-02-final.json"])
    puts, gated = tmp_path / "puts.txt", tmp_path / "gated.txt"
    steps = [_script(_step(text, "Rebuild the human-readable views (format parity)")),
             _script(_step(text, "Publication redaction gate (no AWS account ID)")),
             publish_step or _script(_step(text, "Publish incident reports to /.well-known/"))]
    for s in steps:
        _run(s, d, puts, gated)
    return _lines(puts), _lines(gated)


def run_nightly(tmp_path):
    text = (WORKFLOWS / "evidence-nightly.yml").read_text()
    d = _tree(tmp_path, "infrastructure")
    names = [f"{a}.json" for a in ("vdr-report", "vdr-trend", "vdr-detail-report", "vdr-accepted-vulnerabilities",
                                   "vdr-history", "vdr-non-machine-vv", "vdr-monthly", "vdr-audit-log-review",
                                   "vdr-recovery-exercises", "vdr-recovery-exercise-2026-12-01",
                                   "vdr-drill-board-meetings", "vdr-drill-cfo-reviews", "vdr-drill-tabletops",
                                   "vdr-drill-disclosures", "vdr-drill-phishing", "vdr-drill-tabletop-2026-12-01",
                                   "vdr-drill-chaos-gremlins", "vdr-drill-chaos-gremlin-2026-12-01")]
    _fill(d, names)
    (d / "recovery-new.txt").write_text("vdr-recovery-exercise-2026-12-01.json\n")
    (d / "drills-new.txt").write_text("vdr-drill-tabletop-2026-12-01.json\n")
    (d / "gremlin-new.txt").write_text("vdr-drill-chaos-gremlin-2026-12-01.json\n")
    puts, gated = tmp_path / "puts.txt", tmp_path / "gated.txt"
    for name in ("Rebuild the human-readable views (format parity)", "Publish VDR + trend to /.well-known/"):
        _run(_script(_step(text, name)), d, puts, gated)
    return _lines(puts), _lines(gated)


RUNNERS = {"deploy-with-opa.yml": run_deploy, "package-maintenance.yml": run_maintenance,
           "incident-reports.yml": run_incident, "evidence-nightly.yml": run_nightly}


@pytest.mark.parametrize("wf", sorted(RUNNERS))
def test_every_json_a_publisher_puts_has_its_view_put_too(wf, tmp_path):
    puts, _ = RUNNERS[wf](tmp_path)
    assert any(k.endswith(".json") for k in puts), f"{wf}: the harness saw no JSON put"
    assert missing_views(puts) == [], f"{wf} puts JSON or CSV without its human-readable view"


def test_the_named_gaps_are_closed(tmp_path):
    """The files the earlier wiring left without a view: per-incident reports and
    certification reports (deploy), the frozen issue, snapshot and review
    (maintainer), and per-incident reports (incident publisher)."""
    deploy, _ = run_deploy(tmp_path / "d")
    assert {"incident-INC-2026-001-01-initial.view.md", "ksi-signal.schema.view.md",
            "fedramp-certification-reports/2026-11-06-sim-x-simulated-certification-report.view.md"} <= deploy
    maint, _ = run_maintenance(tmp_path / "m")
    assert {"ocr-issue-2026-12-01.view.md", "snapshot-2026-12-01.view.md", "quarterly-review-2026-12-08.view.md",
            "snapshots/2026-12-01/ksi-signal.view.md", "snapshots/2026-12-01/iiw.view.md"} <= maint
    inc, _ = run_incident(tmp_path / "i")
    assert "incident-INC-2026-001-02-final.view.md" in inc


@pytest.mark.parametrize("wf", ["package-maintenance.yml", "incident-reports.yml"])
def test_each_view_a_publisher_puts_passes_its_redaction_gate(wf, tmp_path):
    puts, gated = RUNNERS[wf](tmp_path)
    views = {k for k in puts if k.endswith(".view.md")}
    assert views and views <= gated, sorted(views - gated)


def test_the_deploy_gates_the_certification_report_views(tmp_path):
    puts, gated = run_deploy(tmp_path)
    views = {k for k in puts if k.endswith(".view.md")}
    assert views <= gated, sorted(views - gated)


def test_known_bad_a_publish_step_without_views_fails(tmp_path):
    puts, _ = run_incident(tmp_path, publish_step=(FIX / "publish-without-view.sh").read_text())
    assert missing_views(puts) == ["incident-INC-2026-001-01-initial.json", "incident-INC-2026-001-02-final.json"]


def test_the_manifest_lists_the_view_of_every_json_another_workflow_publishes(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("tm_views", REPO / "scripts" / "build-trust-manifest.py")
    tm = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tm)
    from datetime import datetime, timezone
    m = tm.build(_freshness.load_freshness_config(REPO / "infrastructure" / "schemas" / "freshness-config.json"),
                 tmp_path, {"entries": []}, datetime(2026, 11, 6, tzinfo=timezone.utc))
    by = {a["name"]: a for a in m["artifacts"]}
    for name in ("ocr-issues.json", "quarterly-reviews.json"):
        assert by[name]["human_readable"] == [f"https://samaydlette.com/.well-known/{name[:-5]}.view.md"], name
    for a in m["artifacts"]:
        if a["name"].endswith((".json", ".csv")) and a["name"] not in _signers.VIEWLESS:
            assert any(h.endswith(".view.md") for h in a["human_readable"]), a["name"]


def test_the_maintainer_writes_the_index_artifacts_on_its_own_cadence():
    """ocr-issues.json and quarterly-reviews.json are written only by the
    package maintainer, which runs on a daily schedule: their governed cadence
    is the scheduled unattended run, not the deploy."""
    cfg = {a["path"].rsplit("/", 1)[1]: a for a in _freshness.load_freshness_config(
        REPO / "infrastructure" / "schemas" / "freshness-config.json")["artifacts"]}
    for name in ("ocr-issues.json", "quarterly-reviews.json"):
        assert _signers.signers(name) == ["maintenance"]
        assert cfg[name]["cadence"] == "nightly", name
