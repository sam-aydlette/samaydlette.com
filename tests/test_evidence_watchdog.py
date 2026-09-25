"""The evidence SLA watchdog must page on every way the evidence can go stale.

From 2026-09-09 to 2026-09-24 the nightly VDR refresh failed every night and
nothing reached the operator. The watchdog (infrastructure/watchdog/) turns
three facts into CloudWatch metrics that alarms page on: the VDR's age, the
runtime signal's age, and whether the nightly last succeeded.

The logic is tested directly in node. The handler is run against stand-in AWS
SDK packages in a temporary directory, so the shipped wiring is exercised too.
"""

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
WATCHDOG = REPO / "infrastructure" / "watchdog"
NOW = "2026-09-25T12:00:00Z"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not available")


def node(script, cwd):
    out = subprocess.run(["node", "--input-type=module", "-e", script],
                         cwd=cwd, capture_output=True, text=True, check=True)
    return json.loads(out.stdout.strip().splitlines()[-1])


def metrics(vdr=None, runtime=None, status=None):
    script = textwrap.dedent(f"""
        import {{ computeMetrics }} from '{WATCHDOG / "logic.mjs"}';
        const now = Date.parse('{NOW}');
        console.log(JSON.stringify(computeMetrics({{
          vdr: {json.dumps(vdr)}, runtime: {json.dumps(runtime)}, status: {json.dumps(status)}}}, now)));
    """)
    return node(script, REPO)


def status(result="success", finished_at="2026-09-25T06:00:00Z"):
    return {"result": result, "finished_at": finished_at, "vuln_gate": "success", "reconcile": "success"}


def test_fresh_evidence_and_a_passing_nightly_page_nobody():
    m = metrics(vdr={"emitted_at": "2026-09-25T06:00:00Z"},
                runtime={"emitted_at": "2026-09-25T02:00:00Z"}, status=status())
    assert m["VdrAgeHours"] == pytest.approx(6)
    assert m["RuntimeSignalAgeHours"] == pytest.approx(10)
    assert m["NightlyFailed"] == 0


def test_twelve_days_stale_reads_as_twelve_days():
    # The failure this exists for.
    m = metrics(vdr={"emitted_at": "2026-09-13T12:00:00Z"})
    assert m["VdrAgeHours"] == pytest.approx(12 * 24)


def test_a_failed_nightly_pages_even_while_the_evidence_is_still_fresh():
    m = metrics(vdr={"emitted_at": "2026-09-25T06:00:00Z"}, status=status("failure"))
    assert m["NightlyFailed"] == 1


def test_a_missing_or_stale_beacon_is_a_failure_not_a_pass():
    # A disabled cron writes nothing: silence must page, not look like success.
    assert metrics(status=None)["NightlyFailed"] == 1
    assert metrics(status=status(finished_at="2026-09-24T09:00:00Z"))["NightlyFailed"] == 1  # 27h
    assert metrics(status=status(finished_at="2026-09-24T11:00:00Z"))["NightlyFailed"] == 0  # 25h


def test_unreadable_artifacts_report_as_breaches():
    m = metrics(vdr=None, runtime={"emitted_at": "not a date"})
    assert m["VdrAgeHours"] > 24
    assert m["RuntimeSignalAgeHours"] > 26


def _fake_sdk(tmp_path, objects):
    """Copy the watchdog next to stand-in @aws-sdk packages that serve `objects`
    from S3 and record every PutMetricData call."""
    for f in ("index.mjs", "logic.mjs"):
        shutil.copy(WATCHDOG / f, tmp_path / f)
    s3 = tmp_path / "node_modules" / "@aws-sdk" / "client-s3"
    cw = tmp_path / "node_modules" / "@aws-sdk" / "client-cloudwatch"
    for d in (s3, cw):
        d.mkdir(parents=True)
        (d / "package.json").write_text('{"type": "module", "main": "index.js"}')
    (s3 / "index.js").write_text(textwrap.dedent(f"""
        const OBJECTS = {json.dumps(objects)};
        export class GetObjectCommand {{ constructor(input) {{ this.input = input; }} }}
        export class S3Client {{
          async send(cmd) {{
            globalThis.__reads = (globalThis.__reads || []).concat([cmd.input]);
            const body = OBJECTS[cmd.input.Key];
            if (body === undefined) {{ const e = new Error('NoSuchKey'); e.name = 'NoSuchKey'; throw e; }}
            return {{ Body: {{ transformToString: async () => JSON.stringify(body) }} }};
          }}
        }}
    """))
    (cw / "index.js").write_text(textwrap.dedent("""
        export class PutMetricDataCommand { constructor(input) { this.input = input; } }
        export class CloudWatchClient {
          async send(cmd) { globalThis.__puts = (globalThis.__puts || []).concat([cmd.input]); return {}; }
        }
    """))


def run_handler(tmp_path, objects):
    _fake_sdk(tmp_path, objects)
    script = textwrap.dedent(f"""
        process.env.S3_BUCKET = 'site-bucket';
        process.env.METRIC_NAMESPACE = 'Samaydlette/Evidence';
        console.log = ((orig) => (...a) => {{ globalThis.__logs = (globalThis.__logs||[]).concat(a); }})(console.log);
        const {{ handler }} = await import('./index.mjs');
        const out = await handler({{}}, {{}}, {{ now: Date.parse('{NOW}') }});
        process.stdout.write(JSON.stringify({{ out, reads: globalThis.__reads, puts: globalThis.__puts }}) + '\\n');
    """)
    return node(script, tmp_path)


def test_handler_reads_the_three_objects_and_publishes_one_metric_batch(tmp_path):
    r = run_handler(tmp_path, {
        ".well-known/vdr-report.json": {"emitted_at": "2026-09-25T06:00:00Z"},
        ".well-known/ksi-signal-runtime.json": {"emitted_at": "2026-09-25T02:00:00Z"},
        ".well-known/vdr-status.json": status(),
    })
    assert {x["Key"] for x in r["reads"]} == {
        ".well-known/vdr-report.json", ".well-known/ksi-signal-runtime.json", ".well-known/vdr-status.json"}
    assert all(x["Bucket"] == "site-bucket" for x in r["reads"])
    (put,) = r["puts"]
    assert put["Namespace"] == "Samaydlette/Evidence"
    names = {d["MetricName"]: d["Value"] for d in put["MetricData"]}
    assert names["NightlyFailed"] == 0
    assert names["VdrAgeHours"] == pytest.approx(6)


def test_handler_turns_a_missing_object_into_a_breach_not_a_crash(tmp_path):
    r = run_handler(tmp_path, {".well-known/ksi-signal-runtime.json": {"emitted_at": "2026-09-25T02:00:00Z"}})
    names = {d["MetricName"]: d["Value"] for d in r["puts"][0]["MetricData"]}
    assert names["VdrAgeHours"] > 24
    assert names["NightlyFailed"] == 1


def test_alarm_thresholds_match_the_logic():
    """The alarms page on the thresholds the docs and the logic state."""
    tf = (REPO / "infrastructure" / "watchdog.tf").read_text()
    logic = (WATCHDOG / "logic.mjs").read_text()
    assert 'metric    = "VdrAgeHours"\n      threshold = 24' in tf
    assert 'metric    = "RuntimeSignalAgeHours"\n      threshold = 26' in tf
    assert 'metric    = "NightlyFailed"\n      threshold = 0' in tf
    assert 'treat_missing_data  = "breaching"' in tf
    assert "MAX_BEACON_AGE_HOURS = 26" in logic
