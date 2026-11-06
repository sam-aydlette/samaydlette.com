"""The evidence SLA watchdog must page on every way the evidence can go stale.

From 2026-09-09 to 2026-09-24 the nightly VDR refresh failed every night and
nothing reached the operator. The watchdog (infrastructure/watchdog/) turns
facts into CloudWatch metrics that alarms page on: the VDR's age, the runtime
signal's age, whether the nightly last succeeded, and how many published
artifacts are past their governed freshness window (REQ-PUB-2). The windows come
from infrastructure/schemas/freshness-config.json, never from the code.

The logic is tested directly in node. The handler is run against stand-in AWS
SDK packages in a temporary directory, so the shipped wiring is exercised too.
"""

import json
import re
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


CONFIG = REPO / "infrastructure" / "schemas" / "freshness-config.json"
BAD_CONFIG = REPO / "tests" / "fixtures" / "freshness" / "freshness-config-invalid.json"
FRESH = "2026-09-25T10:00:00Z"


def config():
    return json.loads(CONFIG.read_text())


def fresh_objects():
    """Every listed artifact, freshly written (1-2h old)."""
    objects = {}
    for a in config()["artifacts"]:
        doc = {}
        if a["timestamp"]["source"] == "json":
            node = doc
            *parents, leaf = a["timestamp"]["field"].split(".")
            for k in parents:
                node = node.setdefault(k, {})
            node[leaf] = FRESH
        objects[a["path"]] = doc
    objects[".well-known/vdr-status.json"] = status()
    return objects


def readings(objects, last_modified=FRESH):
    return {k: {"body": json.dumps(v), "lastModified": last_modified} for k, v in objects.items()}


def compute(objects, cfg=None, last_modified=FRESH):
    script = textwrap.dedent(f"""
        import {{ computeMetrics, parseConfig }} from '{WATCHDOG / "logic.mjs"}';
        const now = Date.parse('{NOW}');
        const out = computeMetrics(parseConfig({json.dumps(cfg or config())}),
                                   {json.dumps(readings(objects, last_modified))}, now);
        console.log(JSON.stringify(out));
    """)
    return node(script, REPO)


def metrics(vdr=None, runtime=None, status=None):
    objects = fresh_objects()
    for key, value in ((".well-known/vdr-report.json", vdr), (".well-known/ksi-signal-runtime.json", runtime),
                       (".well-known/vdr-status.json", status)):
        if value is None:
            objects.pop(key)
        else:
            objects[key] = value
    return compute(objects)["metrics"]


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


def test_every_listed_artifact_inside_its_window_counts_none_stale():
    out = compute(fresh_objects())
    assert out["metrics"]["StaleArtifacts"] == 0 and out["stale"] == []


def test_each_listed_artifact_past_its_own_window_is_counted():
    objects = fresh_objects()
    # 25h: inside the deploy window (720h) but past the nightly window (24h).
    objects[".well-known/trust-center.json"] = {"generated_at": "2026-09-24T11:00:00Z"}
    objects[".well-known/vdr-trend.json"] = {"updated_at": "2026-09-24T11:00:00Z"}
    # 31 days: past the deploy window.
    objects[".well-known/security-decision-record.json"] = {"metadata": {"lastUpdated": "2026-08-25T00:00:00Z"}}
    out = compute(objects)
    assert sorted(out["stale"]) == [".well-known/security-decision-record.json", ".well-known/vdr-trend.json"]
    assert out["metrics"]["StaleArtifacts"] == 2


def test_missing_unreadable_or_untimestamped_artifacts_count_as_stale():
    objects = fresh_objects()
    del objects[".well-known/boundary-map.json"]
    objects[".well-known/reconcile-report.json"] = {"no": "timestamp"}
    out = compute(objects)
    assert set(out["stale"]) == {".well-known/boundary-map.json", ".well-known/reconcile-report.json"}


def test_last_modified_artifacts_are_aged_by_the_object_time():
    stale = [a["path"] for a in config()["artifacts"] if a["timestamp"]["source"] == "last_modified"]
    assert ".well-known/iiw.csv" in stale
    out = compute(fresh_objects(), last_modified="2026-08-01T00:00:00Z")
    assert set(stale) <= set(out["stale"])


def test_the_windows_come_from_the_config():
    cfg = config()
    for a in cfg["artifacts"]:
        if a["path"] == ".well-known/vdr-report.json":
            a["max_age_hours"] = 4
        if a["path"] == ".well-known/vdr-status.json":
            a["max_age_hours"] = 2
    objects = fresh_objects()
    objects[".well-known/vdr-report.json"] = {"emitted_at": "2026-09-25T06:00:00Z"}  # 6h
    objects[".well-known/vdr-status.json"] = status(finished_at="2026-09-25T09:00:00Z")  # 3h
    out = compute(objects, cfg)
    assert ".well-known/vdr-report.json" in out["stale"]
    assert out["metrics"]["NightlyFailed"] == 1


def _parse(cfg):
    script = textwrap.dedent(f"""
        import {{ parseConfig }} from '{WATCHDOG / "logic.mjs"}';
        try {{ const c = parseConfig({json.dumps(cfg)}); console.log(JSON.stringify({{ok: true, n: c.artifacts.length}})); }}
        catch (e) {{ console.log(JSON.stringify({{ok: false, error: e.message}})); }}
    """)
    return node(script, REPO)


def test_the_watchdog_rejects_an_invalid_config():
    assert _parse(config())["ok"] is True
    bad = json.loads(BAD_CONFIG.read_text())
    assert _parse(bad)["ok"] is False
    for mutate in (lambda c: c.pop("version"),
                   lambda c: c["artifacts"][0].update(max_age_hours="24"),
                   lambda c: c["artifacts"][0].update(path=".well-known/../x"),
                   lambda c: c["artifacts"].append(dict(c["artifacts"][0])),
                   lambda c: c.update(artifacts=[a for a in c["artifacts"] if a["path"] != ".well-known/vdr-status.json"])):
        cfg = config()
        mutate(cfg)
        assert _parse(cfg)["ok"] is False, cfg


def _fake_sdk(tmp_path, objects, cfg=None):
    """Copy the watchdog next to stand-in @aws-sdk packages that serve `objects`
    from S3 and record every PutMetricData call. The governed config is
    packaged beside the handler, as watchdog.tf packages it."""
    for f in ("index.mjs", "logic.mjs"):
        shutil.copy(WATCHDOG / f, tmp_path / f)
    if cfg is not False:
        (tmp_path / "freshness-config.json").write_text(json.dumps(cfg or config()))
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
            return {{ Body: {{ transformToString: async () => JSON.stringify(body) }},
                      LastModified: new Date('{FRESH}') }};
          }}
        }}
    """))
    (cw / "index.js").write_text(textwrap.dedent("""
        export class PutMetricDataCommand { constructor(input) { this.input = input; } }
        export class CloudWatchClient {
          async send(cmd) { globalThis.__puts = (globalThis.__puts || []).concat([cmd.input]); return {}; }
        }
    """))


def run_handler(tmp_path, objects, cfg=None):
    _fake_sdk(tmp_path, objects, cfg)
    script = textwrap.dedent(f"""
        process.env.S3_BUCKET = 'site-bucket';
        process.env.METRIC_NAMESPACE = 'Samaydlette/Evidence';
        console.log = ((orig) => (...a) => {{ globalThis.__logs = (globalThis.__logs||[]).concat(a); }})(console.log);
        const {{ handler }} = await import('./index.mjs');
        let out = null, error = null;
        try {{ out = await handler({{}}, {{}}, {{ now: Date.parse('{NOW}') }}); }} catch (e) {{ error = e.message; }}
        process.stdout.write(JSON.stringify({{ out, error, reads: globalThis.__reads || [], puts: globalThis.__puts || [],
                                              logs: globalThis.__logs || [] }}) + '\\n');
    """)
    return node(script, tmp_path)


def test_handler_reads_every_listed_object_and_publishes_one_metric_batch(tmp_path):
    objects = fresh_objects()
    objects[".well-known/vdr-report.json"] = {"emitted_at": "2026-09-25T06:00:00Z"}
    r = run_handler(tmp_path, objects)
    assert {x["Key"] for x in r["reads"]} == {a["path"] for a in config()["artifacts"]}
    assert all(x["Bucket"] == "site-bucket" for x in r["reads"])
    (put,) = r["puts"]
    assert put["Namespace"] == "Samaydlette/Evidence"
    names = {d["MetricName"]: d["Value"] for d in put["MetricData"]}
    assert names["NightlyFailed"] == 0 and names["StaleArtifacts"] == 0
    assert names["VdrAgeHours"] == pytest.approx(6)
    assert json.loads(r["logs"][-1])["config_version"] == config()["version"]


def test_handler_turns_a_missing_object_into_a_breach_not_a_crash(tmp_path):
    objects = fresh_objects()
    del objects[".well-known/vdr-report.json"]
    del objects[".well-known/vdr-status.json"]
    r = run_handler(tmp_path, objects)
    names = {d["MetricName"]: d["Value"] for d in r["puts"][0]["MetricData"]}
    assert names["VdrAgeHours"] > 24
    assert names["NightlyFailed"] == 1
    assert names["StaleArtifacts"] == 2


@pytest.mark.parametrize("cfg", [False, "bad"])
def test_handler_with_a_missing_or_invalid_config_publishes_nothing(tmp_path, cfg):
    # Nothing published = missing data = every alarm breaching: it pages.
    r = run_handler(tmp_path, fresh_objects(), json.loads(BAD_CONFIG.read_text()) if cfg == "bad" else False)
    assert r["error"] and r["puts"] == [] and r["reads"] == []


def test_alarm_thresholds_and_reads_come_from_the_governed_config():
    """The alarms page on the governed windows, the role reads exactly the
    listed objects, and the config ships with the function."""
    tf = (REPO / "infrastructure" / "watchdog.tf").read_text()
    logic = (WATCHDOG / "logic.mjs").read_text()
    assert 'jsondecode(file("${path.module}/schemas/freshness-config.json"))' in tf
    assert 'threshold = local.freshness_windows[".well-known/vdr-report.json"]' in tf
    assert 'threshold = local.freshness_windows[".well-known/ksi-signal-runtime.json"]' in tf
    assert 'metric    = "NightlyFailed"\n      threshold = 0' in tf
    assert 'metric    = "StaleArtifacts"\n      threshold = 0' in tf
    assert 'treat_missing_data  = "breaching"' in tf
    assert '[for p in keys(local.freshness_windows) : "${data.aws_s3_bucket.website.arn}/${p}"]' in tf
    assert 'filename = "freshness-config.json"' in tf
    # No window is a literal in the watchdog any more.
    assert "MAX_BEACON_AGE_HOURS" not in logic
    assert not re.search(r"threshold\s*=\s*(24|26)\b", tf)
