"""CDS-TRC-ACL: access to the certification data is logged, within the
operator's privacy limits, and only monthly aggregates are published."""
import gzip
import importlib.util
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "edge-access-logging"


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


chk = _load("edge_check", "check-edge-access-logging.py")
summ = _load("access_summary", "build-access-summary.py")
NAME = "samaydlette-com-edge-access"
NOW = datetime(2026, 11, 5, 12, tzinfo=timezone.utc)


def _j(p):
    return json.loads((FIX / p).read_text())


# --- the configuration check --------------------------------------------------------

def test_the_allowlist_equals_the_bootstrap_delivery_fields():
    tf = (REPO / "infrastructure" / "bootstrap" / "trust-access-logs.tf").read_text()
    block = re.search(r"edge_access_log_fields = \[(.*?)\]", tf, re.S).group(1)
    assert tuple(re.findall(r'"([^"]+)"', block)) == chk.ALLOWED_FIELDS
    assert "local.edge_access_log_fields" in tf


def test_no_identifying_field_is_allowed():
    assert not set(chk.ALLOWED_FIELDS) & set(chk.IDENTIFYING)


def test_the_good_configuration_passes():
    assert chk.problems(_j("good-deliveries.json"), _j("delivery-source.json"), NAME) == []


def test_the_known_bad_fixture_fails_for_identifying_fields(capsys):
    rc = chk.main(["--deliveries", str(FIX / "known-bad-deliveries.json"),
                   "--source", str(FIX / "delivery-source.json"), "--name", NAME])
    assert rc == 1
    err = capsys.readouterr().err
    assert "c-ip" in err and "cs-uri-query" in err and "cs(User-Agent)" in err


def test_no_delivery_fails_the_deploy(tmp_path):
    (tmp_path / "d.json").write_text('{"deliveries": []}')
    rc = chk.main(["--deliveries", str(tmp_path / "d.json"), "--source", str(tmp_path / "absent.json"),
                   "--name", NAME])
    assert rc == 1


def test_a_source_that_is_not_the_distribution_fails():
    src = {"deliverySource": {"name": NAME, "logType": "ACCESS_LOGS", "resourceArns": ["arn:aws:s3:::x"]}}
    assert any("not a CloudFront" in p for p in chk.problems(_j("good-deliveries.json"), src, NAME))


def test_a_field_outside_the_allowlist_fails_even_if_not_named_identifying():
    d = _j("good-deliveries.json")
    d["deliveries"][0]["recordFields"].append("x-edge-request-id")
    assert any("outside the privacy allowlist" in p for p in chk.problems(d, _j("delivery-source.json"), NAME))


def test_the_deploy_checks_logging_before_the_sdr_and_publishes_the_summary():
    wf = (REPO / ".github" / "workflows" / "deploy-with-opa.yml").read_text()
    step = wf.index("- name: Check edge access logging and build the access summary")
    assert step < wf.index("- name: Build Security Decision Record")
    body = wf[step:wf.index("\n    - name:", step + 10)]
    assert "check-edge-access-logging.py" in body and "build-access-summary.py" in body
    assert "access-summary.bundle access-summary.json" in wf


def test_raw_edge_records_expire_after_90_days():
    tf = (REPO / "infrastructure" / "logging.tf").read_text()
    for prefix in ('prefix = "cloudfront/"', 'CloudFront/" }'):
        i = tf.index(prefix)
        assert "expiration { days = 90 }" in tf[i:i + 200]


# --- the summary ----------------------------------------------------------------------

def _rec(day, stem, status=200, cc="US", **extra):
    return {"date": day, "time": "10:00:00", "cs-uri-stem": stem, "sc-status": str(status), "c-country": cc, **extra}


def test_only_trust_paths_are_counted_and_nothing_identifying_survives():
    recs = [_rec("2026-11-02", "/.well-known/ksi-signal.json"),
            _rec("2026-11-02", "/trust/index.html", cc="DE"),
            _rec("2026-11-03", "/index.html"),
            _rec("2026-11-03", "/.well-known/wp-login.php", status=404),
            _rec("2026-11-03", "/.well-known/<script>", status=200, **{"c-ip": "192.0.2.7"})]
    doc = summ.build({}, recs, NOW)
    (m,) = doc["months"]
    assert m["requests"] == 4
    assert m["artifacts"] == {"/.well-known/ksi-signal.json": 1, "/trust/": 1, summ.OTHER: 2}
    assert m["countries"] == {"DE": 1, "US": 3}
    text = json.dumps(doc)
    assert "192.0.2.7" not in text and "wp-login" not in text and "<script>" not in text


def test_months_are_carried_forward_and_capped():
    prev = {"artifact": "access-summary",
            "months": [{"month": f"2025-{m:02d}", "coverage_from": f"2025-{m:02d}-01", "requests": 1}
                       for m in range(1, 13)]}
    doc = summ.build(prev, [_rec("2026-11-02", "/trust/")], NOW)
    assert len(doc["months"]) == summ.MONTHS_KEPT
    assert doc["months"][-1]["month"] == "2026-11" and doc["months"][0]["month"] == "2025-01"


def test_a_month_whose_early_records_expired_keeps_its_fuller_count():
    prev = {"artifact": "access-summary",
            "months": [{"month": "2026-08", "coverage_from": "2026-08-01", "requests": 500}]}
    doc = summ.build(prev, [_rec("2026-08-20", "/trust/")], NOW)
    assert doc["months"][0]["requests"] == 500


def test_the_current_month_is_recomputed():
    prev = {"artifact": "access-summary",
            "months": [{"month": "2026-11", "coverage_from": "2026-11-01", "requests": 1}]}
    doc = summ.build(prev, [_rec("2026-11-01", "/trust/"), _rec("2026-11-04", "/trust/")], NOW)
    assert doc["months"][0]["requests"] == 2


def test_gzipped_records_are_read_and_a_bad_line_fails_closed(tmp_path):
    with gzip.open(tmp_path / "a.gz", "wt") as fh:
        fh.write(json.dumps(_rec("2026-11-02", "/trust/")) + "\n")
    assert [r["cs-uri-stem"] for r in summ.read_records(tmp_path)] == ["/trust/"]
    (tmp_path / "b.log").write_text("not json\n")
    with pytest.raises(SystemExit):
        list(summ.read_records(tmp_path))


def test_a_month_younger_than_six_is_never_dropped(tmp_path, monkeypatch):
    prev = {"artifact": "access-summary",
            "months": [{"month": f"2026-{m:02d}", "coverage_from": f"2026-{m:02d}-01", "requests": 1}
                       for m in range(5, 12)]}
    (tmp_path / "prev.json").write_text(json.dumps(prev))
    (tmp_path / "recs").mkdir()
    monkeypatch.setattr(summ, "MONTHS_KEPT", 3)
    with pytest.raises(SystemExit):
        summ.main(["--records", str(tmp_path / "recs"), "--previous", str(tmp_path / "prev.json"),
                   "--output", str(tmp_path / "o.json"), "--md-output", str(tmp_path / "o.md")])


def test_the_deploy_reads_only_this_sites_delivery():
    """The Get* delivery reads are scoped to this site's delivery, source and
    destination, never every delivery in the account."""
    tf = (REPO / "infrastructure" / "bootstrap" / "trust-access-logs.tf").read_text()
    stmt = tf[tf.index('sid = "ReadEdgeAccessDelivery"'):]
    stmt = stmt[:stmt.index("\n  }\n")]
    resources = re.search(r"resources = \[(.*?)\]", stmt, re.S).group(1)
    assert "*" not in resources
    assert {r.strip().rstrip(",") for r in resources.strip().splitlines()} == {
        "aws_cloudwatch_log_delivery.edge_access.arn",
        "aws_cloudwatch_log_delivery_source.edge_access.arn",
        "aws_cloudwatch_log_delivery_destination.edge_access.arn"}


# --- own-records lookup (DEC-160), exercised against a simulated requester -----------

def test_the_own_records_lookup_finds_exactly_the_stated_window():
    found = summ.own_records(summ.EXERCISE["synthetic_records"], summ.EXERCISE["window"])
    assert len(found) == summ.EXERCISE["expected_matches"] == 2
    assert all(set(r) <= set(summ.SUPPLIED_FIELDS) for r in found)
    assert not set(summ.SUPPLIED_FIELDS) & set(chk.IDENTIFYING) and set(summ.SUPPLIED_FIELDS) <= set(chk.ALLOWED_FIELDS)


def test_every_build_exercises_the_lookup_and_delivers_nothing():
    doc = summ.build({}, [], datetime(2026, 11, 6, tzinfo=timezone.utc))
    ex = doc["ownRecordsExercise"]
    assert ex["simulated"] is True and "(simulated)" in ex["requester"]
    assert ex["syntheticCheck"]["result"] == "pass" and ex["deliveredTo"].startswith("nobody")
    assert "DEC-194" in doc["party_records"] and "no deadline" in doc["party_records"]


def test_known_bad_a_lookup_that_misses_fails_the_build(monkeypatch):
    monkeypatch.setitem(summ.EXERCISE, "expected_matches", 3)
    with pytest.raises(SystemExit, match="own-records lookup found 2 synthetic record"):
        summ.build({}, [], datetime(2026, 11, 6, tzinfo=timezone.utc))
