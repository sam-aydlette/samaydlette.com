"""The monthly Chaos Gremlin restore drill (KSI-RPL-TRC, KSI-RPL-RRO) and the
recovery objectives it measures against, against a stubbed versioned bucket.

scripts/hold-chaos-gremlin.py copies deployed objects into a versioned scratch
bucket, lets the Gremlin (simulated) delete and overwrite some, restores them
from versions and compares them with the deployed commit; the RTO and RPO come
from data/recovery-objectives.json. Every run also feeds a forged restore
through the same comparison, which must catch it.
"""

import copy
import importlib.util
import json
import re
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _ksi_methods  # noqa: E402
import _recovery_objectives as ro  # noqa: E402
import _scheduled_review as sr  # noqa: E402

FIX = REPO / "tests" / "fixtures" / "recovery-objectives"
DUE = date(2026, 12, 1)
NOW = datetime(2026, 12, 1, 7, 0, tzinfo=timezone.utc)


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


gr = _load("hold_chaos_gremlin_t", "hold-chaos-gremlin.py")
rx = _load("hold_recovery_t", "hold-recovery-exercise.py")
TREE = {f"page-{i:02d}.html": f"<html>page {i}<link href='a.css?v='></html>".encode() for i in range(30)}
TREE.update({"index.html": b"<html>home</html>", "assets/a.css": b"body{}", "LICENSE": b"no extension"})


class Clock:
    """Wall time that advances one second per call (S3's whole-second LastModified)."""

    def __init__(self):
        self.t = NOW

    def __call__(self):
        self.t += timedelta(seconds=1)
        return self.t


class StubBucket:
    """A versioned bucket in memory: every write and delete adds a version."""

    def __init__(self, clock, drop_history=False):
        self.v, self.clock, self.drop_history, self.n = {}, clock, drop_history, 0

    def _add(self, key, body, marker=False):
        self.n += 1
        self.v.setdefault(key, []).append({"version_id": f"v{self.n}", "body": body, "delete_marker": marker,
                                           "last_modified": self.clock().replace(microsecond=0)})
        return f"v{self.n}"

    def put(self, key, body):
        return self._add(key, body)

    def delete(self, key):
        self._add(key, None, marker=True)
        if self.drop_history:
            self.v[key] = self.v[key][-1:]

    def get(self, key):
        latest = (self.v.get(key) or [None])[-1]
        return None if latest is None or latest["delete_marker"] else latest["body"]

    def versions(self, key):
        return [{k: x[k] for k in ("version_id", "last_modified", "delete_marker")} for x in self.v.get(key, [])]

    def restore_version(self, key, version_id):
        body = next(x["body"] for x in self.v[key] if x["version_id"] == version_id)
        self._add(key, body)


def _live(tree, tamper=()):
    def get(url):
        rel = url.split("samaydlette.com/", 1)[1]
        body = tree.get(rel)
        if body is None:
            return 404, b""
        return 200, (b"tampered" if rel in tamper else body.replace(b"?v=", b"?v=1730000000"))
    return get


def _drill(bucket=None, tree=TREE, get=None, objectives=None):
    clock = Clock()
    s3 = bucket(clock) if bucket else StubBucket(clock)
    return gr.drill(DUE, tree, get or _live(tree), s3, objectives or ro.load(), rx.normalize, "drill/x/",
                    wallclock=clock, sleep=lambda s: None)


def _results(checks):
    return {c["id"]: c["result"] for c in checks}


# --- the drill -------------------------------------------------------------------------------

def test_the_drill_damages_restores_and_matches_the_commit():
    checks, rec = _drill()
    assert _results(checks) == {"copied-in": "pass", "damage": "pass", "restored": "pass", "rto": "pass",
                                "rpo": "pass", "forgery-caught": "pass"}
    assert len(rec["objects"]) == gr.SAMPLE and "index.html" in rec["objects"]
    assert len(rec["damaged"]["deleted"]) == gr.DELETE and len(rec["damaged"]["overwritten"]) == gr.OVERWRITE
    assert "LICENSE" not in rec["objects"]
    assert 0 < rec["oldestRestorePointSeconds"] < 3600


def test_each_month_draws_a_different_sample_and_damage():
    assert gr.sample(TREE, DUE) != gr.sample(TREE, date(2027, 1, 1))
    assert gr.sample(TREE, DUE) == gr.sample(TREE, DUE)


def test_known_bad_the_planted_forgery_is_what_the_comparison_catches():
    """The bad input changes the result: the Gremlin's bytes in place of a restored object."""
    bodies = {r: TREE[r] for r in ("index.html", "page-01.html")}
    assert gr.mismatches(bodies, TREE, rx.normalize) == []
    assert gr.mismatches({**bodies, "page-01.html": gr.GREMLIN_BYTES}, TREE, rx.normalize) == ["page-01.html"]


def test_known_bad_a_bucket_that_loses_history_fails_the_restore():
    checks, _ = _drill(bucket=lambda c: StubBucket(c, drop_history=True))
    assert _results(checks)["restored"] == "fail"


def test_known_bad_a_restore_that_picks_the_gremlins_version_fails():
    class NewestFirst(StubBucket):
        def restore_version(self, key, version_id):
            self._add(key, self.v[key][-1]["body"] or gr.GREMLIN_BYTES)
    checks, _ = _drill(bucket=NewestFirst)
    assert _results(checks)["restored"] == "fail"


def test_known_bad_damage_that_did_not_land_fails_the_drill():
    class Immune(StubBucket):
        def delete(self, key):
            pass

        def put(self, key, body):
            return None if body == gr.GREMLIN_BYTES else super().put(key, body)
    checks, _ = _drill(bucket=Immune)
    assert _results(checks)["damage"] == "fail"


def test_known_bad_a_live_site_that_is_not_the_commit_stops_the_drill():
    rels = gr.sample(TREE, DUE)
    checks, _ = _drill(get=_live(TREE, tamper={rels[0]}))
    assert _results(checks) == {"copied-in": "fail"}


def test_known_bad_objectives_the_measurement_exceeds_fail():
    obj = copy.deepcopy(ro.load())
    obj["rpo"]["hours"] = 0
    obj["rto"]["hours"] = 0
    checks, _ = _drill(objectives=obj)
    assert _results(checks)["rpo"] == "fail"


def test_the_record_is_simulated_screened_and_carries_the_objectives(tmp_path):
    clock = Clock()
    doc = gr.build(DUE, NOW, "FR-TEST", TREE, _live(TREE), StubBucket(clock), "a" * 40, ro.load(), rx.normalize,
                   wallclock=clock, sleep=lambda s: None)
    assert doc["result"] == "pass" and doc["simulated"] is True
    assert doc["objectives"] == {"rtoHours": 504, "rpoHours": 24, "source": "data/recovery-objectives.json"}
    assert doc["gremlin"].endswith("(simulated)") and doc["engagement"]
    assert doc["bucket"].startswith("aws_s3_bucket.recovery_drill")


def test_a_held_drill_is_indexed_and_counts(tmp_path, monkeypatch):
    monkeypatch.setattr(gr, "_rx", lambda: type("R", (), {"site_tree": staticmethod(lambda c, r: TREE),
                                                          "REPO": REPO, "http_get": _live(TREE),
                                                          "normalize": staticmethod(rx.normalize)}))
    clock = Clock()
    index, entries, files, failed = gr.run({}, tmp_path, NOW, "FR-TEST", "a" * 40, StubBucket(clock),
                                           wallclock=clock, sleep=lambda s: None)
    assert not failed and [e["dueDate"] for e in entries] == ["2026-12-01"]
    assert files == ["vdr-drill-chaos-gremlin-2026-12-01.json"]
    assert (tmp_path / "vdr-drill-chaos-gremlins.json").is_file()
    assert sr.method_status("chaos-gremlin", index, NOW) == (True, None)
    assert sr.method_status("chaos-gremlin", index, NOW + timedelta(days=32))[0] is False


def test_nothing_is_due_before_the_first_date(tmp_path):
    index, entries, files, failed = gr.run({}, tmp_path, NOW - timedelta(days=2), "FR-TEST", "a" * 40, None)
    assert entries == [] and files == [] and index["reviews"] == []


def test_the_drill_is_a_scheduled_review_signed_by_the_nightly_only():
    import _signers
    rv = sr.REVIEWS["chaos-gremlin"]
    assert rv.publisher == "nightly" and rv.cadence == "monthly"
    assert _signers.signers("vdr-drill-chaos-gremlins.json") == ["nightly"]
    assert _signers.signers("vdr-drill-chaos-gremlin-2026-12-01.json") == ["nightly"]


# --- the recovery objectives ------------------------------------------------------------------

def test_the_objectives_load_and_match_their_schema():
    jsonschema = pytest.importorskip("jsonschema")
    doc = json.loads((REPO / "data" / "recovery-objectives.json").read_text())
    schema = json.loads((REPO / "infrastructure" / "schemas" / "recovery-objectives.schema.json").read_text())
    jsonschema.validate(doc, schema)
    assert ro.rto_hours() == 21 * 24 and ro.rpo_hours() == 24


def test_the_recovery_plan_states_the_same_objectives():
    """Narrative must match config: the plan's numbers are the data's."""
    plan = (REPO / "docs" / "recovery-plan.md").read_text()
    doc = ro.load()
    rto = re.search(r"\*\*Recovery Time Objective \(RTO\):\*\* (\d+) days", plan)
    rpo = re.search(r"\*\*Recovery Point Objective \(RPO\):\*\* (\d+) hours", plan)
    assert rto and int(rto.group(1)) * 24 == doc["rto"]["hours"] and doc["rto"]["stated"] == f"{rto.group(1)} days"
    assert rpo and int(rpo.group(1)) == doc["rpo"]["hours"] and doc["rpo"]["stated"] == f"{rpo.group(1)} hours"


def test_known_bad_an_rpo_longer_than_the_rto_fails_closed():
    with pytest.raises(SystemExit, match="recovery point objective is longer"):
        ro.load(FIX / "rpo-longer-than-rto.json")


def test_known_bad_missing_objectives_fail_closed(tmp_path):
    with pytest.raises(SystemExit, match="not found"):
        ro.load(tmp_path / "absent.json")


# --- availability incidents against the RTO (the second RPL-RRO method) ------------------------

def _availability(incidents):
    return {"feed_type": "availability", "measured_at": NOW.isoformat(), "daily": [{"date": "2026-12-01"}],
            "incidents": incidents}


def test_incidents_inside_the_rto_pass():
    doc = _availability([{"service": "site", "start": "2026-11-20T00:00:00Z", "end": "2026-11-20T01:00:00Z"}])
    assert _ksi_methods.CHECKS["availability-rto"](doc, NOW) == (True, None)
    assert _ksi_methods.CHECKS["availability-rto"](_availability([]), NOW) == (True, None)


def test_known_bad_an_incident_longer_than_the_rto_fails():
    doc = _availability([{"service": "site", "start": "2026-11-01T00:00:00Z", "end": "2026-11-23T00:00:00Z"}])
    ok, why = _ksi_methods.CHECKS["availability-rto"](doc, NOW)
    assert not ok and "504 hours" in why


def test_known_bad_an_ongoing_incident_is_measured_to_now():
    doc = _availability([{"service": "site", "start": "2026-11-05T00:00:00Z", "end": None}])
    assert _ksi_methods.CHECKS["availability-rto"](doc, NOW)[0] is False


def test_known_bad_an_unreadable_incident_fails():
    doc = _availability([{"service": "site", "start": "yesterday-ish"}])
    assert _ksi_methods.CHECKS["availability-rto"](doc, NOW)[0] is False


def test_the_probe_feed_records_incident_start_and_end():
    """The field the method reads exists in what the probe publishes."""
    probe = _load("probe_t", "availability-probe.py")
    key = probe.TARGETS[0][0]
    samples = [{"t": f"2026-11-01T00:{m:02d}:00Z", "probed": [key], "fail": {key: "HTTP 503"} if 1 <= m <= 4 else {}}
               for m in range(6)]
    incs, _ = probe.incidents(samples)
    assert incs and {"start", "end"} <= set(incs[0])
