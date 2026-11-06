"""The governed table of non-OPA methods (infrastructure/schemas/ksi-methods.json)
and their verifiers: a method counts for a KSI only when its record is signed
by its publisher, inside its window and passing its check."""

import copy
import json
import sys
from datetime import datetime
from pathlib import Path

import jsonschema
import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _freshness  # noqa: E402
import _ksi_methods as km  # noqa: E402

FIX = REPO / "tests" / "fixtures" / "ksi-methods"
BAD = json.loads((FIX / "known-bad.json").read_text())["cases"]
RECORDS = json.loads((FIX / "records.json").read_text())
NOW = datetime.fromisoformat(RECORDS["now"])
CFG = _freshness.load_freshness_config()
PUBLISHED = {a["path"] for a in CFG["artifacts"]}
KNOWN = km._catalog_ids()


def _committed():
    return json.loads(km.DEFAULT_PATH.read_text())


def test_the_committed_table_is_valid_and_matches_its_schema():
    doc = km.load()
    schema = json.loads((REPO / "infrastructure" / "schemas" / "ksi-methods.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(_committed(), schema)
    assert len(doc["methods"]) == len(km.by_key(doc))


def test_the_table_lists_only_the_reviewed_mechanisms():
    """The mechanisms the strict-count review judged genuine, plus the drills
    the operator chose on 2026-11-06 (night), and no other (no mechanism is
    added to satisfy a gate)."""
    assert set(km.by_key(km.load())) == {
        "audit-log-review", "recovery-rebuild", "recovery-backup-read", "grype", "dependabot", "codeql", "zap",
        "checkov-tfsec", "security-settings", "runtime-divergence", "reconcile", "plan-gate", "conformance",
        "inbox-simulation", "training", "availability",
        # the drills plan (2026-11-06, night)
        "scn-evaluations", "security-review", "board-meeting", "cfo-review", "groundhog-day", "incident-lessons",
        "tabletop", "disclosure-drill", "security-txt", "phishing-drill",
        # the live drills (PR C3 of the same plan)
        "quarantine-drill", "chaos-gremlin", "availability-rto"}
    stand_in = {m["key"] for m in km.load()["methods"] if m["input"] == "stand-in"}
    assert stand_in == {"inbox-simulation", "training", "security-review", "board-meeting", "groundhog-day",
                        "incident-lessons", "tabletop", "disclosure-drill", "phishing-drill", "quarantine-drill"}
    assert all(m.get("stand_in_proof") for m in km.load()["methods"] if m["input"] == "stand-in")


def _mutate(case):
    doc = copy.deepcopy(_committed())
    if "duplicate" in case:
        doc["methods"].append(copy.deepcopy(km.by_key(doc)[case["duplicate"]]))
    else:
        m = km.by_key(doc)[case["method"]]
        m.update(case["set"])
    return doc


@pytest.mark.parametrize("case", BAD, ids=[c["case"] for c in BAD])
def test_known_bad_tables_fail(case):
    with pytest.raises(SystemExit) as exc:
        km.validate(_mutate(case), KNOWN, PUBLISHED)
    assert case["expect"] in str(exc.value)


def _write(tmp_path, doc):
    p = tmp_path / "rec.json"
    p.write_text(json.dumps(doc))
    b = tmp_path / "rec.bundle"
    b.write_text("{}")
    return p, b


def _verify(tmp_path, case, signed=True):
    m = km.by_key(km.load())[case["method"]]
    p, b = _write(tmp_path, case["doc"])
    return km.verify_published(m, p, b, NOW, CFG, lambda *_a: signed, ["publisher"])


@pytest.mark.parametrize("case", RECORDS["good"], ids=[c["case"] for c in RECORDS["good"]])
def test_a_signed_fresh_passing_record_counts(case, tmp_path):
    assert _verify(tmp_path, case) == (True, None)


@pytest.mark.parametrize("case", RECORDS["bad"], ids=[c["case"] for c in RECORDS["bad"]])
def test_known_bad_records_do_not_count(case, tmp_path):
    ok, why = _verify(tmp_path, case)
    assert not ok and case["expect"] in why, why


def test_known_bad_a_record_signed_by_the_wrong_publisher_does_not_count(tmp_path):
    ok, why = _verify(tmp_path, RECORDS["good"][0], signed=False)
    assert not ok and "does not verify against its publisher" in why


def test_known_bad_a_missing_record_does_not_count(tmp_path):
    m = km.by_key(km.load())["reconcile"]
    ok, why = km.verify_published(m, tmp_path / "nope.json", tmp_path / "nope.bundle", NOW, CFG,
                                  lambda *_a: True, ["publisher"])
    assert not ok and "not available to this build" in why


VDR = {"methodology": {"detection": {"feeds": [{"feed": "grype", "status": "ok"}, {"feed": "checkov", "status": "ok"},
                                               {"feed": "tfsec", "status": "failed"}]}}}


@pytest.mark.parametrize("key,usable,want", [
    ("grype", (True, None), (True, None)),
    ("checkov-tfsec", (True, None), (False, "the tfsec feed failed the detection gate")),
    ("dependabot", (True, None), (False, "the VDR's detection record lists no dependabot feed")),
    ("grype", (False, "the VDR report is not bound to this inventory's signal_id"),
     (False, "the VDR report is not bound to this inventory's signal_id")),
])
def test_a_detection_feed_counts_only_from_a_usable_vdr_with_every_feed_passing(key, usable, want):
    assert km.verify_vdr_feeds(km.by_key(km.load())[key], usable, VDR) == want
