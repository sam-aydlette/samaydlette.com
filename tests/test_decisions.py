"""The decision register (data/decisions.json) replaces the POA&M (CR26).

Every human decision about a finding lives in one register, read by the VDR
builder, the vulnerability gate, reconciliation and the trust center through
scripts/_decisions.py. These tests pin:

- the loader fails closed, and every known-bad register under
  tests/fixtures/decisions/ stops each consumer for its own reason;
- the committed register matches its schema;
- the migration carried every POA&M item over with its disposition, dates and
  check IDs (against frozen copies of the retired sources);
- the POA&M is gone: no builder, no publish step, no freshness window, and the
  deploy deletes the published copies and fails if any is still served.
"""
import json
import os
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "decisions"
MIG = REPO / "tests" / "fixtures" / "migration"
REGISTER = REPO / "data" / "decisions.json"
SCHEMA = REPO / "infrastructure" / "schemas" / "decisions.schema.json"

sys.path.insert(0, str(REPO / "scripts"))
import _decisions  # noqa: E402

KNOWN_BAD = [
    ("undecided.json", "an in-force decision needs decided_by"),
    ("duplicate-claim.json", "'CKV_AWS_68' is claimed by both DEC-001 and DEC-002"),
    ("closed-not-remediated.json", "a closed record's disposition must be one of"),
    ("unknown-field.json", "unknown field(s) ['reviewby']"),
    ("planned-reduction-malformed.json", "planned_reduction must be {date: YYYY-MM-DD, target_pain: N0-N5}"),
    ("planned-reduction-closed.json", "only an in-force record plans a reduction"),
    ("automatable-no-evidence.json", "'no' needs its evidence"),
    ("unconfirmed.json", "an in-force decision needs confirmed_on"),
    ("marking-in-text.json", "justification carries a drafting or confirmation note"),
    ("superseded-without-replaced-by.json", "a superseded record needs closed_on and replaced_by"),
    ("confirmed-before-decided.json", "confirmed_on 2025-12-31 is before decided_on 2026-01-01"),
]


def _env():
    return {k: v for k, v in os.environ.items() if k not in ("GATE_EVENTS_FILE", "GATE_MODES_FILE")}


# --- the loader --------------------------------------------------------------------

def test_the_committed_register_loads_and_matches_its_schema():
    reg = _decisions.load()
    # The migration range (DEC-001..099): 37 carried over from the POA&M, 2 new.
    # Later records are added in the blocks below.
    assert len([r for r in reg["decisions"] if _num(r) < 100]) == 39
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(json.loads(REGISTER.read_text()), json.loads(SCHEMA.read_text()))


@pytest.mark.parametrize("fixture,reason", KNOWN_BAD)
def test_each_known_bad_register_fails_closed_for_its_reason(fixture, reason):
    with pytest.raises(SystemExit, match="fail-closed") as exc:
        _decisions.load(FIX / fixture)
    assert reason in str(exc.value)


# The JSON schema cannot express a cross-record claim, a text screen or a date order.
LOADER_ONLY = {"duplicate-claim.json", "marking-in-text.json", "confirmed-before-decided.json"}


@pytest.mark.parametrize("fixture", [f for f, _ in KNOWN_BAD if f not in LOADER_ONLY])
def test_the_schema_refuses_the_same_registers(fixture):
    # Uniqueness across records is the loader's alone; a schema cannot say it.
    jsonschema = pytest.importorskip("jsonschema")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(json.loads((FIX / fixture).read_text()), json.loads(SCHEMA.read_text()))


def test_a_missing_or_empty_register_fails_closed(tmp_path):
    with pytest.raises(SystemExit, match="not found"):
        _decisions.load(tmp_path / "absent.json")
    p = tmp_path / "empty.json"
    p.write_text(json.dumps({"schema": "decisions/1", "decisions": []}))
    with pytest.raises(SystemExit, match="non-empty"):
        _decisions.load(p)


def test_a_lapsed_record_is_reported_due_and_still_resolves_by_id():
    reg = _decisions.load(REPO / "tests" / "fixtures" / "dispositions" / "register-lapsed.json")
    assert [r["id"] for r in _decisions.review_due(reg, today=date(2026, 11, 4))] == ["DEC-003"]
    assert _decisions.review_due(reg, today=date(2025, 6, 1)) == []


def test_a_former_poam_id_resolves_to_its_record():
    by_id = _decisions.by_any_id(_decisions.load())
    assert by_id["POAM-007"]["id"] == "DEC-007" and by_id["DEC-007"] is by_id["POAM-007"]


@pytest.mark.parametrize("fixture,reason", KNOWN_BAD)
def test_every_consumer_stops_on_a_known_bad_register(tmp_path, fixture, reason):
    bad = str(FIX / fixture)
    runs = {
        "vdr builder": [sys.executable, str(REPO / "scripts" / "build-vdr-report.py"), "--decisions", bad,
                        "--output", str(tmp_path / "vdr.json"), "--md-output", ""],
        "vulnerability gate": [sys.executable, str(REPO / "scripts" / "vuln-gate.py"), "--findings",
                               str(_findings(tmp_path)), "--register", bad],
        "reconciliation": [sys.executable, str(REPO / "scripts" / "reconcile.py"), "--artifacts-dir",
                           str(REPO / "tests" / "fixtures" / "clean"), "--decisions", bad],
    }
    for name, cmd in runs.items():
        r = subprocess.run(cmd, cwd=tmp_path, capture_output=True, text=True, env=_env())
        assert r.returncode != 0, name
        assert reason in r.stderr, f"{name}: {r.stderr[-400:]}"
    assert not (tmp_path / "vdr.json").exists()


def test_the_trust_center_and_ocr_read_the_register_through_the_same_loader():
    # Both read their other inputs first, so they are not driven from a bad
    # register alone above; they call the loader the other consumers do.
    for script in ("build-trust-center.py", "build-ocr.py"):
        assert "_decisions.load(" in (REPO / "scripts" / script).read_text(), script


def _findings(tmp_path):
    p = tmp_path / "findings.json"
    p.write_text("[]")
    return p


# --- the migration -----------------------------------------------------------------

POAM_TO_DISPOSITION = {"false-positive": "false-positive", "configuration": "risk-accepted",
                       "operational-requirement": "operational-requirement", "closed": "remediated"}


def test_every_poam_item_landed_in_the_register_with_its_decision():
    items = json.loads((MIG / "poam-items-2026-11-04.json").read_text())["items"]
    by_former = {r["former_id"]: r for r in _decisions.load()["decisions"] if r.get("former_id")}
    assert set(by_former) == {i["id"] for i in items}
    for i in items:
        r = by_former[i["id"]]
        assert r["id"] == "DEC-" + i["id"].split("-")[1], i["id"]
        assert r["disposition"] == POAM_TO_DISPOSITION[i["category"]], i["id"]
        assert r["status"] == ("closed" if i["category"] == "closed" else "in-force"), i["id"]
        assert r["title"] == i["title"], i["id"]
        if (i["id"], "justification") not in AMENDED_SINCE_MIGRATION:
            assert r["justification"] == _published_text(i["description"]), i["id"]
        for k in ("decided_by", "decided_on", "review_by", "original_detection_date"):
            if (i["id"], k) not in AMENDED_SINCE_MIGRATION:
                assert r.get(k) == i.get(k), (i["id"], k)
        if (i["id"], "resources") not in AMENDED_SINCE_MIGRATION:
            assert r["applies_to"]["resources"] == i.get("asset_identifiers", []), i["id"]


# Fields corrected after the migration, each for a stated reason; everything
# else still matches the POA&M item it came from.
AMENDED_SINCE_MIGRATION = {
    # Detection dates the POA&M never recorded: the inline Checkov skips for
    # CKV_AWS_68, CKV_AWS_86/310 and CKV_AWS_117 were added on 2025-06-14
    # (commit f453e9d, "fixing Checkov findings"), so each was detected by then.
    ("POAM-007", "original_detection_date"), ("POAM-009", "original_detection_date"),
    ("POAM-010", "original_detection_date"),
    # DEC-010 named "aws-lambda::compliance-monitor", which no inventory
    # component carries; the CKV_AWS_117 skip is global, so it covers every Lambda.
    ("POAM-010", "resources"),
    # Wording corrected 2026-11-06, decisions unchanged: DEC-007 said the site had
    # no authentication endpoints (the Silk Reeling API behind the distribution
    # has a JWT authorizer), and DEC-009 pointed to the retired POAM-016.
    ("POAM-007", "justification"), ("POAM-009", "justification"),
    # DEC-026 cited the retired POAM-025 for the operator's MFA; it now cites DEC-025.
    ("POAM-026", "justification"),
}


def test_the_post_migration_amendments_are_the_stated_ones():
    recs = _decisions.records(_decisions.load())
    assert all(recs[d]["original_detection_date"] == "2025-06-14" for d in ("DEC-007", "DEC-009", "DEC-010"))
    assert recs["DEC-010"]["applies_to"]["resources"] == [
        "aws::function::opa_compliance", "aws::function::evidence_watchdog", "aws::function::silk_reeling"]
    items = {i["id"]: i for i in json.loads((MIG / "poam-items-2026-11-04.json").read_text())["items"]}
    for dec, poam in (("DEC-007", "POAM-007"), ("DEC-009", "POAM-009")):
        old, new = items[poam]["description"], recs[dec]["justification"]
        assert new.startswith(old.split(".")[0] + ".") and "Text corrected 2026-11-06" in new, dec
    assert "no auth endpoints" not in recs["DEC-007"]["justification"]
    assert "POAM-016" not in recs["DEC-009"]["justification"]


def test_the_check_maps_are_the_ones_the_poam_held():
    frozen = json.loads((MIG / "check-maps-2026-11-04.json").read_text())
    accepted, false_pos = _decisions.check_maps(_decisions.load())
    rename = lambda m: {c: "DEC-" + p.split("-")[1] for c, p in m.items()}  # noqa: E731
    assert accepted == rename(frozen["risk_accepted"])
    assert false_pos == rename(frozen["false_positive"])


# Text removed from the POA&M wording when it moved to the register, because the
# register is published (trust-center.json): IAM user names stay out of
# published output. The parity test applies exactly these and nothing else.
PUBLICATION_REDACTIONS = {" (saydlette-dev)": ""}


def _published_text(text):
    for old, new in PUBLICATION_REDACTIONS.items():
        text = text.replace(old, new)
    return text


def test_no_iam_user_name_is_in_published_decision_text():
    users = {res.split("::", 1)[1] for r in _decisions.load()["decisions"]
             for res in r["applies_to"]["resources"] if res.startswith("aws-iam-user::")}
    assert users
    for r in _decisions.load()["decisions"]:
        for field in ("title", "justification", "remediation_plan"):
            assert not any(u in (r.get(field) or "") for u in users), (r["id"], field)


def _num(r):
    return int(r["id"][4:])


# Blocks for records added after the migration, one per piece of work, so
# parallel branches never collide (2026-11-05). DEC-041..099 stay unused: the
# migration range is closed.
DEC_BLOCKS = {"certification reports": (100, 129), "notifications": (130, 149),
              "trust center, scope and assessor": (150, 179), "detection and evaluation": (180, 209)}


def test_records_after_the_migration_sit_in_an_allocated_block():
    for r in _decisions.load()["decisions"]:
        n = _num(r)
        assert n <= 40 or any(lo <= n <= hi for lo, hi in DEC_BLOCKS.values()), r["id"]


def test_the_only_new_records_are_the_two_dast_false_positives():
    new = [r for r in _decisions.load()["decisions"] if not r.get("former_id") and _num(r) < 100]
    assert [(r["id"], r["disposition"], r["applies_to"]["vuln_ids"]) for r in new] == [
        ("DEC-039", "false-positive", ["zap-10099"]), ("DEC-040", "false-positive", ["zap-10036-2"])]
    assert all(r["decided_by"] == "Sam Aydlette" for r in new)


# --- the POA&M is retired ----------------------------------------------------------

def test_the_poam_is_neither_built_nor_published_nor_watched():
    assert not (REPO / "scripts" / "build-oscal-poam.py").exists()
    assert not (REPO / "data" / "poam-items.json").exists() and not (REPO / "docs" / "poam.md").exists()
    assert not (REPO / "data" / "vuln-dispositions.json").exists()
    for wf in ("deploy-with-opa.yml", "evidence-nightly.yml"):
        text = (REPO / ".github" / "workflows" / wf).read_text()
        assert "build-oscal-poam" not in text and "poam-items" not in text, wf
    fresh = json.loads((REPO / "infrastructure" / "schemas" / "freshness-config.json").read_text())
    assert not [a for a in fresh["artifacts"] if "oscal-poam" in a["path"]]
    assert "oscal-poam" not in (REPO / "scripts" / "verify-published.sh").read_text()


def test_external_verification_reads_the_register_at_the_published_commit():
    # Not the verifier's working copy: the register the published set was built with.
    text = (REPO / "scripts" / "verify-published.sh").read_text()
    assert 'git -C "$SCRIPTS/.." show "$commit:data/decisions.json"' in text
    assert "'^[0-9a-f]{40}$'" in text and '--decisions "$work/decisions.json"' in text


def test_the_deploy_deletes_the_published_poam_and_fails_if_it_is_still_served():
    import yaml
    jobs = yaml.safe_load((REPO / ".github" / "workflows" / "deploy-with-opa.yml").read_text())["jobs"]
    steps = [s for job in jobs.values() for s in job.get("steps", [])]
    retired = "oscal-poam.json oscal-poam.bundle oscal-poam.json.intoto.jsonl"
    publish = next(s for s in steps if 'aws s3 rm "s3://$BUCKET_NAME/.well-known/$retired"' in s.get("run", ""))
    check = next(s for s in steps if "retired artifact still published" in s.get("run", ""))
    assert retired in publish["run"] and retired in check["run"]
    # Only a 404 counts as gone; any other error fails the round-trip.
    assert "'(404)'" in check["run"] and "could not confirm" in check["run"]
    assert steps.index(publish) < steps.index(check)


def test_every_in_force_record_is_confirmed_and_carries_no_drafting_note():
    """One marking format (source.drafted_by plus confirmed_on): a record the
    operator has not confirmed cannot be in force."""
    for r in _decisions.in_force(_decisions.load()):
        assert r.get("confirmed_on") and r["confirmed_on"] >= r["decided_on"], r["id"]
        assert not _decisions.MARKING_RE.search(r["title"] + " " + r["justification"]), r["id"]
    recs = _decisions.records(_decisions.load())
    assert all(recs[f"DEC-{n:03d}"]["confirmed_on"] == recs[f"DEC-{n:03d}"]["decided_on"]
               for n in range(3, 41) if recs.get(f"DEC-{n:03d}", {}).get("status") == "in-force")


def test_the_closed_procedural_records_are_superseded_not_remediated():
    recs = _decisions.records(_decisions.load())
    for rid in ("DEC-102", "DEC-103", "DEC-104", "DEC-105", "DEC-106", "DEC-190", "DEC-191", "DEC-192"):
        assert recs[rid]["status"] == "closed" and recs[rid]["disposition"] == "superseded", rid
        assert recs[rid]["replaced_by"].strip(), rid
    assert recs["DEC-194"]["status"] == "in-force" and recs["DEC-194"]["confirmed_on"] == "2026-11-06"
