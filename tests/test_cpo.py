"""The Certification Package Overview in FedRAMP's schema (scripts/build-cpo.py).

CPO-CSO-MTD (metadata) and CDS-CSO-SVC (the service list) cite these tests.
"""
import copy
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("build_cpo", REPO / "scripts" / "build-cpo.py")
cpo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cpo)
fs = cpo.fs

OFFERING = json.loads((REPO / "data" / "cds" / "offering.json").read_text())
PROFILE = json.loads((REPO / "data" / "system-profile.json").read_text())
SIGNAL = {"signal_id": "sig-1", "components": [{"id": "a"}, {"id": "b"}]}
NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
RUN = "https://github.com/o/r/actions/runs/1"


def build(off=OFFERING, prof=PROFILE, commit="abc123", run_url=RUN):
    return cpo.build(off, prof, SIGNAL, NOW, commit, run_url)


def test_the_cpo_built_from_the_offering_validates_against_fedramps_schema():
    assert fs.validate(build(), "cpo") == []


def test_a_cpo_that_fails_the_schema_is_never_written(tmp_path):
    doc = build()
    del doc["contactInformation"][1]  # no Sales contact
    out = tmp_path / "cpo.json"
    with pytest.raises(SystemExit):
        fs.write_validated(doc, "cpo", out)
    assert not out.exists()


def test_the_metadata_names_the_accountable_official_version_time_and_source():
    md = build()["metadata"]
    assert md["accountable_official"] == {k: OFFERING["accountable_official"][k] for k in ("name", "title", "contact")}
    assert md["version"] == "abc123"
    assert md["last_updated"] == NOW.isoformat()
    assert "abc123" in md["source_of_update"] and RUN in md["source_of_update"]
    assert "local build" in build(run_url=None)["metadata"]["source_of_update"]


@pytest.mark.parametrize("field", ["name", "title", "contact"])
def test_an_accountable_official_missing_a_field_fails_the_build(field):
    off = copy.deepcopy(OFFERING)
    off["accountable_official"][field] = ""
    with pytest.raises(SystemExit, match="CPO-CSO-MTD"):
        build(off)


def test_a_package_without_a_commit_fails_the_build():
    with pytest.raises(SystemExit, match="CPO-CSO-MTD"):
        build(commit=None)


def test_every_service_is_listed_with_its_security_category_and_scope():
    got = build()["certifiedServices"]
    assert [s["serviceName"] for s in got] == [s["name"] for s in OFFERING["services"]]
    for s, src in zip(got, OFFERING["services"], strict=True):
        assert s["securityCategory"] == src["security_category"]
        assert s["inMinimumAssessmentScope"] is src["in_mas_scope"]


def test_a_service_whose_category_does_not_name_the_system_level_fails():
    off = copy.deepcopy(OFFERING)
    off["services"][0]["security_category"] = "FIPS-199 Low"
    with pytest.raises(SystemExit, match="impact level"):
        build(off)


def test_a_service_without_a_scope_answer_fails():
    off = copy.deepcopy(OFFERING)
    del off["services"][0]["in_mas_scope"]
    with pytest.raises(SystemExit, match="in_mas_scope"):
        build(off)


def test_an_offering_with_no_services_fails():
    off = copy.deepcopy(OFFERING)
    off["services"] = []
    with pytest.raises(SystemExit, match="CDS-CSO-SVC"):
        build(off)


def test_the_fields_the_gates_read_stay_at_the_top_level():
    doc = build()
    assert doc["ksi_signal_id"] == "sig-1"
    assert doc["impact_level"] == PROFILE["impact_level"]
    assert doc["metadata"]["last_updated"]


def test_the_fedramp_id_says_it_is_not_one_and_no_uei_is_invented():
    si = build()["serviceIdentification"]
    assert si["fedRampPackageId"].endswith("PROOF-OF-CONCEPT-NOT-A-REAL-FEDRAMP-ID")
    assert "ueiNumber" not in si


def test_no_contact_puts_anything_in_the_email_field():
    assert all("contactEmail" not in c for c in build()["contactInformation"])


def test_the_markdown_carries_the_metadata_and_every_service():
    md = cpo.render_markdown(build())
    assert "abc123" in md and OFFERING["accountable_official"]["title"] in md
    assert all(s["name"] in md for s in OFFERING["services"])


def test_every_package_file_is_held_to_class_cs_two_week_maintenance_window():
    """CPO-CSX-CPM: Class C keeps the package current at least every 2 weeks. Each
    package file's governed window is at most 14 days, so the watchdog's
    stale-artifact alarm pages when the package lapses."""
    cfg = json.loads((REPO / "infrastructure" / "schemas" / "freshness-config.json").read_text())
    windows = {a["path"]: a["max_age_hours"] for a in cfg["artifacts"]}
    package = [".well-known/" + f for f, _t, _d in cpo.PACKAGE] + [".well-known/certification-package-overview.json"]
    assert all(windows[p] <= 14 * 24 for p in package), {p: windows[p] for p in package}
