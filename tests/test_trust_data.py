"""Trust-center data: complete human-readable views kept consistent with their
JSON by automation (CDS-TRC-HMR, CDS-CSO-CBF), and the signed manifest of all
certification data (CDS-TRC-PAC, CDS-CSO-UTC)."""
import csv
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "human-views"
WF = REPO / ".github" / "workflows" / "deploy-with-opa.yml"
FRESH = REPO / "infrastructure" / "schemas" / "freshness-config.json"


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


hv = _load("human_views", "scripts/build-human-views.py")
tm = _load("trust_manifest", "scripts/build-trust-manifest.py")
sys.path.insert(0, str(REPO / "scripts"))
import _freshness  # noqa: E402


# --- views ---------------------------------------------------------------------------------

def test_a_view_reproduces_its_json_exactly(tmp_path):
    src = tmp_path / "original.json"
    src.write_text((FIX / "original.json").read_text())
    view = hv.build(src)
    assert view.name == "original.view.md"
    assert hv.parse(view.read_text()) == json.loads(src.read_text())
    assert '"A\\|B"' in view.read_text()  # a pipe in a value cannot break the table


def test_known_bad_a_view_that_differs_from_its_json_fails(tmp_path):
    src = tmp_path / "original.json"
    src.write_text((FIX / "original.json").read_text())
    with pytest.raises(SystemExit, match="does not match"):
        hv.check(src, FIX / "original.view.tampered.md")


def test_a_json_the_view_cannot_represent_fails_closed(tmp_path):
    src = tmp_path / "odd.json"
    src.write_text(json.dumps({"0": "an object whose keys look like list positions"}))
    with pytest.raises(SystemExit, match="does not reproduce"):
        hv.build(src)
    assert not (tmp_path / "odd.view.md").exists()


def test_csv_views_round_trip(tmp_path):
    src = tmp_path / "iiw.csv"
    with src.open("w", newline="") as f:
        csv.writer(f).writerows([["id", "name"], ["1", "a, with comma"], ["2", 'quote "x"']])
    view = hv.build(src)
    assert hv.parse(view.read_text()) == [["id", "name"], ["1", "a, with comma"], ["2", 'quote "x"']]


def test_views_cover_every_deploy_published_json_in_the_governed_list(tmp_path):
    names = [a["path"].rsplit("/", 1)[1] for a in _freshness.load_freshness_config(FRESH)["artifacts"]]
    for n in names:
        (tmp_path / n).write_text("{}" if n.endswith(".json") else "a,b\n")
    got = {p.name for p in hv.sources(FRESH, tmp_path)}
    want = {n for n in names if n.endswith((".json", ".csv"))} - set(hv.NOT_DEPLOY_PUBLISHED)
    assert got == want and "ksi-signal.json" in got and "iiw.csv" in got


def test_main_lists_the_views_it_wrote(tmp_path):
    src = tmp_path / "original.json"
    src.write_text((FIX / "original.json").read_text())
    lst = tmp_path / "published-docs.txt"
    assert hv.main([str(src), "--list", str(lst)]) == 0
    assert lst.read_text() == "original.view.md\n"


# --- manifest ------------------------------------------------------------------------------

def _manifest(tmp_path, files=("ksi-signal.json", "ksi-signal.md", "ksi-signal.view.md")):
    for n in files:
        (tmp_path / n).write_text('{"$schema": "https://fedramp.gov/schemas/x.json"}' if n.endswith(".json") else "x")
    index = {"entries": [{"name": "AC", "kind": "policy", "url": "https://samaydlette.com/.well-known/policies/ac.md",
                          "version": "git:abc", "last_updated": "2026-11-05"}]}
    return tm.build(_freshness.load_freshness_config(FRESH), tmp_path, index, datetime(2026, 11, 5, tzinfo=timezone.utc))


def test_the_manifest_lists_every_governed_artifact_with_its_signature(tmp_path):
    m = _manifest(tmp_path)
    fresh = _freshness.load_freshness_config(FRESH)["artifacts"]
    assert [a["name"] for a in m["artifacts"]] == [a["path"].rsplit("/", 1)[1] for a in fresh]
    for a, f in zip(m["artifacts"], fresh, strict=True):
        assert a["url"] == "https://samaydlette.com/" + f["path"]
        assert ("signature" in a) == ("signature" in f)
    sim = next(a for a in m["artifacts"] if a["name"] == "simulated-assessment.json")
    assert sim["signed_by"] == "assessor"
    assert m["policies_and_procedures"][0]["url"].endswith("/ac.md")
    assert m["access"] and m["signers"]["deploy"].endswith("deploy-with-opa.yml@refs/heads/main")


def test_the_manifest_names_only_human_views_that_exist(tmp_path):
    m = _manifest(tmp_path)
    ksi = next(a for a in m["artifacts"] if a["name"] == "ksi-signal.json")
    assert ksi["human_readable"] == ["https://samaydlette.com/.well-known/ksi-signal.md",
                                     "https://samaydlette.com/.well-known/ksi-signal.view.md"]
    assert ksi["schema"].endswith("ksi-signal.schema.json")
    # Not built here: its view is the one every publisher of it puts
    # (scripts/_signers.py, held to the publish steps by
    # tests/test_human_views_published.py); no curated summary is claimed.
    sdr = next(a for a in m["artifacts"] if a["name"] == "security-decision-record.json")
    assert sdr["human_readable"] == ["https://samaydlette.com/.well-known/security-decision-record.view.md"]
    rt = next(a for a in m["artifacts"] if a["name"] == "ksi-signal-runtime.json")
    assert rt["human_readable"] == [rt["human_readable"][0]]
    assert rt["human_readable"][0].startswith("https://samaydlette.com/trust/")


def test_known_bad_a_json_built_without_its_view_fails_the_manifest(tmp_path):
    with pytest.raises(SystemExit, match="without its view"):
        _manifest(tmp_path, files=("ksi-signal.json", "ksi-signal.md"))


def test_the_manifest_points_at_the_independent_availability_feed(tmp_path):
    ext = _manifest(tmp_path)["external"][0]
    assert ext["url"].startswith("https://raw.githubusercontent.com/") and "availability-status" in ext["url"]


# --- wiring --------------------------------------------------------------------------------

def test_views_and_manifest_are_built_before_signing_and_the_gate():
    wf = WF.read_text()
    deploy = wf.split("\n  deploy:\n", 1)[1]
    views = deploy.index("- name: Build the human-readable views and the trust manifest (format parity)")
    assert deploy.index("- name: Build the trust center") < views
    assert views < deploy.index("- name: Sign trust-center artifacts") < deploy.index(
        "- name: Publication redaction gate")
    step = deploy[views:].split("\n    - name:", 1)[0]
    assert "build-human-views.py --freshness schemas/freshness-config.json" in step
    assert "build-trust-manifest.py" in step


def test_the_nightly_rebuilds_the_views_of_what_it_republishes():
    wf = (REPO / ".github" / "workflows" / "evidence-nightly.yml").read_text()
    step = wf.split("- name: Rebuild the human-readable views (format parity)", 1)[1].split("\n    - name:", 1)[0]
    publish = wf.split("- name: Publish VDR + trend to /.well-known/", 1)[1].split("\n    - name:", 1)[0]
    for a in ("vdr-report", "vdr-trend", "vdr-detail-report", "vdr-accepted-vulnerabilities", "vdr-history"):
        assert f"{a}.json" in step
        assert a in publish.split('put "$a.view.md"')[0].rsplit("for a in", 1)[1]


# --- the trust page's static section (works with JavaScript off) -------------------------

def test_the_trust_page_indexes_the_data_and_says_how_to_get_access():
    page = (REPO / "website" / "trust" / "index.html").read_text()
    section = page.split('<section id="data"', 1)[1].split("</section>", 1)[0]
    for href in ('/.well-known/trust-manifest.json', '/.well-known/trust-manifest.md',
                 '/.well-known/assessor-guide.md', '/.well-known/simulated-assessment.json',
                 '/.well-known/policies/agency-access.md', '/.well-known/policies/information-sharing.md',
                 '/.well-known/access-summary.json', '/.well-known/agency-access-exercise.md'):
        assert f'href="{href}"' in section or href in section, href
    # no engagement (DEC-194): no intake form, and the statement is on the page
    assert "issues/new" not in page and not (REPO / ".github" / "ISSUE_TEMPLATE" / "agency-access.yml").exists()
    assert "No engagement (DEC-194)" in section
    # the simulated assessor never passes for a real one
    assert "(simulated)" in section and "not a FedRAMP assessment" in section
    # the privacy notice states what is not logged and how long raw records live
    for words in ("IP address", "user agent", "90 days", "13 months"):
        assert words in section, words
