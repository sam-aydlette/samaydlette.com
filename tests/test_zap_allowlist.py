"""Outside-in results record allowlist status and are attributed by host (REQ-IRV-11).

Each ZAP finding names the URLs it was observed at (not just the scan target),
and records whether its probe was allowlisted, from the governed allowlist
security/zap/allowlist.json. A probe that reached a location without an
allowlist entry is not allowlisted.
"""
import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "zap"
spec = importlib.util.spec_from_file_location("vdr", REPO / "scripts" / "build-vdr-report.py")
vdr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vdr)


def _by_ref(allowlist):
    return {f["tool_id"]: f for f in vdr.ingest_zap(str(FIX / "report.json"), allowlist)}


def test_resource_is_the_observed_url_not_the_site():
    f = _by_ref(vdr.load_zap_allowlist(FIX / "allowlist-empty.json"))["10038"]
    assert f["resource"] == "https://samaydlette.com/research/"
    assert [loc["host"] for loc in f["locations"]] == ["samaydlette.com", "samaydlette.com"]


def test_empty_allowlist_means_not_allowlisted():
    for f in _by_ref(vdr.load_zap_allowlist(FIX / "allowlist-empty.json")).values():
        assert f["allowlisted"] is False
        assert all(loc["allowlisted"] is False for loc in f["locations"])


def test_allowlisted_only_when_every_location_was():
    al = vdr.load_zap_allowlist(FIX / "allowlist-research.json")
    f = _by_ref(al)
    assert f["10038"]["allowlisted"] is False  # /research/ allowlisted, / not
    assert [loc["allowlisted"] for loc in f["10038"]["locations"]] == [True, False]  # report order
    assert f["10021"]["allowlisted"] is True


def test_alert_without_instances_falls_back_to_the_site_and_says_so():
    f = _by_ref(vdr.load_zap_allowlist(FIX / "allowlist-empty.json"))["90004"]
    assert f["resource"] == "https://samaydlette.com"
    assert f["locations"] == []
    assert f["allowlisted"] is False


def test_tracking_ids_are_unchanged():
    assert {f["tracking_id"] for f in _by_ref({"entries": []}).values()} == {"zap-10038", "zap-10021", "zap-90004"}


def test_malformed_allowlist_fails_closed():
    with pytest.raises(SystemExit):
        vdr.load_zap_allowlist(FIX / "allowlist-malformed.json")


def test_allowlist_entry_without_a_decision_fails_closed(tmp_path):
    p = tmp_path / "a.json"
    p.write_text(json.dumps({"entries": [{"url_prefix": "https://samaydlette.com/"}]}))
    with pytest.raises(SystemExit):
        vdr.load_zap_allowlist(p)


def test_committed_allowlist_loads():
    vdr.load_zap_allowlist(REPO / "security" / "zap" / "allowlist.json")


def test_allowlist_prefix_does_not_match_a_lookalike_host():
    al = {"entries": [{"url_prefix": "https://samaydlette.com"}]}
    assert vdr._zap_location("https://samaydlette.com.evil.net/x", al)["allowlisted"] is False
    assert vdr._zap_location("https://samaydlette.com/x", al)["allowlisted"] is True


def test_allowlist_status_is_published_in_the_report():
    """The published VDR finding, not only the ingested one, carries the
    observed locations and the allowlist status (REQ-IRV-11)."""
    al = vdr.load_zap_allowlist(FIX / "allowlist-research.json")
    report, _ = vdr.build_report(vdr.ingest_zap(str(FIX / "report.json"), al), [], set(), {})
    pub = {f["tool_id"]: f for f in report["findings"]}
    ing = _by_ref(al)
    for ref, f in ing.items():
        assert pub[ref]["allowlisted"] == f["allowlisted"], ref
        assert pub[ref]["locations"] == f["locations"], ref
