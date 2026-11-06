"""Append-only published histories are never silently restarted.

The deploy carries over the previously published access summary, certification
report index and package submission log. A fetch that fails for any reason but
"never published" (404) must fail the deploy rather than start the history
again from nothing (scripts/fetch-published-history.py). Known-bad responses
are under tests/fixtures/history-fetch/."""
import importlib.util
import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "history-fetch"
WORKFLOW = REPO / ".github" / "workflows" / "deploy-with-opa.yml"
HISTORIES = ("access-summary.json", "fedramp-certification-reports.json", "package-submission-log.json",
             # the certification package carries its version, KSI metric and
             # training history forward from the previous published copy
             "ongoing-certification-report.json", "security-decision-record.json",
             "certification-package-overview.json")

spec = importlib.util.spec_from_file_location("fetch_history", REPO / "scripts" / "fetch-published-history.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def _from(fixture):
    resp = json.loads((FIX / fixture).read_text())
    return lambda _url: (resp["status"], resp["body"].encode())


@pytest.mark.parametrize("fixture,needle", [("http-500.json", "returned HTTP 500"),
                                            ("truncated-200.json", "truncated or not JSON")])
def test_known_bad_a_failed_or_truncated_fetch_fails_and_keeps_nothing(tmp_path, fixture, needle):
    out = tmp_path / "previous.json"
    with pytest.raises(SystemExit, match=needle):
        mod.fetch("package-submission-log.json", out, get=_from(fixture))
    assert not out.exists()


def test_never_published_starts_the_history(tmp_path):
    out = tmp_path / "previous.json"
    out.write_text("{}")
    assert mod.fetch("access-summary.json", out, get=lambda _u: (404, b"")) is False
    assert not out.exists()


def test_a_published_copy_is_kept_byte_for_byte(tmp_path):
    body = b'{"schema": "package-submission-log/1", "entries": []}\n'
    out = tmp_path / "previous.json"
    assert mod.fetch("package-submission-log.json", out, get=lambda _u: (200, body)) is True
    assert out.read_bytes() == body


@pytest.mark.parametrize("status", [301, 403, 502, 503])
def test_any_other_status_fails(tmp_path, status):
    with pytest.raises(SystemExit, match=f"HTTP {status}"):
        mod.fetch("access-summary.json", tmp_path / "p.json", get=lambda _u: (status, b""))


def test_a_network_error_fails(tmp_path):
    def boom(_url):
        raise TimeoutError("timed out")
    with pytest.raises(SystemExit, match="cannot fetch"):
        mod.fetch("access-summary.json", tmp_path / "p.json", get=boom)


@pytest.mark.parametrize("name,site", [("../x.json", mod.SITE), ("a.txt", mod.SITE),
                                       ("a.json", "http://samaydlette.com"), ("a.json", "https://example.org")])
def test_only_json_from_the_providers_site_is_fetched(tmp_path, name, site):
    with pytest.raises(SystemExit):
        mod.fetch(name, tmp_path / "p.json", site=site, get=lambda _u: (200, b"{}"))


def test_the_deploy_fetches_every_history_fail_closed():
    wf = WORKFLOW.read_text()
    for name in HISTORIES:
        assert re.search(rf"fetch-published-history\.py {re.escape(name)}\b", wf), name
        # no silent fallback to an empty history for this file
        assert not re.search(rf"curl[^\n]*{re.escape(name)}", wf), name
