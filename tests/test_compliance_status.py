"""The homepage compliance line must fail closed, not fail green.

index.html ships `// compliance evidence: live dashboard` — a link and no claim.
ComplianceStatus.js only ever ADDS facts to it, so an unreachable, stale or
malformed signal leaves an honest line rather than a wrong one. A compliance site
asserting a green state it did not verify is worse than one asserting nothing.

These execute the real module in node against fetch and DOM shims, so they exercise
the shipped code rather than a reimplementation of it, following the approach in
test_viewer_divergence.py.
"""

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
COMPONENT = REPO / "website" / "assets" / "js" / "components" / "ComplianceStatus.js"
INDEX = REPO / "website" / "index.html"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not available")


def run(signal, *, ok=True, throws=False, has_hook=True):
    """Return what the component wrote into the hook, or None if it stayed silent."""
    fetch = (
        "() => Promise.reject(new Error('offline'))" if throws
        else f"() => Promise.resolve({{ ok: {str(ok).lower()}, "
             f"json: () => Promise.resolve({json.dumps(signal)}) }})"
    )
    hook = (
        "({ set textContent(v) { written = v; } })" if has_hook else "null"
    )
    script = textwrap.dedent(f"""
        let written = null, fetched = false;
        global.document = {{ querySelector: () => {hook} }};
        global.fetch = (...a) => {{ fetched = true; return ({fetch})(...a); }};
        const {{ ComplianceStatus }} = await import({json.dumps(COMPONENT.as_uri())});
        const c = new ComplianceStatus();
        if (c.el) await c.load();
        console.log(JSON.stringify({{ written, fetched }}));
    """)
    out = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        capture_output=True, text=True, check=True,
    )
    return json.loads(out.stdout.strip().splitlines()[-1])


def sig(*, age_hours=2, compared=46, regressions=0, unassessed=0):
    from datetime import datetime, timedelta, timezone
    when = datetime.now(timezone.utc) - timedelta(hours=age_hours)
    return {
        "emitted_at": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "divergence": {
            "status": "converged" if not regressions else "diverged",
            "ksis_compared": compared,
            "regressions": [{"ksi": f"K{i}"} for i in range(regressions)],
            "unassessed": [{"ksi": f"U{i}"} for i in range(unassessed)],
            "unattributed_failures": 0,
        },
    }


# --- the happy path ---

def test_fresh_and_converged_reports_the_full_ratio():
    r = run(sig())
    assert r["written"].startswith("46/46 controls, re-verified ")
    assert r["written"].endswith(" → ")


@pytest.mark.parametrize("hours,expected", [(2, "2h ago"), (26, "1d ago")])
def test_age_is_rendered_from_the_runtime_timestamp(hours, expected):
    assert expected in run(sig(age_hours=hours))["written"]


# --- the red path: the whole point is that it does not hide ---

def test_a_regression_lowers_the_ratio_rather_than_hiding_it():
    assert run(sig(regressions=1))["written"].startswith("45/46 controls")


def test_unassessed_controls_are_not_counted_as_passing():
    assert run(sig(regressions=1, unassessed=2))["written"].startswith("43/46 controls")


# --- staying silent ---

@pytest.mark.parametrize("case,kwargs", [
    ("stale beyond two missed daily runs", dict(signal=sig(age_hours=49))),
    ("http error", dict(signal=sig(), ok=False)),
    ("network failure", dict(signal=sig(), throws=True)),
])
def test_stays_silent(case, kwargs):
    assert run(**kwargs)["written"] is None, case


@pytest.mark.parametrize("bad", [
    {},
    {"emitted_at": "2026-08-06T16:00:00Z"},
    {"emitted_at": "not-a-date", "divergence": {"ksis_compared": 46, "regressions": [], "unassessed": []}},
    {"emitted_at": "2026-08-06T16:00:00Z", "divergence": {"ksis_compared": 0, "regressions": [], "unassessed": []}},
    {"emitted_at": "2026-08-06T16:00:00Z", "divergence": {"ksis_compared": 46, "regressions": "nope", "unassessed": []}},
])
def test_malformed_signals_write_nothing(bad):
    assert run(bad)["written"] is None


def test_no_fetch_on_pages_without_the_hook():
    # main.js loads on all 40+ pages; only the homepage carries the hook.
    assert run(sig(), has_hook=False)["fetched"] is False


# --- what ships in the HTML ---

def test_index_ships_the_link_and_no_claim():
    html = INDEX.read_text()
    assert "data-compliance-status" in html
    assert '<a href="/viewer.html">live dashboard</a>' in html
    # no hardcoded figures: every number must come from the signal at runtime
    i = html.index("compliance evidence")
    assert "controls" not in html[i:i + 200]
