"""The dashboard must render the signed divergence verdict, not recompute it.

The Drift card previously derived its own verdict by diffing validation results
between the two signals. That cannot distinguish a resource that regressed from
an evaluator that could not read the resource: a validation carrying only a
`resource_read_error` is a `fail` like any other, so a missing IAM grant showed
up as infrastructure drift. The runtime emitter already makes that distinction
and records it in the signed signal; the page should defer to it.

These tests execute the real viewer.js in node against a DOM shim, so they
exercise the shipped code rather than a reimplementation of it.
"""

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
VIEWER_JS = REPO / "website" / "assets" / "js" / "viewer.js"
VIEWER_HTML = REPO / "website" / "viewer.html"
VIEWER_CSS = REPO / "website" / "assets" / "css" / "viewer.css"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not available")

DOM_SHIM = """
// Minimal DOM: enough for the status cards and the divergence panel.
function mkNode(id) {
  return {
    id, className: '', textContent: '', innerHTML: '',
    _kids: {},
    querySelector(sel) {
      const k = sel.replace('.', '');
      if (!this._kids[k]) this._kids[k] = { textContent: '', innerHTML: '' };
      return this._kids[k];
    },
  };
}
const NODES = {};
for (const id of ['status-signed','status-deploy','status-runtime','status-drift',
                  'divergence-meta','divergence-body','ksi-meta','ksi-components',
                  'ksi-component-summary','ksi-validations','oscal-meta','oscal-summary',
                  'oscal-controls','oscal-filter-summary','filter-status',
                  'filter-origination','filter-search']) NODES[id] = mkNode(id);

global.document = {
  getElementById: (id) => NODES[id] || null,
  addEventListener: () => {},
  readyState: 'complete',
};
global.window = {};
global.fetch = () => Promise.reject(new Error('no network in test'));
"""


def run_viewer(runtime_signal, deploy_signal=None):
    """Execute viewer.js's renderStatus + renderDivergencePanel and dump the DOM."""
    src = VIEWER_JS.read_text()
    # The IIFE keeps its functions private; re-expose the two under test.
    src = src.replace(
        "})();",
        "global.__renderStatus = renderStatus;\n"
        "global.__renderDivergencePanel = renderDivergencePanel;\n})();",
        1,
    )
    script = (
        DOM_SHIM
        + src
        + textwrap.dedent(f"""
        const runtime = {json.dumps(runtime_signal)};
        const deploy  = {json.dumps(deploy_signal or {"emitted_at": "2026-08-06T10:00:00Z"})};
        global.__renderStatus(deploy, runtime, null);
        global.__renderDivergencePanel(runtime);
        const drift = NODES['status-drift'];
        console.log(JSON.stringify({{
          driftClass: drift.className,
          driftValue: drift.querySelector('.status-value').textContent,
          driftDetail: drift.querySelector('.status-detail').textContent,
          body: NODES['divergence-body'].innerHTML,
          meta: NODES['divergence-meta'].innerHTML,
        }}));
        """)
    )
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True)
    return json.loads(out.stdout.strip().splitlines()[-1])


def sig(status, regressions=(), unassessed=(), unattributed=0, compared=6):
    return {
        "emitted_at": "2026-08-06T16:50:00Z",
        "divergence": {
            "status": status,
            "compared_against": {"signal_id": "sig-1", "emitted_at": "2026-08-06T10:00:00Z",
                                 "commit": "abc1234"},
            "ksis_compared": compared,
            "regressions": list(regressions),
            "unassessed": list(unassessed),
            "unattributed_failures": unattributed,
        },
    }


def entry(ksi, rules, runtime="fail"):
    return {"ksi_id": ksi, "deploy_status": "pass", "runtime_status": runtime,
            "violation_ids": list(rules)}


def test_converged_reads_as_in_sync():
    r = run_viewer(sig("converged"))
    assert "is-good" in r["driftClass"]
    assert r["driftValue"] == "in sync"


def test_diverged_is_bad_and_names_the_ksis():
    r = run_viewer(sig("diverged", regressions=[entry("KSI-RPL-ABO", ["versioning_disabled"])]))
    assert "is-bad" in r["driftClass"]
    assert r["driftValue"] == "drift detected"
    assert "KSI-RPL-ABO" in r["driftDetail"]
    assert "Regressions" in r["body"]
    assert "versioning_disabled" in r["body"]


def test_degraded_warns_and_is_not_reported_as_drift():
    """The four-week false positive, as the dashboard would have shown it."""
    r = run_viewer(sig("degraded",
                       unassessed=[entry("KSI-MLA-EVC", ["resource_read_error"], runtime="unassessed")]))
    assert "is-warn" in r["driftClass"], "an evaluator fault must not read as drift"
    assert "is-bad" not in r["driftClass"]
    assert r["driftValue"] != "drift detected"
    assert "Unassessed" in r["body"]
    assert "observer" in r["body"]


def test_unassessed_badge_does_not_borrow_the_failure_class():
    r = run_viewer(sig("degraded",
                       unassessed=[entry("KSI-MLA-EVC", ["resource_read_error"], runtime="unassessed")]))
    assert "badge-unassessed" in r["body"]
    assert "badge-fail" not in r["body"]


def test_regression_and_unassessed_render_separately():
    r = run_viewer(sig("diverged",
                       regressions=[entry("KSI-RPL-ABO", ["versioning_disabled"])],
                       unassessed=[entry("KSI-MLA-EVC", ["resource_read_error"], runtime="unassessed")]))
    assert "Regressions" in r["body"] and "Unassessed" in r["body"]
    assert r["body"].index("Regressions") < r["body"].index("Unassessed")


def test_signal_without_divergence_block_falls_back_not_crashes():
    """Rollout window: signals emitted before the verdict existed."""
    r = run_viewer({"emitted_at": "2026-08-06T16:50:00Z", "validations": []})
    assert "predates the signed divergence verdict" in r["driftDetail"]
    assert "has not run since the check was added" in r["body"]


def test_missing_runtime_signal_is_reported_as_unavailable():
    r = run_viewer(None)
    assert r["driftValue"] == "unavailable"
    assert "status-card status-card" not in r["driftClass"]


def test_comparison_provenance_is_shown():
    r = run_viewer(sig("converged"))
    assert "abc1234" in r["meta"] and "sig-1" in r["meta"]


def test_unattributed_failures_are_surfaced():
    r = run_viewer(sig("degraded", unattributed=2))
    assert "no KSI mapping" in r["body"]


# --- markup / style wiring --------------------------------------------------

def test_panel_and_targets_exist_in_the_page():
    html = VIEWER_HTML.read_text()
    assert 'id="divergence-panel"' in html
    assert 'id="divergence-body"' in html
    assert 'id="divergence-meta"' in html
    assert "/.well-known/ksi-signal-runtime.json" in html


def test_unassessed_badge_is_styled():
    assert ".badge-unassessed" in VIEWER_CSS.read_text()
