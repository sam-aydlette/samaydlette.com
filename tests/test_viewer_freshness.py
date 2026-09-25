"""The dashboard must say, plainly, when published evidence is stale.

From 2026-09-09 to 2026-09-24 the nightly VDR refresh failed every night. The
dashboard showed the deploy signal's age as relative text on a green card and
did not show the VDR's age at all, so a policy breach looked like a quiet week.
The VDR card, the runtime card's window and the banner exist so that it cannot.

These tests execute the real viewer.js in node against a DOM shim, as
test_viewer_divergence.py does, so they exercise the shipped code.
"""

import datetime as dt
import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
VIEWER_JS = REPO / "website" / "assets" / "js" / "viewer.js"
VIEWER_HTML = REPO / "website" / "viewer.html"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not available")

DOM_SHIM = """
function mkNode(id) {
  return {
    id, className: '', textContent: '', innerHTML: '', hidden: true,
    _kids: {},
    querySelector(sel) {
      const k = sel.replace('.', '');
      if (!this._kids[k]) this._kids[k] = { textContent: '', innerHTML: '' };
      return this._kids[k];
    },
  };
}
const NODES = {};
for (const id of ['status-signed','status-deploy','status-runtime','status-vdr',
                  'status-drift','sla-banner']) NODES[id] = mkNode(id);
global.document = {
  getElementById: (id) => NODES[id] || null,
  addEventListener: () => {},
  readyState: 'complete',
};
global.window = {};
global.fetch = () => Promise.reject(new Error('no network in test'));
"""


def hours_ago(h):
    t = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=h)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def render(vdr=None, runtime=None):
    src = VIEWER_JS.read_text().replace(
        "})();", "global.__renderStatus = renderStatus;\n})();", 1)
    script = DOM_SHIM + src + textwrap.dedent(f"""
        global.__renderStatus({{"emitted_at": "{hours_ago(200)}"}},
                              {json.dumps(runtime)}, null, {json.dumps(vdr)});
        const card = (id) => ({{cls: NODES[id].className,
                               value: NODES[id].querySelector('.status-value').textContent,
                               detail: NODES[id].querySelector('.status-detail').textContent}});
        console.log(JSON.stringify({{
          vdr: card('status-vdr'), runtime: card('status-runtime'),
          banner: {{hidden: NODES['sla-banner'].hidden, text: NODES['sla-banner'].textContent}},
        }}));
    """)
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True)
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_fresh_evidence_is_green_and_the_banner_stays_hidden():
    r = render(vdr={"emitted_at": hours_ago(2)}, runtime={"emitted_at": hours_ago(3)})
    assert "is-good" in r["vdr"]["cls"]
    assert "policy: under 24h" in r["vdr"]["detail"]
    assert "is-good" in r["runtime"]["cls"]
    assert r["banner"]["hidden"] is True


def test_a_vdr_past_24_hours_is_red_and_named_in_the_banner():
    r = render(vdr={"emitted_at": hours_ago(30)}, runtime={"emitted_at": hours_ago(3)})
    assert "is-bad" in r["vdr"]["cls"]
    assert r["vdr"]["value"].startswith("stale")
    assert r["banner"]["hidden"] is False
    assert "vulnerability report" in r["banner"]["text"]
    assert "under 24h" in r["banner"]["text"]


def test_twelve_days_stale_reads_in_days():
    # The failure this exists for: the VDR sat 12 days old.
    r = render(vdr={"emitted_at": hours_ago(12 * 24)}, runtime={"emitted_at": hours_ago(3)})
    assert r["vdr"]["value"] == "stale · 12d ago"
    assert "12d old" in r["banner"]["text"]


def test_an_unreachable_vdr_is_a_breach_not_a_blank():
    r = render(vdr=None, runtime={"emitted_at": hours_ago(3)})
    assert "is-bad" in r["vdr"]["cls"]
    assert r["vdr"]["value"] == "unknown"
    assert r["banner"]["hidden"] is False


def test_the_daily_runtime_check_gets_scheduling_slack_then_goes_stale():
    ok = render(vdr={"emitted_at": hours_ago(2)}, runtime={"emitted_at": hours_ago(25)})
    assert "is-good" in ok["runtime"]["cls"]
    assert ok["banner"]["hidden"] is True
    late = render(vdr={"emitted_at": hours_ago(2)}, runtime={"emitted_at": hours_ago(27)})
    assert "is-bad" in late["runtime"]["cls"]
    assert late["runtime"]["value"].startswith("stale")
    assert "runtime check" in late["banner"]["text"]


def test_the_page_carries_the_card_and_an_announced_banner():
    html = VIEWER_HTML.read_text()
    assert 'id="status-vdr"' in html
    assert 'id="sla-banner" role="alert" hidden' in html
