"""The trust center page judges fast-moving evidence live, and defers to signed verdicts.

Carried over from the retired dashboard's tests (test_viewer_freshness.py,
test_viewer_divergence.py):

- From 2026-09-09 to 2026-09-24 the nightly VDR refresh failed every night while
  the dashboard looked green. The page must say plainly when evidence is stale,
  judged when it is read, not when it was deployed.
- A missing IAM grant once showed up as infrastructure drift because the page
  recomputed divergence from validation results. The page must render the
  runtime emitter's signed verdict (divergence.status), never recompute it.

These execute the shipped website/assets/js/trust.js in node.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
TRUST_JS = REPO / "website" / "assets" / "js" / "trust.js"
PAGE = REPO / "website" / "trust" / "index.html"
NOW = "2026-09-30T12:00:00Z"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not available")


def run(tmp_path: Path, fn: str, data: dict, window: int) -> dict:
    mod = tmp_path / "trust.mjs"
    mod.write_text(TRUST_JS.read_text())
    script = (f"import {{ {fn} }} from {json.dumps(str(mod))};"
              f"console.log(JSON.stringify({fn}({json.dumps(data)}, Date.parse({json.dumps(NOW)}), {window})));")
    out = subprocess.run(["node", "--input-type=module", "-e", script], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def test_fresh_converged_runtime_is_ok(tmp_path):
    r = run(tmp_path, "evaluateRuntime", {"emitted_at": "2026-09-30T10:00:00Z", "divergence": {"status": "converged", "ksis_compared": 46}}, 26)
    assert r["status"] == "ok" and "2 h old" in r["detail"]


def test_stale_runtime_is_attention_even_if_converged(tmp_path):
    r = run(tmp_path, "evaluateRuntime", {"emitted_at": "2026-09-28T00:00:00Z", "divergence": {"status": "converged"}}, 26)
    assert r["status"] == "attention" and "past its freshness window" in r["detail"]


def test_runtime_verdict_is_the_signed_one(tmp_path):
    # Failing validations in the signal do not make it diverged; only the
    # emitter's signed status does, and a degraded status is never "ok".
    signal = {"emitted_at": "2026-09-30T11:00:00Z", "validations": [{"result": "fail", "violations": [{"id": "resource_read_error"}]}],
              "divergence": {"status": "degraded", "unassessed": [{"ksi_id": "KSI-MLA-EVC"}]}}
    r = run(tmp_path, "evaluateRuntime", signal, 26)
    assert r["status"] == "attention" and r["detail"].startswith("degraded") and "1 not assessed" in r["detail"]


def test_failed_or_stale_nightly_is_attention(tmp_path):
    assert run(tmp_path, "evaluateNightly", {"result": "failure", "finished_at": "2026-09-30T11:00:00Z"}, 24)["status"] == "attention"
    stale = run(tmp_path, "evaluateNightly", {"result": "success", "finished_at": "2026-09-29T00:00:00Z"}, 24)
    assert stale["status"] == "attention" and "36 h ago" in stale["detail"]
    assert run(tmp_path, "evaluateNightly", {"result": "success", "finished_at": "2026-09-30T07:30:00Z"}, 24)["status"] == "ok"


def test_missing_timestamps_are_never_ok(tmp_path):
    assert run(tmp_path, "evaluateNightly", {"result": "success"}, 24)["status"] == "attention"
    assert run(tmp_path, "evaluateRuntime", {"divergence": {"status": "converged"}}, 26)["status"] == "attention"


def test_page_never_claims_certification():
    text = PAGE.read_text()
    assert "not FedRAMP Certified" in text and "adhere to" in text
    for claim in ("is FedRAMP Certified", "is certified", "is authorized", "FedRAMP Authorized"):
        assert claim not in text


def test_page_renders_data_as_text_only():
    js = TRUST_JS.read_text()
    assert "innerHTML" not in js and "insertAdjacentHTML" not in js
