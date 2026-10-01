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


# ---------------------------------------------------------------------------
# The live queue: date-driven items are rebuilt when the page is read, so an
# empty queue cannot outlive the deploy that published it.

WHY = {k: f"why {k}" for k in ("decision_review_due", "exception_expiring", "poam_overdue", "runtime_diverged",
                               "runtime_unassessed", "runtime_stale", "vulnerability_evidence_stale")}


def queue(tmp_path: Path, doc: dict, live: dict | None = None) -> list[dict]:
    mod = tmp_path / "trust.mjs"
    mod.write_text(TRUST_JS.read_text())
    script = (f"import {{ liveQueue }} from {json.dumps(str(mod))};"
              f"console.log(JSON.stringify(liveQueue({json.dumps(doc)}, Date.parse({json.dumps(NOW)}), {json.dumps(live or {})})));")
    out = subprocess.run(["node", "--input-type=module", "-e", script], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def doc(**over) -> dict:
    d = {
        "freshness_windows_hours": {"runtime": 26, "vulnerability_scan": 24},
        "decisions_pending": [{"kind": "trust_root_change", "id": "aws_iam_role.x", "title": "t", "why_yours": "w"},
                              {"kind": "poam_overdue", "id": "POAM-STALE", "title": "deploy-time copy", "why_yours": "w"}],
        "decision_log": [
            {"kind": "poam_risk_decision", "id": "POAM-010", "subject": "Lambda VPC", "review_by": "2026-09-01", "source": "/.well-known/oscal-poam.json"},
            {"kind": "poam_risk_decision", "id": "POAM-011", "subject": "Later", "review_by": "2027-06-01", "source": "/.well-known/oscal-poam.json"},
            {"kind": "policy_exception", "id": "a11y_error:page.html", "subject": "a11y_error on page.html", "review_by": "2026-10-20", "ticket": "POAM-033"},
            {"kind": "significant_change", "id": "SCN-1", "subject": "s", "review_by": None},
        ],
        "live_queue": {"why_yours": WHY, "exception_warning_days": 30,
                       "poam_due": [{"id": "POAM-020", "title": "Due soon", "due": "2026-09-29"},
                                    {"id": "POAM-021", "title": "Not yet", "due": "2026-12-01"}]},
    }
    d.update(over)
    return d


def kinds(items: list[dict]) -> set[tuple[str, str]]:
    return {(i["kind"], i["id"]) for i in items}


def test_dates_are_judged_when_the_page_is_read(tmp_path):
    k = kinds(queue(tmp_path, doc()))
    assert ("decision_review_due", "POAM-010") in k          # review date passed since the deploy
    assert ("decision_review_due", "POAM-011") not in k
    assert ("exception_expiring", "a11y_error:page.html") in k  # 20 days left
    assert ("poam_overdue", "POAM-020") in k and ("poam_overdue", "POAM-021") not in k
    assert ("poam_overdue", "POAM-STALE") not in k           # the deploy-time copy is replaced, not duplicated
    assert ("trust_root_change", "aws_iam_role.x") in k      # deploy-only kinds are kept
    assert all(i["why_yours"] for i in queue(tmp_path, doc()))


def test_live_runtime_replaces_the_deploy_time_runtime_items(tmp_path):
    d = doc(decisions_pending=[{"kind": "runtime_unassessed", "id": "runtime-unassessed", "title": "old", "why_yours": "w"}])
    fresh = {"emitted_at": "2026-09-30T11:00:00Z", "divergence": {"status": "converged", "regressions": [], "unassessed": []}}
    assert not {k for k in kinds(queue(tmp_path, d, {"runtime": fresh})) if k[0].startswith("runtime")}
    # Without a live read the deploy-time runtime item stands.
    assert ("runtime_unassessed", "runtime-unassessed") in kinds(queue(tmp_path, d))
    stale = {"emitted_at": "2026-09-28T00:00:00Z", "divergence": {"status": "diverged", "regressions": [{"ksi_id": "KSI-A"}]}}
    k = kinds(queue(tmp_path, d, {"runtime": stale}))
    assert ("runtime_diverged", "KSI-A") in k and ("runtime_stale", "runtime-stale") in k


def test_stale_vulnerability_evidence_is_a_decision(tmp_path):
    assert ("vulnerability_evidence_stale", "vdr-stale") in kinds(queue(tmp_path, doc(), {"vdrReport": {"emitted_at": "2026-09-29T06:00:00Z"}}))
    assert ("vulnerability_evidence_stale", "vdr-stale") not in kinds(queue(tmp_path, doc(), {"vdrReport": {"emitted_at": "2026-09-30T06:00:00Z"}}))


def test_a_document_without_live_data_is_shown_as_deployed(tmp_path):
    d = doc()
    del d["live_queue"]
    assert queue(tmp_path, d) == d["decisions_pending"]


def test_links_name_the_file_not_the_directory():
    # CloudFront serves index.html only at the site root; /trust/ is a 404 in
    # production, so every link must name /trust/index.html. /silk-reeling/ is
    # the exception: CloudFront routes it to the app, not to S3.
    import re
    routed = {"/", "/silk-reeling/"}
    bad = []
    for path in (REPO / "website").rglob("*.html"):
        for m in re.finditer(r'href="(/[^"#?]*/)(?:[#?][^"]*)?"', path.read_text()):
            if m.group(1) not in routed:
                bad.append(f"{path.relative_to(REPO)}: {m.group(1)}")
    assert not bad, bad[:10]
