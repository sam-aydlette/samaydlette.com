"""Deploy-vs-runtime divergence detection (infrastructure/lambda/divergence.js).

The runtime Lambda re-evaluates the live account a day after the deploy gate
evaluated the plan. Both run the same compiled policy, so a disagreement means
something — but only if "the resource regressed" is kept distinct from "the
evaluator could not look".

That distinction is the whole point of these tests. The pipeline published four
KSIs as failing at runtime and passing at deploy for four weeks, and the cause
was an IAM gap on one bucket, not drift. Any consumer that acts on this signal
(alerting, gating, rollback) keys on `status == "diverged"`, so a read failure
being classified as a regression is a correctness defect with real blast radius,
not a cosmetic one.

The module under test is deliberately free of AWS-SDK imports (same reason
canonical.js is), so it runs under plain node with no node_modules present.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
MODULE = REPO / "infrastructure" / "lambda" / "divergence.js"

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None, reason="node not available"
)


DEPLOY_SIGNAL = {
    "signal_id": "sig-deploy-1",
    "emitted_at": "2026-08-05T10:03:34Z",
    "provenance": {"source": {"commit": "abc1234"}},
    "ksis": [
        {"id": "KSI-SVC-SIN", "status": "pass"},
        {"id": "KSI-CNA-ULN", "status": "pass"},
        {"id": "KSI-PIY-GIV", "status": "pass"},
        {"id": "KSI-RPL-ABO", "status": "pass"},
        {"id": "KSI-MLA-EVC", "status": "pass"},
        {"id": "KSI-ALREADY-RED", "status": "fail"},
    ],
}


def divergence(validations, deploy_signal=None):
    """Call computeDivergence in node and return the parsed result."""
    payload = json.dumps({
        "deploy": deploy_signal if deploy_signal is not None else DEPLOY_SIGNAL,
        "validations": validations,
    })
    script = (
        f"const {{computeDivergence}} = require({json.dumps(str(MODULE))});"
        "let raw='';process.stdin.on('data',d=>raw+=d).on('end',()=>{"
        "const {deploy,validations}=JSON.parse(raw);"
        "process.stdout.write(JSON.stringify(computeDivergence(deploy,validations)));});"
    )
    out = subprocess.run(
        ["node", "-e", script], input=payload, capture_output=True, text=True, check=True
    )
    return json.loads(out.stdout)


def fail(*violations):
    return [{"result": "fail", "violations": list(violations)}]


def viol(rule_id, category, ksi_ids):
    return {"id": rule_id, "category": category, "ksi_ids": ksi_ids}


def test_all_passing_converges():
    d = divergence([{"result": "pass", "violations": []}])
    assert d["status"] == "converged"
    assert d["regressions"] == []
    assert d["unassessed"] == []


def test_genuine_drift_is_a_regression():
    """A resource-category failure on a KSI the deploy gate passed is drift."""
    d = divergence(fail(viol("versioning_disabled", "infrastructure", ["KSI-RPL-ABO"])))
    assert d["status"] == "diverged"
    assert [r["ksi_id"] for r in d["regressions"]] == ["KSI-RPL-ABO"]
    assert d["regressions"][0]["deploy_status"] == "pass"
    assert d["regressions"][0]["runtime_status"] == "fail"


def test_read_failure_is_not_drift():
    """THE regression test for the four-week false positive.

    A category:input violation means the evaluator never reached a verdict. It
    must degrade the signal, never report the resource as regressed — otherwise
    a missing IAM grant reads as infrastructure drift and anything acting on
    `diverged` fires on an observer fault.
    """
    d = divergence(fail(viol("resource_read_error", "input", ["KSI-MLA-EVC"])))
    assert d["status"] == "degraded"
    assert d["regressions"] == []
    assert [r["ksi_id"] for r in d["unassessed"]] == ["KSI-MLA-EVC"]
    assert d["unassessed"][0]["runtime_status"] == "unassessed"


def test_read_failure_never_masks_real_drift():
    """A read error on one attribute must not suppress a real regression."""
    d = divergence(fail(
        viol("versioning_disabled", "infrastructure", ["KSI-RPL-ABO"]),
        viol("resource_read_error", "input", ["KSI-MLA-EVC"]),
    ))
    assert d["status"] == "diverged"
    assert [r["ksi_id"] for r in d["regressions"]] == ["KSI-RPL-ABO"]
    assert [r["ksi_id"] for r in d["unassessed"]] == ["KSI-MLA-EVC"]


def test_no_divergence_when_both_sides_already_agree():
    """A KSI already failing at deploy time is an open finding, not a divergence."""
    d = divergence(fail(viol("some_rule", "infrastructure", ["KSI-ALREADY-RED"])))
    assert d["status"] == "converged"
    assert d["regressions"] == []


def test_violation_without_ksi_ids_is_counted_not_dropped():
    """An unattributable failure must degrade the signal rather than vanish."""
    d = divergence(fail({"id": "input_error", "category": "input"}))
    assert d["unattributed_failures"] == 1
    assert d["status"] == "degraded"


def test_multiple_rules_on_one_ksi_are_deduped_and_sorted():
    d = divergence(fail(
        viol("missing_required_tags", "infrastructure", ["KSI-PIY-GIV"]),
        viol("missing_classification_tag", "infrastructure", ["KSI-PIY-GIV"]),
    ))
    assert [r["ksi_id"] for r in d["regressions"]] == ["KSI-PIY-GIV"]
    assert d["regressions"][0]["violation_ids"] == [
        "missing_classification_tag",
        "missing_required_tags",
    ]


def test_records_what_it_compared_against():
    """The verdict is only meaningful with the deploy signal it was compared to."""
    d = divergence([{"result": "pass", "violations": []}])
    assert d["compared_against"] == {
        "signal_id": "sig-deploy-1",
        "emitted_at": "2026-08-05T10:03:34Z",
        "commit": "abc1234",
    }
    assert d["ksis_compared"] == 6


def test_deploy_signal_without_ksis_reports_nothing_comparable():
    """A deploy signal carrying no KSIs must not silently read as converged-and-clean."""
    d = divergence(
        fail(viol("versioning_disabled", "infrastructure", ["KSI-RPL-ABO"])),
        deploy_signal={"signal_id": "s", "emitted_at": "t", "provenance": {}},
    )
    assert d["ksis_compared"] == 0
    # Nothing to compare against, so no regression can be asserted.
    assert d["regressions"] == []
    assert d["compared_against"]["commit"] is None
