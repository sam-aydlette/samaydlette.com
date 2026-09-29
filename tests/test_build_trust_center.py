"""The trust center is derived from this build's artifacts and registers, never typed.

Pure-function tests over synthetic inputs. Account numbers use the AWS
documentation example (this repo is public).
"""

from __future__ import annotations

import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("btc", REPO / "scripts" / "build-trust-center.py")
assert spec and spec.loader
btc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(btc)

NOW = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)
SIG = "sig-1"


def poam_item(pid: str, status: str, disposition: str, scheduled: str) -> dict:
    props = {"poam-id": pid, "status": status, "disposition": disposition, "scheduled-completion-date": scheduled,
             "point-of-contact": "Operator", "status-date": "2026-05-08"}
    return {"title": f"{pid} title", "description": f"{pid} rationale",
            "props": [{"name": k, "value": v} for k, v in props.items()]}


def inputs(**overrides):
    inp = {
        "signal": {"signal_id": SIG, "system_id": "sys", "categorization": {"impact_level": "moderate"},
                   "emitted_at": "2026-09-29T11:00:00Z", "components": [{}, {}],
                   "ksis": [{"id": "KSI-A", "status": "pass"}, {"id": "KSI-B", "status": "fail"}]},
        "vdr": {"summary": {"dispositioned_findings": 9}, "findings": [
            {"tracking_id": "f-block", "title": "blocking", "is_blocking": True, "final_disposition": "open"},
            {"tracking_id": "f-open", "title": "open", "is_blocking": False, "final_disposition": "open", "component_id": "aws::function::app"},
            {"tracking_id": "f-done", "title": "done", "is_blocking": False, "final_disposition": "false-positive"},
        ]},
        "poam": {"plan-of-action-and-milestones": {"poam-items": [
            poam_item("POAM-001", "open", "risk-accepted", "2026-09-01"),  # overdue
            poam_item("POAM-002", "open", "operational-requirement", "TBD (pending procurement)"),  # not a date
            poam_item("POAM-003", "closed", "remediated", "2026-01-01"),  # closed: neither overdue nor a decision
        ]}},
        "reconcile": {"result": "pass", "ksi_signal_id": SIG, "generated_at": "2026-09-29T11:30:00Z",
                      "invariants": [{"id": "a", "status": "held"}, {"id": "b", "status": "deferred"}]},
        "boundary_map": {"ksi_signal_id": SIG, "health": {"unclassified": 0, "untagged": 1},
                         "trust_root_changes": [{"address": "aws_iam_group_policy.ops", "actions": ["create"], "component": None}],
                         "unclassified": [],
                         "nodes": [{"id": "aws::iam_role::x", "name": "x", "kind": "collected", "flags": ["untagged"]},
                                   {"id": "declared:vendor", "name": "Vendor API", "kind": "not_inventoried", "flags": []}]},
        "trust_root_plan": {"status": "changes_pending", "planned_at": "2026-09-29T11:00:00Z",
                            "changes": [{"address": "aws_iam_group_policy.ops", "actions": ["create"]}]},
        "runtime": {"emitted_at": "2026-09-29T10:00:00Z", "divergence": {
            "status": "diverged", "ksis_compared": 2, "regressions": [{"ksi_id": "KSI-A"}], "unassessed": [{"ksi_id": "KSI-B"}]}},
        "vdr_status": {"result": "success", "finished_at": "2026-09-29T00:00:00Z"},
        "previous": None,
        "dispositions": {"CVE-1": {"disposition": "false-positive", "justification": "unreachable", "poam_ref": "POAM-034",
                                   "decided_by": "Operator", "decided_on": "2026-08-24"}},
        "exceptions": [{"resource": "page.html", "rule_id": "a11y_error", "justification": "decorative", "expiry": "2026-10-10", "ticket": "POAM-033"},
                       {"resource": "other.html", "rule_id": "a11y_error", "justification": "later", "expiry": "2027-06-01", "ticket": "POAM-033"}],
        "policy_config": {"gate": {"tls": {"minimum": "TLSv1.2_2021"}, "required_tags": ["Owner"]}},
        "rules": [{"path": "policy.terraform.s3.violations", "title": "Versioning", "custom": {"id": "versioning_disabled", "severity": "MEDIUM", "ksi_ids": ["KSI-RPL-ABO"]}}],
        "scn_register": [
            {"scn_id": "SCN-1", "status": "post-implementation verification COMPLETE 2026-06-01", "approver_name": "Operator",
             "date_initiated": "2026-05-01", "scn_type": "adaptive", "short_description": "done", "categorization_rationale": "why"},
            {"scn_id": "SCN-2", "status": "Step 1 implemented; verification pending", "approver_name": "Operator",
             "date_initiated": "2026-09-01", "scn_type": "adaptive", "short_description": "in flight", "categorization_rationale": "why"},
        ],
        "checkov_skips": ["CKV_AWS_144"],
        "figures": {"moderate_coverage": "323/323"},
    }
    inp.update(overrides)
    return inp


def build(**overrides):
    return btc.build(inputs(**overrides), "c0ffee", NOW)


def kinds(doc):
    return [(d["kind"], d["id"]) for d in doc["decisions_pending"]]


def picture(doc):
    return {p["id"]: p["status"] for p in doc["picture"]}


def test_artifacts_bound_to_another_inventory_fail_closed():
    with pytest.raises(SystemExit):
        build(reconcile={**inputs()["reconcile"], "ksi_signal_id": "other"})
    with pytest.raises(SystemExit):
        build(boundary_map={**inputs()["boundary_map"], "ksi_signal_id": "other"})


def test_picture_reports_what_was_observed_and_says_when_nothing_was():
    p = picture(build())
    assert p["reconciliation"] == "attention"  # an invariant was deferred
    assert p["trust_root"] == "attention" and p["runtime"] == "attention" and p["boundary"] == "attention"
    assert p["vulnerability_scan"] == "ok"
    assert p["github_settings"] == p["dnssec"] == p["sns_subscription"] == "not_observed"
    p = picture(build(runtime=None, vdr_status=None, trust_root_plan=None))
    assert p["runtime"] == p["vulnerability_scan"] == p["trust_root"] == "not_observed"


def test_stale_runtime_signal_is_attention_and_a_decision():
    doc = build(runtime={"emitted_at": "2026-09-27T00:00:00Z", "divergence": {"status": "converged"}})
    assert picture(doc)["runtime"] == "attention"
    assert ("runtime_stale", "runtime-stale") in kinds(doc)


def test_the_queue_holds_only_what_precedent_cannot_settle():
    k = kinds(build())
    assert ("vdr_blocking", "f-block") in k and ("vdr_undispositioned", "f-open") in k
    assert not any(i == "f-done" for _, i in k)
    assert ("poam_overdue", "POAM-001") in k
    assert not any(i in ("POAM-002", "POAM-003") for _, i in k)  # free-text dates and closed items are not overdue
    assert ("exception_expiring", "a11y_error:page.html") in k
    assert ("exception_expiring", "a11y_error:other.html") not in k
    assert ("runtime_diverged", "KSI-A") in k and ("runtime_unassessed", "runtime-unassessed") in k
    assert ("trust_root_change", "aws_iam_group_policy.ops") in k
    assert ("boundary_untagged", "aws::iam_role::x") in k and ("boundary_not_inventoried", "declared:vendor") in k
    assert ("scn_unverified", "SCN-2") in k and ("scn_unverified", "SCN-1") not in k
    assert all(d["why_yours"] for d in build()["decisions_pending"])


def test_missing_decision_fields_are_gaps_never_guesses():
    doc = build()
    poam = next(e for e in doc["decision_log"] if e["id"] == "POAM-001")
    assert poam["decided_by"] is None and poam["decided_on"] is None
    assert set(poam["gaps"]) == {"decided_by", "decided_on", "review_by"}
    assert poam["point_of_contact"] == "Operator"  # recorded, but not presented as the decider
    cve = next(e for e in doc["decision_log"] if e["id"] == "CVE-1")
    assert cve["decided_by"] == "Operator" and cve["gaps"] == ["review_by"]
    exc = next(e for e in doc["decision_log"] if e["kind"] == "policy_exception")
    assert exc["review_by"] == "2026-10-10" and "review_by" not in exc["gaps"]
    scn = next(e for e in doc["decision_log"] if e["id"] == "SCN-1")
    assert scn["gaps"] == [] and scn["verified"] is True  # an SCN is not reviewed on a cadence
    assert doc["decision_log_gaps"]["decided_by"] == 4  # two open POA&M decisions and two exceptions
    assert ("decision_records_incomplete", "decision-record-gaps") in kinds(doc)


def test_escalation_history_keeps_one_entry_per_day():
    prev = {"escalation_rate": {"history": [{"date": "2026-09-28", "resolved_by_precedent": 5, "escalated": 1},
                                            {"date": "2026-09-29", "resolved_by_precedent": 0, "escalated": 0}]}}
    rate = build(previous=prev)["escalation_rate"]
    assert [h["date"] for h in rate["history"]] == ["2026-09-28", "2026-09-29"]
    assert rate["history"][-1]["resolved_by_precedent"] == 9
    assert rate["rate"] == round(rate["escalated"] / (9 + rate["escalated"]), 3)


def test_catalog_and_posture_come_from_their_sources():
    doc = build()
    cat = doc["policy_catalog"]
    assert cat["immutable"]["rules"][0]["id"] == "versioning_disabled"
    assert {r["name"]: r["entries"] for r in cat["precedent"]["registers"]}["Checkov suppressions"] == 1
    assert any(t["value"] == "TLSv1.2_2021" for t in cat["thresholds"]["items"])
    assert doc["posture"]["ksis"] == {"total": 2, "by_status": {"fail": 1, "pass": 1}}
    assert doc["posture"]["frameworks"]["moderate_coverage"] == "323/323"


def test_redaction_fails_closed():
    with pytest.raises(SystemExit):
        btc.check_redaction(json.dumps({"x": "arn:aws:iam::123456789012:role/r"}))
    with pytest.raises(SystemExit):
        btc.check_redaction(json.dumps({"x": "someone@example.com"}))
    btc.check_redaction(json.dumps(build()))


def test_checkov_skips_are_read_from_the_config(tmp_path):
    cfg = tmp_path / ".checkov.yaml"
    cfg.write_text("framework: terraform\nskip-check:\n  # POAM-003 reason\n  - CKV_AWS_144\n  - CKV2_AWS_57\nquiet: true\n")
    assert btc.read_checkov_skips(cfg) == ["CKV_AWS_144", "CKV2_AWS_57"]


def test_malformed_history_from_the_live_site_is_dropped():
    prev = {"escalation_rate": {"history": [{"date": "2026-09-27", "resolved_by_precedent": 1, "escalated": 0, "note": "x"},
                                            {"date": "<script>", "resolved_by_precedent": 1, "escalated": 0},
                                            {"date": "2026-09-26", "resolved_by_precedent": "1", "escalated": 0},
                                            "junk"]}}
    history = build(previous=prev)["escalation_rate"]["history"]
    assert history[0] == {"date": "2026-09-27", "resolved_by_precedent": 1, "escalated": 0}
    assert [h["date"] for h in history] == ["2026-09-27", "2026-09-29"]
