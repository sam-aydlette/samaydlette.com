"""One alert issue per failing gate command, routed to its owners (scripts/gate-alerts.py)."""
import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import _gates  # noqa: E402

spec = importlib.util.spec_from_file_location("gate_alerts", REPO / "scripts" / "gate-alerts.py")
ga = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ga)

RECONCILE = "scripts/run-gates.sh reconcile"
VULN = "scripts/run-gates.sh vuln"


def _results(tmp_path, **runs):
    p = tmp_path / "results.jsonl"
    p.write_text("".join(json.dumps({"run": r, "result": res, "at": "t"}) + "\n" for r, res in runs.items()))
    return p


def _by_title(actions):
    return {a["title"]: a for a in actions}


def test_a_failing_gate_opens_one_issue_for_its_command_with_every_owner(tmp_path):
    reg = _gates.load_gate_modes()
    acts = _by_title(ga.plan(reg, "nightly", ["nightly"], _results(tmp_path, **{RECONCILE: "fail"}), True))
    a = acts[ga.title_for("nightly", RECONCILE)]
    assert a["action"] == "open"
    sharing = {c: e["owner"] for c, e in reg["checks"].items() if e.get("run") == RECONCILE and "nightly" in e["stages"]}
    assert len(sharing) > 1, "the test needs a command several checks share"
    assert dict(a["checks"]) == sharing
    assert a["labels"] == [ga.LABEL] + sorted(set(sharing.values()))
    # A gate failed, so the run's failure is accounted for: no fallback issue.
    assert ga.fallback_title("nightly") not in acts


def test_a_passing_gate_closes_its_issue_and_unreported_gates_are_left_alone(tmp_path):
    reg = _gates.load_gate_modes()
    acts = _by_title(ga.plan(reg, "nightly", ["nightly"], _results(tmp_path, **{VULN: "pass"}), False))
    assert acts[ga.title_for("nightly", VULN)]["action"] == "close"
    # Not run this time (and checks with no run script): no action either way.
    assert ga.title_for("nightly", RECONCILE) not in acts
    assert all(a["action"] == "close" for a in acts.values())


def test_a_run_that_failed_outside_any_gate_opens_the_fallback_and_success_closes_it(tmp_path):
    reg = _gates.load_gate_modes()
    failed = _by_title(ga.plan(reg, "deploy", ["pr", "pre-apply"], _results(tmp_path, **{VULN: "pass"}), True))
    assert failed[ga.fallback_title("deploy")]["action"] == "open"
    ok = _by_title(ga.plan(reg, "deploy", ["pr", "pre-apply"], _results(tmp_path), False))
    assert ok[ga.fallback_title("deploy")]["action"] == "close"


def test_each_workflow_keeps_its_own_issues():
    assert ga.title_for("deploy", VULN) != ga.title_for("nightly", VULN)
    assert ga.fallback_title("deploy") != ga.fallback_title("nightly")


def test_dry_run_names_the_actions_and_calls_nothing(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(ga, "_gh", lambda *a: (_ for _ in ()).throw(AssertionError("called gh")))
    assert ga.main(["nightly", str(_results(tmp_path, **{VULN: "fail"})), "nightly", "--run-failed", "true", "--dry-run"]) == 0
    assert f"open: {ga.title_for('nightly', VULN)}" in capsys.readouterr().out
