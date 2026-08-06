"""The 'stop the line' pre-flight gate (scripts/check-runtime-divergence.py).

This gate can only be cleared by a deploy, so both of its failure directions are
expensive: blocking when it should not wedges the pipeline shut, and passing when
it should not lets a change land on top of a system already in drift.

The cases that matter most here are the ones that must NOT block — the rollout
case (no divergence block yet), the observer-fault case (degraded), and the stale
case. Each of them, if it blocked, would have deadlocked this repository at some
point in its recorded history.
"""

import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "divgate", REPO / "scripts" / "check-runtime-divergence.py"
)
divgate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(divgate)

NOW = datetime(2026, 8, 6, 12, 0, 0, tzinfo=timezone.utc)


def signal(status=None, *, age_hours=1.0, regressions=(), unassessed=(), unattributed=0,
           omit_divergence=False):
    emitted = (NOW - timedelta(hours=age_hours)).isoformat().replace("+00:00", "Z")
    s = {"emitted_at": emitted, "emitter": "runtime"}
    if not omit_divergence:
        s["divergence"] = {
            "status": status,
            "compared_against": {"signal_id": "sig-1", "emitted_at": emitted, "commit": "abc1234"},
            "ksis_compared": 46,
            "regressions": list(regressions),
            "unassessed": list(unassessed),
            "unattributed_failures": unattributed,
        }
    return s


def entry(ksi, rules, deploy="pass", runtime="fail"):
    return {"ksi_id": ksi, "deploy_status": deploy, "runtime_status": runtime,
            "violation_ids": list(rules)}


def run(sig, max_age=48.0):
    return divgate.evaluate(sig, max_age, now=NOW)[0]


# --- the blocking case ------------------------------------------------------

def test_fresh_divergence_blocks():
    code = run(signal("diverged", regressions=[entry("KSI-RPL-ABO", ["versioning_disabled"])]))
    assert code == divgate.BLOCK


def test_block_message_names_the_ksi_and_the_rule():
    _, lines = divgate.evaluate(
        signal("diverged", regressions=[entry("KSI-RPL-ABO", ["versioning_disabled"])]),
        48.0, now=NOW,
    )
    body = "\n".join(lines)
    assert "DEPLOY BLOCKED" in body
    assert "KSI-RPL-ABO" in body
    assert "versioning_disabled" in body
    assert "--allow-divergence" in body  # the escape hatch must be discoverable


# --- the cases that must NOT block -----------------------------------------

def test_converged_passes():
    assert run(signal("converged")) == divgate.PASS


def test_degraded_never_blocks():
    """An observer fault (unreadable resource, missing grant) is not drift.

    This is the condition the pipeline published for four weeks. Blocking on it
    would have made the fix undeployable by the gate meant to protect the fix.
    """
    code = run(signal("degraded",
                      unassessed=[entry("KSI-MLA-EVC", ["resource_read_error"],
                                        runtime="unassessed")]))
    assert code == divgate.PASS


def test_missing_divergence_block_does_not_block():
    """Rollout case: the emitter that produces the block is not deployed yet."""
    assert run(signal(omit_divergence=True)) == divgate.PASS


def test_stale_divergence_does_not_block():
    """A verdict describing a days-old system state must not gate a new deploy."""
    code = run(signal("diverged", age_hours=72.0,
                      regressions=[entry("KSI-RPL-ABO", ["versioning_disabled"])]))
    assert code == divgate.PASS


def test_undateable_signal_does_not_block():
    s = signal("diverged", regressions=[entry("KSI-RPL-ABO", ["versioning_disabled"])])
    s["emitted_at"] = "not-a-timestamp"
    assert run(s) == divgate.PASS


def test_unrecognized_status_does_not_block():
    assert run(signal("something-new")) == divgate.PASS


# --- staleness boundary -----------------------------------------------------

def test_just_inside_max_age_still_blocks():
    code = run(signal("diverged", age_hours=47.0,
                      regressions=[entry("KSI-RPL-ABO", ["versioning_disabled"])]))
    assert code == divgate.BLOCK


def test_just_outside_max_age_does_not_block():
    code = run(signal("diverged", age_hours=49.0,
                      regressions=[entry("KSI-RPL-ABO", ["versioning_disabled"])]))
    assert code == divgate.PASS


# --- untrusted-input handling (CodeGuard: log injection, SSRF scheme) -------

def test_workflow_command_injection_is_neutralised():
    """Signal fields are printed into GitHub Actions logs, which parse `::`.

    A field carrying CR/LF plus `::` could otherwise forge annotations or
    workflow commands from inside a log line the gate emits.
    """
    hostile = "KSI-X\n::error::forged\r::set-output name=x::y"
    _, lines = divgate.evaluate(
        signal("diverged", regressions=[entry(hostile, ["versioning_disabled"])]),
        48.0, now=NOW,
    )
    body = "\n".join(lines)
    assert "::error::" not in body
    assert "::set-output" not in body
    assert "\n::" not in body
    assert "KSI-X" in body  # still legible, just defanged


def test_untrusted_fields_are_length_bounded():
    _, lines = divgate.evaluate(
        signal("diverged", regressions=[entry("K" * 5000, ["r"])]), 48.0, now=NOW
    )
    assert max(len(x) for x in lines) < 600


def test_clean_handles_non_string_and_missing_values():
    assert divgate.clean(None) == "none"
    assert divgate.clean(17) == "17"
    assert divgate.clean({"a": 1})  # must not raise


def test_violation_ids_of_wrong_type_do_not_crash():
    _, lines = divgate.evaluate(
        signal("diverged", regressions=[{"ksi_id": "K", "violation_ids": "notalist"}]),
        48.0, now=NOW,
    )
    assert "DEPLOY BLOCKED" in "\n".join(lines)


def test_non_https_url_is_refused():
    """urllib honours file://; a gate deciding deploys must not read local files."""
    import pytest
    for bad in ("file:///etc/passwd", "http://example.com/s.json", "ftp://h/s.json"):
        with pytest.raises(ValueError, match="non-HTTPS"):
            divgate.fetch(bad, 1.0)


# --- age helper -------------------------------------------------------------

def test_age_hours_handles_naive_and_z_suffixed_timestamps():
    assert divgate.age_hours("2026-08-06T10:00:00Z", NOW) == 2.0
    assert divgate.age_hours("2026-08-06T10:00:00", NOW) == 2.0
    assert divgate.age_hours(None, NOW) is None
    assert divgate.age_hours("garbage", NOW) is None
