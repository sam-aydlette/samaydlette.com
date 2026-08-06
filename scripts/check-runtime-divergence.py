#!/usr/bin/env python3
# =============================================================================
# RUNTIME DIVERGENCE PRE-FLIGHT GATE  ("stop the line")
# =============================================================================
# The deploy gate evaluates a Terraform plan; the runtime Lambda re-evaluates
# the live account daily. Both run the same compiled policy, so a disagreement
# is a real signal — and until this gate existed it was published on both sides
# and read by neither.
#
# This is the ANDON CORD, not an autopilot. It refuses to start a new deploy
# while the currently-deployed system is diverged, so a human decides what to
# do. It never reverts anything: the worst case is a blocked deploy, never a
# mutated production system.
#
# POSITION IN THE PIPELINE: this runs BEFORE `terraform apply`. The
# reconciliation gate (scripts/reconcile.py) runs after apply and before
# publish, and checks a different thing — that the generated artifacts agree
# with each other and with live reality. Stopping the line has to happen before
# anything is mutated, so it cannot live in reconcile.
#
# WHAT BLOCKS AND WHAT DOES NOT
#
#   status=diverged  -> BLOCK. A KSI the deploy gate published as PASSING is
#                       failing against the live account. Someone should look
#                       before layering another change on top.
#   status=degraded  -> WARN.  The runtime evaluator could not reach a verdict
#                       (a category:input violation such as resource_read_error
#                       — a missing IAM grant, an unreadable resource). That is
#                       a fault in the OBSERVER, not evidence of drift, and
#                       blocking deploys on it is how this pipeline would have
#                       wedged itself for the four weeks it published exactly
#                       that condition. It is loud, and it never blocks.
#   status=converged -> PASS.
#
# DELIBERATE FAIL-OPEN ON AVAILABILITY, FAIL-CLOSED ON VERDICT
#
# A signal that is missing, unfetchable, or carries no `divergence` block does
# NOT block the deploy; it warns. Two reasons, both load-bearing:
#
#   1. Rollout. The published runtime signal carries no `divergence` block
#      until the Lambda that emits it has itself been deployed. A gate that
#      blocked on its absence would refuse the very deploy that installs it.
#   2. Deadlock. This gate can only be cleared by a deploy. If a transient
#      network failure could wedge it shut, the gate would create a worse
#      failure mode than the one it prevents — and the escape hatch would be
#      needed routinely rather than exceptionally.
#
# The VERDICT still fails closed: a signal that is present, fresh, and diverged
# blocks, and no amount of retrying changes that. Only --allow-divergence does,
# and it is recorded in the log.
#
# REPLAY RESISTANCE: `emitted_at` lives inside the signed payload, so a replayed
# older signal fails the staleness check rather than passing as fresh. This
# script does not verify the KMS signature itself (that needs `cryptography`,
# which the deploy job does not install; the recipe lives in
# tests/test_runtime_signature.py). Scope is honest: transport is HTTPS from our
# own distribution, and freshness is checked against signed content.
#
# Usage:
#   check-runtime-divergence.py                       # default published URL
#   check-runtime-divergence.py --max-age-hours 48
#   check-runtime-divergence.py --allow-divergence "fixing forward: POAM-0xx"
# =============================================================================

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

DEFAULT_URL = "https://samaydlette.com/.well-known/ksi-signal-runtime.json"

BLOCK = 1
PASS = 0

# Every value below is interpolated from a document fetched over the network,
# then printed into GitHub Actions logs. Actions parses `::` command syntax out
# of a job's stdout, so an unsanitized field carrying CR/LF plus `::` could
# forge workflow commands or annotations from inside a log line. The signal
# comes from our own bucket over TLS, so this is defense in depth rather than a
# live exposure — but a gate that decides whether a deploy proceeds should not
# be the thing that trusts remote text verbatim.
_SANITIZE = str.maketrans({"\r": " ", "\n": " ", "\x00": ""})
_MAX_FIELD = 200


def clean(value):
    """Render an untrusted field safe to print into a CI log line."""
    if value is None:
        return "none"
    text = str(value).translate(_SANITIZE).replace("::", ":")
    return text[:_MAX_FIELD] + ("…" if len(text) > _MAX_FIELD else "")


def warn(msg):
    """Emit a GitHub Actions warning annotation that is also readable locally."""
    print(f"::warning::divergence-gate: {msg}", file=sys.stderr)


def fetch(url, timeout):
    # urllib honours file:// and ftp:// as readily as https://. This URL is
    # operator-supplied rather than user-supplied, but an unrestricted scheme
    # turns a --url typo (or anyone who can edit the workflow) into a local
    # file read whose contents decide whether a deploy proceeds. Allow-list the
    # one scheme this gate has any business fetching.
    if not url.lower().startswith("https://"):
        raise ValueError(f"refusing to fetch a non-HTTPS runtime signal URL: {url!r}")
    req = urllib.request.Request(url, headers={"Cache-Control": "no-cache"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (scheme checked above)
        return json.loads(r.read().decode("utf-8"))


def age_hours(emitted_at, now=None):
    """Hours since `emitted_at`, or None if it is absent/unparseable."""
    if not emitted_at:
        return None
    try:
        ts = datetime.fromisoformat(str(emitted_at).replace("Z", "+00:00"))
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ((now or datetime.now(timezone.utc)) - ts).total_seconds() / 3600.0


def rules_of(entry):
    ids = entry.get("violation_ids")
    return "/".join(clean(i) for i in ids) if isinstance(ids, list) and ids else "?"


def describe(entries):
    return ", ".join(
        f"{clean(e.get('ksi_id'))} [{rules_of(e)}]" for e in entries
    )


def evaluate(signal, max_age_hours, now=None):
    """Return (exit_code, lines_to_print). Pure, so the tests can drive it."""
    out = []
    div = signal.get("divergence")
    if not isinstance(div, dict):
        warn(
            "published runtime signal carries no `divergence` block; the emitter "
            "that produces it has not been deployed yet. Not blocking."
        )
        return PASS, out

    status = div.get("status")
    against = div.get("compared_against") or {}
    age = age_hours(signal.get("emitted_at"), now)

    out.append(
        f"runtime signal emitted_at={clean(signal.get('emitted_at'))} "
        f"({'age unknown' if age is None else f'{age:.1f}h old'}); "
        f"status={clean(status)}; compared against deploy signal "
        f"{clean(against.get('signal_id'))} @ commit {clean(against.get('commit'))}"
    )

    stale = age is None or age > max_age_hours
    if stale:
        warn(
            f"runtime signal is stale or undateable "
            f"({'no parseable emitted_at' if age is None else f'{age:.1f}h > {max_age_hours}h'}). "
            "The daily evaluation may not be running, so this gate is not "
            "currently protecting anything. Not blocking."
        )

    if status == "diverged":
        regressions = div.get("regressions") or []
        # A stale signal cannot be used to block: it describes a system state
        # that may be hours or days out of date, and the operator has no way to
        # clear it except by deploying.
        if stale:
            warn(
                f"divergence reported ({describe(regressions)}) but the signal is "
                "stale; not blocking on an out-of-date verdict. Check the dashboard."
            )
            return PASS, out
        out.append("")
        out.append("DEPLOY BLOCKED — the live system disagrees with its published compliance state.")
        out.append("")
        out.append(f"  {len(regressions)} KSI(s) published as PASSING at deploy time are FAILING at runtime:")
        for e in regressions:
            out.append(
                f"    - {clean(e.get('ksi_id'))}: deploy={clean(e.get('deploy_status'))} "
                f"runtime={clean(e.get('runtime_status'))} "
                f"rules={rules_of(e)}"
            )
        out.append("")
        out.append("  This is drift in the deployed system, not an evaluator fault.")
        out.append("  Investigate before layering another change on top.")
        out.append("")
        out.append("  To deploy anyway (e.g. this deploy IS the fix):")
        out.append('    check-runtime-divergence.py --allow-divergence "<reason>"')
        return BLOCK, out

    if status == "degraded":
        unassessed = div.get("unassessed") or []
        unattributed = div.get("unattributed_failures") or 0
        warn(
            "runtime evaluation is DEGRADED — the evaluator could not reach a "
            f"verdict on {len(unassessed)} KSI(s)"
            + (f" plus {unattributed} unattributed failure(s)" if unattributed else "")
            + f". {describe(unassessed)}. "
            "This is an observer fault (check the evaluator's permissions), not "
            "drift, so it does not block. It does mean the gate is only partly "
            "protecting this deploy."
        )
        return PASS, out

    if status != "converged":
        warn(f"unrecognized divergence status '{clean(status)}'; treating as non-blocking.")
        return PASS, out

    out.append("Runtime evaluation agrees with the published deploy-time verdict.")
    return PASS, out


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--url", default=DEFAULT_URL,
                    help="published runtime signal to read (default: %(default)s)")
    ap.add_argument("--signal", default=None,
                    help="read a local signal file instead of fetching (tests)")
    ap.add_argument("--max-age-hours", type=float, default=48.0,
                    help="older than this and the verdict is too stale to block on")
    ap.add_argument("--timeout", type=float, default=15.0, help="fetch timeout in seconds")
    ap.add_argument("--allow-divergence", metavar="REASON", default=None,
                    help="break-glass: proceed despite divergence, recording REASON")
    a = ap.parse_args()

    if a.signal:
        signal = json.loads(open(a.signal).read())
    else:
        try:
            signal = fetch(a.url, a.timeout)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
            warn(
                f"could not read the published runtime signal ({type(e).__name__}). "
                "Availability failures do not block deploys — see the header of "
                "this script. Not blocking."
            )
            return PASS

    code, lines = evaluate(signal, a.max_age_hours)
    for line in lines:
        print(line, file=sys.stderr if code == BLOCK else sys.stdout)

    if code == BLOCK and a.allow_divergence:
        print("", file=sys.stderr)
        warn(
            f"BREAK-GLASS: proceeding despite divergence. Reason: {clean(a.allow_divergence)}"
        )
        return PASS
    return code


if __name__ == "__main__":
    sys.exit(main())
