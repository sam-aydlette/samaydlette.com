#!/usr/bin/env python3
"""Run the method's conformance tests and record the results (REQ-GOV-2).

data/method-profile.json names the profile version this pipeline conforms to,
and maps each conformance test of the method (Appendix B, T1-T74) to the pytest
tests that implement it, or records why none does:

    implemented      the mapped tests construct the scenario and assert its outcome
    partial          the mapped tests cover part of it; `reason` says what is missing
    not-implemented  no test yet; `reason` names the missing capability
    not-applicable   the scenario cannot arise in this system; `reason` says why

This runs every mapped test once and writes conformance-results.json: per test
ID, its declared coverage and whether its tests passed. The deploy signs and
publishes it, and every VDR-family output names the profile version and the
sha256 of the results it was built under.

Fails closed: an invalid profile, a mapped test that does not exist, or a mapped
test that fails stops the build.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET  # noqa: S405 (parses pytest's own junit output, written locally)
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _offering  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
DEFAULT_PROFILE = REPO / "data" / "method-profile.json"
IDS = [f"T{i}" for i in range(1, 75)]
STATUSES = ("implemented", "partial", "not-implemented", "not-applicable")
NODE_RE = re.compile(r"^tests/[A-Za-z0-9_/]+\.py::[A-Za-z_][A-Za-z0-9_]*$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _fail(msg):
    raise SystemExit(f"::error::method profile: {msg} (fail-closed, REQ-GOV-2)")


def load_profile(path=None):
    p = Path(path or DEFAULT_PROFILE)
    if not p.is_file():
        _fail(f"{p} not found")
    raw = p.read_bytes()
    try:
        prof = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _fail(f"{p} is not valid JSON: {exc}")
    for key in ("profile_version", "decided_by"):
        if not isinstance(prof.get(key), str) or not prof[key].strip():
            _fail(f"{key} must be a non-empty string")
    for key in ("decided_on", "review_by"):
        if not isinstance(prof.get(key), str) or not DATE_RE.match(prof[key]):
            _fail(f"{key} must be an ISO date")
    method = prof.get("method") or {}
    if not isinstance(method.get("path"), str) or not (REPO / method["path"]).is_file():
        _fail("method.path must name the published method in this repository")
    tests = prof.get("tests")
    if not isinstance(tests, dict) or sorted(tests, key=lambda t: int(t[1:])) != IDS:
        _fail(f"tests must map exactly {IDS[0]}..{IDS[-1]}")
    for tid, t in tests.items():
        if not isinstance(t, dict) or t.get("status") not in STATUSES:
            _fail(f"{tid}: status must be one of {list(STATUSES)}")
        nodes = t.get("pytest") or []
        if not isinstance(nodes, list) or any(not isinstance(n, str) or not NODE_RE.match(n) for n in nodes):
            _fail(f"{tid}: pytest must be a list of tests/<file>.py::<function> node IDs")
        if t["status"] in ("implemented", "partial") and not nodes:
            _fail(f"{tid}: {t['status']} needs at least one pytest node")
        if t["status"] in ("not-implemented", "not-applicable") and nodes:
            _fail(f"{tid}: {t['status']} cannot list tests")
        if t["status"] != "implemented" and not (isinstance(t.get("reason"), str) and t["reason"].strip()):
            _fail(f"{tid}: {t['status']} needs a reason")
    prof["sha256"] = hashlib.sha256(raw).hexdigest()
    return prof


def run_pytest(nodes, junit):
    """Run the nodes once; returns {node: 'passed'|'failed'} for every node pytest ran."""
    cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--junitxml={junit}", *nodes]
    proc = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)  # noqa: S603 (fixed argv, no shell)
    if proc.returncode not in (0, 1):
        tail = (proc.stdout + proc.stderr).strip().splitlines()[-15:]
        _fail("pytest could not run the mapped tests (a mapped test is missing or does not import):\n  "
              + "\n  ".join(tail))
    outcome = {}
    for case in ET.parse(junit).getroot().iter("testcase"):  # noqa: S314 (local pytest output)
        file = case.get("classname", "").replace(".", "/") + ".py"
        name = re.sub(r"\[.*\]$", "", case.get("name", ""))
        node = f"{file}::{name}"
        failed = any(child.tag in ("failure", "error") for child in case)
        skipped = any(child.tag == "skipped" for child in case)
        state = "failed" if failed else ("skipped" if skipped else "passed")
        prior = outcome.get(node)
        # A parametrized test passes only if every case passed.
        outcome[node] = "failed" if "failed" in (prior, state) else ("skipped" if "skipped" in (prior, state) else state)
    return outcome


def build(profile, outcome, commit, now):
    rows, counts = [], {s: 0 for s in STATUSES}
    counts.update({"passed": 0, "failed": 0})
    missing = []
    for tid in IDS:
        t = profile["tests"][tid]
        counts[t["status"]] += 1
        nodes = t.get("pytest") or []
        results = {n: outcome.get(n) for n in nodes}
        missing += [n for n, r in results.items() if r is None]
        result = None
        if nodes:
            result = "failed" if any(r != "passed" for r in results.values()) else "passed"
            counts[result] += 1
        rows.append({"id": tid, "coverage": t["status"], "result": result,
                     "tests": [{"node": n, "result": r} for n, r in results.items()],
                     "reason": t.get("reason")})
    method_path = REPO / profile["method"]["path"]
    doc = {
        "schema": "conformance-results/1",
        "profile_version": profile["profile_version"],
        "profile_sha256": profile["sha256"],
        "method": {"path": profile["method"]["path"],
                   "sha256": hashlib.sha256(method_path.read_bytes()).hexdigest(),
                   "appendix": profile["method"].get("appendix", "B")},
        "commit": commit,
        "generated_at": now.replace(microsecond=0).isoformat(),
        "summary": counts,
        "tests": rows,
    }
    return doc, sorted(set(missing))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", default=None)
    ap.add_argument("--output", default="conformance-results.json")
    ap.add_argument("--commit", default=os.environ.get("GITHUB_SHA", "unknown"))
    args = ap.parse_args(argv)

    profile = load_profile(args.profile)
    nodes = sorted({n for t in profile["tests"].values() for n in t.get("pytest") or []})
    with tempfile.TemporaryDirectory() as tmp:
        outcome = run_pytest(nodes, Path(tmp) / "junit.xml") if nodes else {}
    doc, missing = build(profile, outcome, args.commit, datetime.now(timezone.utc))
    if missing:
        _fail(f"mapped tests that pytest did not run: {missing}")
    doc = _offering.stamp_fedramp_id(doc)  # CDS-CSO-FID
    Path(args.output).write_text(json.dumps(doc, indent=2) + "\n")
    s = doc["summary"]
    print(f"conformance ({doc['profile_version']}): {s['implemented']} implemented, {s['partial']} partial, "
          f"{s['not-implemented']} not implemented, {s['not-applicable']} not applicable; "
          f"{s['passed']} passed, {s['failed']} failed")
    failed = [r["id"] for r in doc["tests"] if r["result"] == "failed"]
    if failed:
        print(f"::error::conformance tests failed: {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
