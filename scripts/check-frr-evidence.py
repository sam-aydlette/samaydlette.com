#!/usr/bin/env python3
"""Every test a FedRAMP rule record cites ran and passed (FRC-CSX-VVR).

scripts/_frr.py shows that each piece of evidence a rule record cites exists.
This shows the cited tests passed in this build: it reads the JUnit XML that the
unit-test job's pytest run wrote and fails when a test cited as evidence failed,
errored, was skipped, or did not run at all. A parametrized test passes only
when every one of its cases ran and passed.

It writes the result per record (frr-evidence.json), which the deploy signs and
publishes beside the Security Decision Record, so a reader can see that each
record's tests, and each Simulated record's stand-in proof tests, passed in the
build that published it.

    python3 scripts/check-frr-evidence.py --junit pytest-results.xml --output frr-evidence.json
"""

import argparse
import json
import sys
import xml.etree.ElementTree as ET  # nosec B405: parses the JUnit file this job's own pytest wrote
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _frr  # noqa: E402
import _offering  # noqa: E402

SCHEMA = "frr-evidence/1"


def _fail(msg):
    raise SystemExit(f"::error::FRR evidence: {msg} (fail-closed)")


def junit_outcomes(path):
    """{(module path, class or None, function): [outcome per case]} from a JUnit XML file."""
    try:
        root = ET.parse(path).getroot()  # nosec B314: trusted, locally generated file
    except (OSError, ET.ParseError) as exc:
        _fail(f"cannot read the test results {path}: {exc}")
    out = {}
    for case in root.iter("testcase"):
        classname, name = case.get("classname", ""), case.get("name", "")
        parts = classname.split(".")
        # classname is "tests.test_x" or "tests.test_x.TestClass"
        if len(parts) >= 2 and parts[-1][:1].isupper():
            module, cls = "/".join(parts[:-1]) + ".py", parts[-1]
        else:
            module, cls = "/".join(parts) + ".py", None
        func = name.split("[", 1)[0]
        if case.find("failure") is not None or case.find("error") is not None:
            outcome = "failed"
        elif case.find("skipped") is not None:
            outcome = "skipped"
        else:
            outcome = "passed"
        out.setdefault((module, cls, func), []).append(outcome)
    if not out:
        _fail(f"{path} records no test cases")
    return out


def _key(ref):
    m = _frr.TEST_RE.match(ref)
    if not m:
        _fail(f"{ref!r} is not a test reference")
    rel, first, second = m.groups()
    return (rel, first, second) if second else (rel, None, first)


def test_result(ref, outcomes):
    cases = outcomes.get(_key(ref))
    if not cases:
        return "not run"
    if all(c == "passed" for c in cases):
        return "passed"
    return "failed" if "failed" in cases else "skipped"


def evaluate(records, outcomes):
    """(per-record results, list of failures)."""
    per, failures = {}, []
    for r in records["records"]:
        refs = [e["ref"] for e in r.get("evidence", []) if e["kind"] == "test"]
        proof = r.get("stand_in_proof")
        if proof:  # a Simulated record's stand-in proof is cited like evidence
            refs += [proof["bad_input"]] + ([proof["replaceable"]["test"]] if proof["replaceable"].get("test") else [])
        tests = {ref: test_result(ref, outcomes) for ref in refs}
        for ref, res in tests.items():
            if res != "passed":
                failures.append(f"{r['frr_id']}: cited test {ref} {res}")
        per[r["frr_id"]] = {"status": r["status"], "tests": tests,
                            "result": "pass" if all(v == "passed" for v in tests.values()) else "fail"}
    return per, failures


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--junit", required=True)
    ap.add_argument("--records", default=str(_frr.DEFAULT_PATH))
    ap.add_argument("--output", default="frr-evidence.json")
    ap.add_argument("--commit", default=None)
    a = ap.parse_args(argv)
    records = _frr.load(a.records)
    per, failures = evaluate(records, junit_outcomes(a.junit))
    cited = sum(len(v["tests"]) for v in per.values())
    doc = {"schema": SCHEMA, "fedRampId": _offering.fedramp_id(), "generated_at": datetime.now(timezone.utc).isoformat(), "commit": a.commit,
           "explanation": "Each FedRAMP rule record's cited tests and whether they passed in the unit-test run "
                          "of the build that published this file (scripts/check-frr-evidence.py). The build "
                          "fails when any cited test fails, errors, is skipped or does not run.",
           "summary": {"records": len(per), "cited_tests": cited,
                       "records_with_tests": sum(1 for v in per.values() if v["tests"])},
           "records": per}
    if failures:
        for f in failures:
            print(f"::error::{f}")
        _fail(f"{len(failures)} cited test(s) did not pass")
    Path(a.output).write_text(json.dumps(doc, indent=2) + "\n")
    print(f"frr-evidence: {cited} cited tests across {doc['summary']['records_with_tests']} records, all passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
