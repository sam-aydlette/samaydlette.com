#!/usr/bin/env python3
"""Ban Rego constructs known to diverge between the Go and Wasm evaluators.

One Rego source serves two enforcement points: the deploy gate (OPA CLI, Go
builtins) and the runtime Lambda (Wasm, with some builtins delegated to a
JavaScript host). The parity test (scripts/policy-parity-test.js) catches
divergence the fixture corpus exercises; this check prevents the known
offenders from entering the policy tree at all, exercised or not:

  - sprintf %q       — sprintf-js (the opa-wasm host) rejects the verb and
                       THROWS at runtime in the Lambda.
  - sprintf %v       — renders Rego sets/composites differently in the Go
                       runtime vs the JS host (found live by the parity
                       test). Format sets explicitly (concat + sort).
  - time.now_ns(     — makes evaluation host/time-dependent; the pipeline
                       supplies data.runtime.evaluated_at instead, keeping
                       Wasm evaluation deterministic.

Comment lines are ignored so the ban can be documented next to the code.
"""

import re
import sys
from pathlib import Path

POLICY_DIR = Path(__file__).resolve().parent.parent / "infrastructure" / "policy"

BANNED = [
    (re.compile(r"%q"), "sprintf %q throws in the opa-wasm JS host"),
    (re.compile(r"%v"), "sprintf %v renders sets differently under Wasm; join explicitly"),
    (re.compile(r"time\.now_ns\s*\("), "use data.runtime.evaluated_at, not host time"),
]


def main():
    findings = []
    for path in sorted(POLICY_DIR.rglob("*.rego")):
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            for pattern, why in BANNED:
                if pattern.search(line):
                    findings.append(f"{path.relative_to(POLICY_DIR.parent.parent)}:{lineno}: {why}\n    {line.strip()}")

    if findings:
        print("Wasm-unsafe constructs in the policy tree:", file=sys.stderr)
        for f in findings:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print("OK: no Wasm-divergent builtin usage in infrastructure/policy/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
