#!/usr/bin/env python3
"""Keep the AWS account ID out of everything this site publishes.

An AWS account ID is a twelve-digit number. It is not a secret, but it is the
first thing an attacker needs to target an account (role-assumption probes,
resource-policy enumeration), and nothing a reader of the published evidence
needs. The published inventory used to carry it in every ARN and in a few
configuration values; the boundary map already refused it.

One rule, used on both sides of every comparison:

  * `redact` replaces every standalone twelve-digit number in a string, or in
    every string (and key) of a JSON document, with ACCOUNT. An ARN keeps its
    shape: arn:aws:lambda:us-east-2:ACCOUNT:function:name.
  * `find` reports the twelve-digit numbers left in a text, for the publication
    gate (scripts/check-published-redaction.py).

Consumers that hold AWS credentials (reconcile's live invariants, the boundary
map's Terraform state, the operator's corroboration) redact what they read
with the same function before comparing it with the published inventory, so a
comparison is exact modulo the account and nothing else. The runtime Lambda
fills its own account back in where it needs a callable ARN.

The pattern is the one reconcile (l) and the boundary-map builder already use:
twelve digits not preceded or followed by a letter or a digit. Stdlib only.
"""

import re
import sys

ACCOUNT_ID = re.compile(r"(?<![0-9A-Za-z])[0-9]{12}(?![0-9A-Za-z])")
PLACEHOLDER = "ACCOUNT"


def redact_text(text):
    """`text` with every standalone twelve-digit number replaced by ACCOUNT."""
    return ACCOUNT_ID.sub(PLACEHOLDER, text)


def redact(value):
    """A copy of a JSON value with every string and every object key redacted.
    Numbers are left alone: an account ID is a string in every AWS API and in
    Terraform state, and the publication gate still fails on a numeric one."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {redact_text(k) if isinstance(k, str) else k: redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def find(text):
    """The twelve-digit numbers in `text`, in order (empty when clean)."""
    return ACCOUNT_ID.findall(text)


def main(argv):
    """`_redact.py FILE...`: redact each JSON file in place. For outputs that must
    always publish (the nightly status beacon) and so cannot be gated, but can
    carry text from a failed AWS call ("User: arn:aws:sts::<account>:...")."""
    import json
    from pathlib import Path
    if not argv:
        print("usage: _redact.py FILE...", file=sys.stderr)
        return 2
    for f in argv:
        p = Path(f)
        p.write_text(json.dumps(redact(json.loads(p.read_text())), indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
