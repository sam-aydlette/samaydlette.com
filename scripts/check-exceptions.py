#!/usr/bin/env python3
"""Validate the exceptions-as-code register and fail CI on expired entries.

infrastructure/policy/exceptions/data.json is the machine-readable register
of accepted findings (POA&M-as-code; see docs/poam.md). Every entry must
carry: resource, rule_id, justification, expiry (YYYY-MM-DD), ticket. An
entry past its expiry no longer suppresses anything at eval time (the policy
is fail-safe), and this script additionally FAILS CI so the register cannot
silently accumulate dead entries — an expired exception must be renewed with
a fresh review or deleted.
"""

import datetime
import json
import sys
from pathlib import Path

REGISTER = Path(__file__).resolve().parent.parent / "infrastructure" / "policy" / "exceptions" / "data.json"
REQUIRED_FIELDS = ("resource", "rule_id", "justification", "expiry", "ticket")


def main():
    entries = json.loads(REGISTER.read_text())
    if not isinstance(entries, list):
        print(f"ERROR: {REGISTER} must contain a JSON array", file=sys.stderr)
        return 1

    today = datetime.date.today()
    errors = []
    for i, entry in enumerate(entries):
        where = f"exceptions[{i}] ({entry.get('rule_id', '?')}/{entry.get('resource', '?')})"
        for field in REQUIRED_FIELDS:
            if not entry.get(field):
                errors.append(f"{where}: missing required field '{field}'")
        expiry_raw = entry.get("expiry")
        if expiry_raw:
            try:
                expiry = datetime.date.fromisoformat(expiry_raw)
            except ValueError:
                errors.append(f"{where}: expiry '{expiry_raw}' is not YYYY-MM-DD")
                continue
            if expiry <= today:
                errors.append(
                    f"{where}: expired on {expiry} — renew with a fresh review "
                    "or delete the entry (justification: "
                    f"{entry.get('justification', '')[:60]}...)"
                )

    if errors:
        print("Exception register problems:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"OK: {len(entries)} exception(s), none expired, all fields present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
