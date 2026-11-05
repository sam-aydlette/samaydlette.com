#!/usr/bin/env python3
"""Publication gate: no published artifact carries an AWS account ID, an IAM user name or a GitHub run ID.

Run immediately before a workflow uploads to /.well-known/, over the directory
the artifacts were built in:

    python3 ../scripts/check-published-redaction.py ksi-signal.json ...  # the workflows
    python3 ../scripts/check-published-redaction.py --root DIR  # a fetched copy

The workflows name exactly the files their upload step publishes, because their
working directories also hold live files they downloaded as inputs and do not
publish (the deploy reads the runtime signal, which the runtime Lambda
publishes). tests/test_published_redaction.py holds each list equal to its
upload step. With no file arguments it scans every artifact the governed freshness config lists (the set of files
this site publishes; tests/test_freshness_config.py fails if a workflow
publishes one that is not listed) that is present under --root, together with
its Markdown rendering. Signatures and provenance envelopes are Sigstore's
output, not ours, and the policy bundle is a compiled archive, so those are not
scanned. A file that is listed but absent is skipped: each workflow publishes
only its own subset, and the round-trip and freshness checks cover absence.

Any standalone twelve-digit number fails the run (exit 1). The number itself is
never printed: the message names the file, the count, and the text before each
match with digits masked. No file to scan at all is a misconfiguration and also
fails (exit 2), so a wrong --root cannot pass silently.

The redaction it enforces is applied by scripts/_redact.py in the inventory
builder; everything else published derives from that inventory.
"""

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _freshness  # noqa: E402
import _redact  # noqa: E402

NOT_SCANNED = (".intoto.jsonl", ".bundle", ".tar.gz")


def candidates(cfg, root):
    """The files under root to scan, in config order."""
    out = []
    for a in cfg["artifacts"]:
        name = Path(a["path"]).name
        if name.endswith(NOT_SCANNED):
            continue
        for n in (name, f"{Path(name).stem}.md" if name.endswith(".json") else None):
            if n and (root / n).is_file() and (root / n) not in out:
                out.append(root / n)
    return out


def violations(paths):
    """['<file>: N account ID(s) ...'] for every file that still carries one."""
    found = []
    for p in paths:
        text = p.read_text(encoding="utf-8", errors="replace")
        hits = list(_redact.ACCOUNT_ID.finditer(text))
        if hits:
            where = "; ".join(re.sub(r"[0-9]", "#", text[max(0, m.start() - 30):m.start()]).replace("\n", " ")
                              for m in hits[:3])
            found.append(f"{p.name}: {len(hits)} account ID(s), e.g. after '{where}'")
        runs = _redact.find_github_runs(text)
        if runs:
            found.append(f"{p.name}: {runs} GitHub run ID(s) or run URL(s)")
        users = _redact.find_iam_users(text)
        if users:
            found.append(f"{p.name}: {users} IAM user name(s) after 'aws-iam-user::'")
    return found


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=".", help="directory the artifacts were built in")
    ap.add_argument("--freshness-config", default=None, help="governed list of published artifacts")
    ap.add_argument("files", nargs="*", help="scan exactly these files instead (each must exist)")
    args = ap.parse_args(argv)

    if args.files:
        paths = [Path(f) for f in args.files]
        missing = [str(p) for p in paths if not p.is_file()]
        if missing:
            print(f"::error::publication redaction gate: not found: {missing}", file=sys.stderr)
            return 2
    else:
        paths = candidates(_freshness.load_freshness_config(args.freshness_config), Path(args.root))
    if not paths:
        print(f"::error::publication redaction gate: nothing to scan under {args.root}", file=sys.stderr)
        return 2
    bad = violations(paths)
    if bad:
        print(f"::error::publication redaction gate: {len(bad)} artifact(s) carry an AWS account ID, IAM user name or GitHub run ID; "
              "nothing is published (scripts/_redact.py)", file=sys.stderr)
        for b in bad:
            print(f"  ✗ {b}", file=sys.stderr)
        return 1
    print(f"publication redaction gate OK: {len(paths)} artifact(s) carry no AWS account ID, IAM user name or GitHub run ID")
    return 0


if __name__ == "__main__":
    sys.exit(main())
