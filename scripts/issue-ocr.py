#!/usr/bin/env python3
"""Issue the quarterly Ongoing Certification Report (CCM-OCR-AVL, CDS-CSO-HAD).

The deploy runs this twice:

    issue-ocr.py plan   --index ocr-issues.json
        Before the OCR and CPO are built. The index is the published one, its
        signature already verified by the workflow, or absent before the first
        issue. When the earliest due date on the calendar (data/ocr-calendar.json)
        with no issue has passed, a new issue is added for it: its period runs
        from the end of the last issue to today, and an issue made after its due
        date records how many days late it is. The OCR and the CPO are then built
        from this index, so this run's OCR is the issued report and the next dates
        move on. The index is always rewritten with this run's emitted_at.

    issue-ocr.py check --index ocr-issues.json --root <dir>
        For a verifier (scripts/verify-published.sh): every file each issue
        lists is under <dir>/<id>/ with the SHA-256 the index records.

    issue-ocr.py freeze --index ocr-issues.json --root . --out ocr
        After the package is built and signed. Copies the files of the package
        the CPO lists (and the CPO, the Markdown renderings and every signature)
        into <out>/<id>/ for the issue `plan` added, and records each file's
        SHA-256 in the index. Prints the issue's ID, or nothing when this run
        issues nothing. The publish step uploads <out>/<id>/ only when nothing is
        published under that prefix yet: an issued snapshot is never replaced.

Stdlib only, fail-closed.
"""

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _ocr_calendar  # noqa: E402
from _common import commit as _commit, fedramp_id, sha256_file  # noqa: E402

BASE = "https://samaydlette.com/.well-known/"
INDEX = "ocr-issues.json"
ALWAYS = ["certification-package-overview.json", "certification-package-overview.md",
          "ongoing-certification-report.md"]


def _fail(msg):
    raise SystemExit(f"::error::OCR issue: {msg} (fail-closed)")


def _load_index(path):
    """The index as published (validated), or a new empty one."""
    issued = _ocr_calendar.load_issued(path)
    if not issued and not Path(path).exists():
        return {"schema": "ocr-issues/1", "issues": []}
    return json.loads(Path(path).read_text())


def plan(index, cal, now, commit=None):
    """Add the due issue to the index, if one is due. Returns the new issue or None."""
    today = now.date()
    issues = index["issues"]
    if any(i.get("files") is None for i in issues):
        _fail("the index already holds an issue with no frozen files")
    target, _ = _ocr_calendar.next_report(cal, issues, today)
    new = None
    if target <= today:
        new = {"id": _ocr_calendar.issue_id(target), "due": target.isoformat(), "issued_on": today.isoformat(),
               "days_late": (today - target).days,
               "period_from": _ocr_calendar.period_start(cal, issues, today).isoformat(),
               "period_to": today.isoformat(), "commit": commit,
               "path": f".well-known/ocr/{_ocr_calendar.issue_id(target)}/", "files": None}
        if any(i["id"] == new["id"] for i in issues):
            _fail(f"issue {new['id']} is already in the index")
        issues.append(new)
    index.update({"fedramp_id": fedramp_id(), "emitted_at": now.isoformat(),
                  "calendar": {k: cal[k] for k in ("issue_dates", "review_business_days", "decided_by",
                                                   "decided_on")},
                  "issues": issues})
    return new


def snapshot_files(root):
    """The files one issue freezes: the package the CPO lists, the CPO, the
    Markdown renderings and every JSON file's signature."""
    cpo = json.loads((root / "certification-package-overview.json").read_text())
    listed = [r["url"][len(BASE):] for r in cpo["serviceProperties"]["additionalRepositories"]
              if r["url"].startswith(BASE)]
    names = [n for n in listed if n != INDEX] + ALWAYS
    names += [n[:-len(".json")] + ".bundle" for n in names if n.endswith(".json")]
    return sorted(set(names))


def freeze(index, root, out):
    pending = [i for i in index["issues"] if i.get("files") is None]
    if not pending:
        return None
    if len(pending) > 1:
        _fail("more than one issue has no frozen files")
    issue = pending[0]
    dest = out / issue["id"]
    if dest.exists() and any(dest.iterdir()):
        _fail(f"{dest} already holds files")
    names = snapshot_files(root)
    missing = [n for n in names if not (root / n).is_file()]
    if missing:
        _fail(f"the package files to freeze are missing: {', '.join(missing)}")
    dest.mkdir(parents=True, exist_ok=True)
    issue["files"] = {}
    for n in names:
        shutil.copyfile(root / n, dest / n)
        issue["files"][n] = sha256_file(dest / n)
    return issue["id"]


def check(index, root):
    """Every file an issue lists is in <root>/<id>/ with the SHA-256 the index
    records. Returns a list of problems; an index with no issues has none."""
    problems = []
    for i in index["issues"]:
        if not i.get("files"):
            problems.append(f"issue {i['id']} lists no frozen files")
            continue
        for name, digest in i["files"].items():
            f = Path(root) / i["id"] / name
            if not f.is_file():
                problems.append(f"{i['id']}/{name} is not published")
            elif sha256_file(f) != digest:
                problems.append(f"{i['id']}/{name} differs from the SHA-256 the index records")
    return problems


def _write(index, path):
    Path(path).write_text(json.dumps(index, indent=2) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan")
    p.add_argument("--index", default=INDEX)
    f = sub.add_parser("freeze")
    f.add_argument("--index", default=INDEX)
    f.add_argument("--root", default=".")
    f.add_argument("--out", default="ocr")
    c = sub.add_parser("check")
    c.add_argument("--index", default=INDEX)
    c.add_argument("--root", default="ocr")
    a = ap.parse_args(argv)

    index = _load_index(a.index)
    if a.cmd == "check":
        problems = check(index, a.root)
        for p in problems:
            print(p, file=sys.stderr)
        n = sum(len(i.get("files") or {}) for i in index["issues"])
        if not problems:
            print(f"{len(index['issues'])} issued report(s), {n} frozen files, each matches the signed index")
        return 1 if problems else 0
    if a.cmd == "plan":
        new = plan(index, _ocr_calendar.load(), datetime.now(timezone.utc), _commit())
        _write(index, a.index)
        print(f"ocr issue: {new['id']} due {new['due']}, issued {new['issued_on']} ({new['days_late']} days late)"
              if new else "ocr issue: none due", file=sys.stderr)
        return 0
    issued = freeze(index, Path(a.root), Path(a.out))
    _write(index, a.index)
    if issued:
        print(issued)
    return 0


if __name__ == "__main__":
    sys.exit(main())
