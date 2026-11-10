#!/usr/bin/env python3
"""Security impact analysis: classify a change for SCN-CSO-EVA.

Every pull request answers the questions in data/sia-questions.json in a block
in its description:

    SIA:
    - category: dependency-update
    - pipeline: no (bumps an action already in use)
    - access: yes

A question whose triggers match the diff (a changed path, or a changed line in
a security-relevant file) must be answered, and a "no" must give a reason in
brackets. Questions not answered and not triggered count as "no". The outcome
follows SCN-CSO-EVA's order:

    any class-change yes     -> class-change: fails; it needs a new assessment
    any transformative yes   -> transformative
    any adaptive yes         -> adaptive
    all no, recurring category            -> routine-recurring
    all no, no security-relevant path     -> not-significant
    all no, otherwise                     -> adaptive

The `SCN-Type:` line must equal the outcome. It may be left out only when the
outcome is routine-recurring or not-significant (docs/policies/cm-policy.md).
`SCN-Type: emergency` is accepted with a warning (SCN-CSO-EMG).

A Dependabot pull request that changes only dependency manifests, lock files
and workflow `uses:` lines is answered by this script: dependency-update, with
every triggered question "no (automated version change only)". Anything else
in it must be answered by a person, by editing the description.

    sia.py --base BASE_SHA --head HEAD_SHA [--author LOGIN]   # body in $PR_BODY

Prints the evaluation (also to $GITHUB_STEP_SUMMARY when set). Exit 1 when the
analysis is incomplete or disagrees with the declared type. Stdlib only,
fail-closed.
"""

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
QUESTIONS = REPO / "data" / "sia-questions.json"
OUTCOMES = ("not-significant", "routine-recurring", "adaptive", "transformative", "class-change")
RANK = {o: i for i, o in enumerate(OUTCOMES)}
TAGS = set(OUTCOMES) - {"class-change"} | {"emergency"}
TAG_RE = re.compile(r"^\s*#{0,2}\s*SCN-Type:\s*(\S*)", re.I | re.M)
ANSWER_RE = re.compile(r"^\s*[-*]\s*([a-z][a-z0-9-]*)\s*:\s*(yes|no)\b\s*(.*)$", re.I)
CATEGORY_RE = re.compile(r"^\s*[-*]\s*category\s*:\s*(\S+)\s*$", re.I)
COMMENT_RE = re.compile(r"^[+-]\s*(#|//|/\*|\*)")
DEPENDABOT = "dependabot[bot]"
MANIFESTS = ("package.json", "package-lock.json", "requirements*.txt", ".terraform.lock.hcl", "pyproject.toml",
             "poetry.lock", "uv.lock", "go.mod", "go.sum", "Gemfile.lock", "Dockerfile")


class SIAError(SystemExit):
    pass


def _fail(msg):
    raise SIAError(f"::error::sia: {msg} (fail-closed)")


def load_questions(path=QUESTIONS):
    try:
        doc = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        _fail(f"cannot read {path}: {exc}")
    for k in ("questions", "recurring_categories", "security_relevant_paths", "line_scan_paths", "decided_by", "decided_on",
              "review_by"):
        if k not in doc:
            _fail(f"{path} has no {k}")
    seen = set()
    for q in doc["questions"]:
        qid = q.get("id")
        if not isinstance(qid, str) or not re.fullmatch(r"[a-z][a-z0-9-]*", qid) or qid in seen or qid == "category":
            _fail(f"bad or duplicate question id {qid!r}")
        seen.add(qid)
        if q.get("outcome") not in OUTCOMES[2:]:
            _fail(f"{qid}: outcome must be one of {list(OUTCOMES[2:])}")
        if not isinstance(q.get("question"), str) or not q["question"].strip():
            _fail(f"{qid}: no question text")
        trig = q.get("triggers", {})
        if set(trig) - {"paths", "diff"}:
            _fail(f"{qid}: unknown trigger kind(s) {sorted(set(trig) - {'paths', 'diff'})}")
        for rx in trig.get("diff", []):
            try:
                re.compile(rx)
            except re.error as exc:
                _fail(f"{qid}: bad pattern {rx!r}: {exc}")
    return doc


def _match(path, globs):
    return any(fnmatch.fnmatch(path, g) or path == g or (g.endswith("/") and path.startswith(g)) for g in globs)


def triggered(doc, changes):
    """{question id: [why]} for each question the diff triggers. `changes` maps a
    changed path to its changed lines, each starting with + or -. Line patterns
    are matched only in configuration and infrastructure (line_scan_paths), so
    prose, tests, comments and code that merely name a thing cannot trigger them."""
    scanned, skip = doc["line_scan_paths"], doc.get("line_scan_exclude", [])
    out = {}
    for q in doc["questions"]:
        why = []
        for path, lines in changes.items():
            if _match(path, q.get("triggers", {}).get("paths", [])):
                why.append(f"changes {path}")
                continue
            if not _match(path, scanned) or _match(path, skip):
                continue
            code = [ln for ln in lines if not COMMENT_RE.match(ln)]
            for rx in q.get("triggers", {}).get("diff", []):
                hit = next((ln for ln in code if re.search(rx, ln)), None)
                if hit is not None:
                    why.append(f"{path}: {hit.strip()[:80]}")
                    break
        if why:
            out[q["id"]] = why
    return out


def parse(body):
    """(declared tag or None, {id: (yes|no, reason)}, category or None) from a PR description."""
    m = TAG_RE.search(body or "")
    tag = m.group(1).strip().lower() if m else None
    answers, category, in_block = {}, None, False
    for line in (body or "").splitlines():
        if re.match(r"^\s*#{0,3}\s*SIA:\s*$", line, re.I):
            in_block = True
            continue
        if not in_block:
            continue
        if not line.strip():
            in_block = not (answers or category)
            continue
        c = CATEGORY_RE.match(line)
        a = ANSWER_RE.match(line)
        if c:
            category = c.group(1).lower()
        elif a:
            qid = a.group(1).lower()
            if qid in answers:
                _fail(f"question {qid} is answered twice")
            reason = a.group(3).strip()
            reason = reason[1:-1].strip() if reason.startswith("(") and reason.endswith(")") else reason
            answers[qid] = (a.group(2).lower(), reason)
        elif re.match(r"^\s*[-*]\s", line):
            _fail(f"cannot read SIA line {_cell(line.strip())[:80]!r}: write `- <question-id>: yes|no (reason)`")
        else:
            in_block = False
    return tag, answers, category


def dependabot_only(changes):
    """True when every change is a version change a dependency bot makes: a manifest
    or lock file, or a workflow line that is a `uses:` reference."""
    for path, lines in changes.items():
        name = path.rsplit("/", 1)[-1]
        if any(fnmatch.fnmatch(name, m) for m in MANIFESTS):
            continue
        if path.startswith(".github/workflows/") and all(re.match(r"^[+-]\s*(-\s*)?uses:\s", ln) for ln in lines):
            continue
        return False
    return True


def evaluate(doc, body, changes, author=None):
    """The evaluation: {outcome, declared, errors, warnings, rows, triggered, category}."""
    qs = {q["id"]: q for q in doc["questions"]}
    tag, answers, category = parse(body)
    trig = triggered(doc, changes)
    errors, warnings, rows = [], [], []
    auto = author == DEPENDABOT and dependabot_only(changes) and not answers
    if auto:
        category = "dependency-update"
        answers = {qid: ("no", "automated version change only") for qid in trig}
        warnings.append("Dependabot version change: answered automatically as dependency-update")
    for qid in answers:
        if qid not in qs:
            errors.append(f"`{qid}` is not a question in data/sia-questions.json")
    if category is not None and category not in doc["recurring_categories"]:
        errors.append(f"category `{category}` is not one of {sorted(doc['recurring_categories'])}")
    outcome = None
    for qid, q in qs.items():
        ans, reason = answers.get(qid, (None, ""))
        if qid in trig and ans is None:
            errors.append(f"`{qid}` must be answered: the diff {trig[qid][0]}")
        elif qid in trig and ans == "no" and not reason:
            errors.append(f"`{qid}` is answered no but gives no reason, and the diff {trig[qid][0]}")
        if ans == "yes" and (outcome is None or RANK[q["outcome"]] > RANK[outcome]):
            outcome = q["outcome"]
        rows.append((qid, ans or "no", reason, q["outcome"], "; ".join(trig.get(qid, []))))
    relevant = any(_match(p, doc["security_relevant_paths"]) for p in changes) or bool(trig)
    if outcome is None:
        if category in doc["recurring_categories"]:
            outcome = "routine-recurring"
        elif not relevant:
            outcome = "not-significant"
        else:
            outcome = "adaptive"
    if outcome == "class-change":
        errors.append("a FIPS 199 or certification class change needs a new assessment and cannot ship under SCN")
    if tag is not None and tag not in TAGS:
        errors.append(f"SCN-Type `{tag}` is not one of {sorted(TAGS)}")
    elif tag == "emergency":
        warnings.append("SCN-Type: emergency. Retroactive SCN materials are due per SCN-CSO-EMG (docs/incident-response.md)")
    elif tag is None and outcome not in ("routine-recurring", "not-significant"):
        errors.append(f"the analysis gives `{outcome}`: add `SCN-Type: {outcome}`")
    elif tag is not None and tag != outcome and outcome != "class-change":
        errors.append(f"SCN-Type is `{tag}` but the analysis gives `{outcome}`")
    return {"outcome": outcome, "declared": tag, "category": category, "errors": errors,
            "warnings": warnings, "rows": rows, "triggered": trig}


def _cell(text):
    """PR text in the summary table: one line, no column breaks, no control characters."""
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(text)).replace("|", "\\|")


def render(ev):
    out = [f"## Security impact analysis: {ev['outcome']}", "",
           f"Declared `SCN-Type`: {ev['declared'] or '(none)'} · category: {ev['category'] or '(none)'}", ""]
    out += ["| Question | Answer | Reason | A yes means | Triggered by |", "|---|---|---|---|---|"]
    for qid, ans, reason, oc, why in ev["rows"]:
        if ans == "yes" or why or reason:
            out.append(f"| `{qid}` | {ans} | {_cell(reason)} | {oc} | {_cell(why)} |")
    out.append("")
    out += [f"- warning: {w}" for w in ev["warnings"]] + [f"- error: {e}" for e in ev["errors"]]
    return "\n".join(out) + "\n"


def parse_diff(text):
    """{path: [changed lines]} from a unified diff; renames are a delete and an add."""
    changes, path, header = {}, None, False
    for line in text.splitlines():
        if line.startswith("diff --git "):
            m = re.match(r"diff --git a/(.+) b/(.+)$", line)
            path, header = (m.group(2) if m else None), True
            if path is not None:
                changes.setdefault(path, [])
        elif header and line.startswith(("--- ", "+++ ")):
            p = line[4:]
            if p != "/dev/null":
                p = p[2:] if p[:2] in ("a/", "b/") else p
                if p != path:
                    changes.pop(path, None)
                    path = p
                    changes.setdefault(path, [])
        elif line.startswith("@@"):
            header = False
        elif not header and path is not None and line[:1] in "+-":
            changes[path].append(line)
    return changes


def git_changes(base, head):
    r = subprocess.run(["git", "diff", "--no-renames", "-U0", "--no-color", "--end-of-options", f"{base}...{head}"],
                       cwd=REPO, capture_output=True, text=True, check=False)
    if r.returncode != 0:
        _fail(f"git diff {base}...{head}: {r.stderr.strip()}")
    return parse_diff(r.stdout)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base", required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--author", default=None)
    ap.add_argument("--questions", default=str(QUESTIONS))
    args = ap.parse_args(argv)
    doc = load_questions(args.questions)
    ev = evaluate(doc, os.environ.get("PR_BODY", ""), git_changes(args.base, args.head), args.author)
    text = render(ev)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(text)
    for w in ev["warnings"]:
        print(f"::warning::{w}")
    for e in ev["errors"]:
        print(f"::error::{e}")
    return 1 if ev["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
