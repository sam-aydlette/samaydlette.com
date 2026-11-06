#!/usr/bin/env python3
"""Hold the monthly recovery exercise, from the evidence nightly (KSI-RPL-TRC, KSI-RPL-ARP; CP-4).

No person runs a recovery test (DEC-195). On the first of every month the
nightly holds one, with no write to production and no restore:

  (a) restore point   the site tree is rebuilt from the deployed commit (the
                      commit the published inventory names) exactly as the
                      deploy uploads it, and every page's sha256 is compared
                      with the live object fetched over HTTPS. The only
                      difference allowed is the deploy's cache-busting
                      `?v=<timestamp>` on asset links, removed on both sides.
                      Every page matching proves the restore point is the
                      commit: losing the bucket loses nothing git does not have.
  (b) configuration   the signed runtime signal (verified against the committed
                      key, fresh, built from the deployed commit) re-validated
                      every bucket and the state-lock table, so versioning and
                      point-in-time recovery are in place as the plan says.
  (c) tabletop        in November, a scripted tabletop walks every loss scenario
                      in docs/recovery-plan.md with a simulated incident
                      commander and a simulated scenario injector; a scenario
                      with no recovery stated fails it.

It writes vdr-recovery-exercise-<due date>.json and .view.md (never rewritten)
and the index vdr-recovery-exercises.json. An exercise with a failing check is
not frozen: the run fails and the next run holds it again, once the cause is
fixed; scripts/check-scheduled-review.py fails the nightly and the deploy from
the day after its due date until then.

  hold-recovery-exercise.py --commit SHA --runtime-signal ksi-signal-runtime.json \
      [--previous-index vdr-recovery-exercises.json] --out DIR --new-files FILE
"""

import argparse
import fnmatch
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
import _offering  # noqa: E402
import _scheduled_review as sr  # noqa: E402

RV = sr.REVIEWS["recovery-exercise"]
SITE = "https://samaydlette.com"
ALLOWED_HOST = "samaydlette.com"
TABLETOP_MONTH = 11
PLAN = REPO / "docs" / "recovery-plan.md"
# The deploy's sync (deploy-with-opa.yml "Sync Website Content") skips these,
# relative to website/; .well-known/ is published separately and is evidence, not content.
SYNC_EXCLUDES = ("*.tf", "*.tfvars*", "*.tfstate*", ".terraform/*", "infrastructure/*", "scripts/*", ".git/*",
                 "README.md", "Makefile", ".gitignore", ".github/*", ".well-known/*")
CACHE_BUST = re.compile(rb"(\.(?:css|js))\?v=\d+")
RECOVERABLE_TYPES = ("object_store", "kv_table")


def _fail(msg):
    raise SystemExit(f"::error::recovery exercise: {msg} (fail-closed)")


def normalize(path, body):
    """The bytes compared: HTML without the deploy's cache-busting query string."""
    return CACHE_BUST.sub(rb"\1?v=", body) if path.endswith(".html") else body


def _git(args, repo):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=True,  # nosec B603
                          timeout=120).stdout


def site_tree(commit, repo=REPO):
    """{site path: bytes} for every file the deploy uploads from `commit`."""
    if not re.fullmatch(r"[0-9a-f]{40}", commit or ""):
        _fail("the deployed commit is not a 40-hex commit id")
    names = _git(["ls-tree", "-r", "--name-only", "-z", commit, "--", "website/"], repo).split(b"\0")
    out = {}
    for raw in names:
        name = raw.decode()
        if not name:
            continue
        rel = name[len("website/"):]
        if any(fnmatch.fnmatchcase(rel, pat) for pat in SYNC_EXCLUDES):
            continue
        out[rel] = _git(["show", f"{commit}:{name}"], repo)
    if not out:
        _fail("the deployed commit has no website tree")
    return out


def http_get(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname != ALLOWED_HOST:
        _fail(f"refusing to fetch {url!r}")
    req = urllib.request.Request(url, headers={"User-Agent": "samaydlette-recovery-exercise/1",
                                               "Accept-Encoding": "identity"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:  # nosec B310: https on the allowed host only
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, b""


def restore_point(tree, get, site=SITE):
    """Check (a): every page in the rebuilt tree is byte-identical (cache-busting aside) to the live one."""
    mismatched, unreachable, unaddressable = [], [], []
    for rel in sorted(tree):
        if "." not in rel.rsplit("/", 1)[-1]:
            # The edge's directory-index function (infrastructure/cloudfront/directory-index.js)
            # redirects an extensionless path to a directory, so no URL reaches the object.
            unaddressable.append(rel)
            continue
        url = f"{site}/{urllib.parse.quote(rel)}"
        status, body = None, b""
        for _ in range(3):
            try:
                status, body = get(url)
            except (OSError, ValueError):
                status = None
            if status == 200:
                break
        if status != 200:
            unreachable.append(rel)
        elif hashlib.sha256(normalize(rel, body)).digest() != hashlib.sha256(normalize(rel, tree[rel])).digest():
            mismatched.append(rel)
    ok = not mismatched and not unreachable
    compared = len(tree) - len(unaddressable)
    detail = (f"{len(tree)} file(s) rebuilt from the deployed commit; {compared - len(mismatched) - len(unreachable)} "
              f"of {compared} identical live")
    if unaddressable:
        detail += (f"; not addressable at the edge (no file extension), so not compared: "
                   f"{', '.join(unaddressable[:10])}")
    if mismatched:
        detail += f"; differ: {', '.join(mismatched[:10])}"
    if unreachable:
        detail += f"; not served: {', '.join(unreachable[:10])}"
    return {"id": "restore-point", "title": "The live site is the deployed commit: every page rebuilt from git "
                                            "matches the served object (sha256)", "result": "pass" if ok else "fail",
            "detail": detail, "files": len(tree), "differ": mismatched, "notServed": unreachable,
            "notAddressable": unaddressable}


def _vdr_builder():
    spec = importlib.util.spec_from_file_location("vdr_for_recovery", HERE / "build-vdr-report.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def configuration(runtime_path, commit, now, loader=None):
    """Check (b): versioning and point-in-time recovery, from the verified runtime signal."""
    title = ("Versioning on every bucket and point-in-time recovery on the state-lock table, re-validated by the "
             "signed runtime signal of the deployed commit")
    rt = (loader or _vdr_builder().load_runtime_signal)(runtime_path, now=now)
    if not rt.get("verified") or not rt.get("fresh"):
        return {"id": "configuration", "title": title, "result": "fail",
                "detail": rt.get("reason") or "the runtime signal is not verified and fresh"}
    sig = json.loads(Path(runtime_path).read_text())
    if ((sig.get("provenance") or {}).get("source") or {}).get("commit") != commit:
        return {"id": "configuration", "title": title, "result": "fail",
                "detail": "the runtime signal was not built from the deployed commit"}
    wanted = sorted(c["component_id"] for c in sig.get("components") or [] if c.get("type") in RECOVERABLE_TYPES)
    passing = {ref for v in rt["validations"] if v.get("result") == "pass" for ref in v.get("component_refs") or []}
    gaps = [c for c in wanted if c not in passing]
    ok = bool(wanted) and not gaps
    return {"id": "configuration", "title": title, "result": "pass" if ok else "fail",
            "detail": (f"{len(wanted)} component(s) re-validated, runtime signal emitted {rt['emitted_at']}"
                       + (f"; not re-validated or failing: {', '.join(gaps)}" if gaps else "")
                       if wanted else "the runtime signal lists no bucket or table"),
            "components": wanted}


def scenarios(text):
    """[(scenario, recovery)] from the plan's 'In-scope loss scenarios' list."""
    m = re.search(r"In-scope loss scenarios:\s*\n((?:\s*- .+\n?)+)", text)
    out = []
    for line in (m.group(1).splitlines() if m else []):
        item = line.strip()[2:].strip()
        what, _, how = item.partition(" — ")
        out.append((what.strip(), how.strip()))
    return out


def tabletop(plan_text):
    """Check (c), each November: a scripted tabletop over every scenario in the plan."""
    ic, inj = sr.CAST["incident-commander"], sr.CAST["scenario-injector"]
    items = scenarios(plan_text)
    lines = [{"speaker": ic, "line": "Welcome to the annual recovery tabletop. The table is real. Nothing else is."},
             {"speaker": inj, "line": f"I have {len(items)} scenario(s) from docs/recovery-plan.md and a sense of "
                                      "foreboding."}]
    gaps = []
    for n, (what, how) in enumerate(items, 1):
        lines.append({"speaker": inj, "line": f"Scenario {n}: {what}. Also, it is raining."})
        if how:
            lines.append({"speaker": ic, "line": f"The plan says: {how}. Nobody panics; the plan says that too."})
        else:
            gaps.append(what)
            lines.append({"speaker": ic, "line": "The plan does not say. Minuted as a gap."})
    has_procedure = "## Recovery procedure" in plan_text
    lines.append({"speaker": ic, "line": "Tabletop adjourned. The table was not harmed. Same time next November."})
    ok = len(items) >= 3 and not gaps and has_procedure
    detail = f"{len(items)} scenario(s) walked"
    if gaps:
        detail += f"; no recovery stated for: {', '.join(gaps)}"
    if not has_procedure:
        detail += "; the plan has no Recovery procedure section"
    return ({"id": "tabletop", "title": "Annual tabletop: every loss scenario in the recovery plan has a stated "
                                        "recovery, walked with simulated responders",
             "result": "pass" if ok else "fail", "detail": detail},
            {"participants": [ic, inj], "scenarios": [w for w, _ in items], "transcript": lines})


def build(due, now, fedramp_id, tree, get, runtime_path, commit, plan_text, runtime_loader=None):
    checks = [restore_point(tree, get), configuration(runtime_path, commit, now, runtime_loader)]
    doc = sr.base_doc(RV, due, now, fedramp_id, f"Recovery exercise for {due:%B %Y} (automated; simulated "
                                                  "tabletop responders)")
    doc.update({"rules": ["KSI-RPL-TRC", "KSI-RPL-ARP", "KSI-RPL-ABO"], "controls": ["cp-4", "cp-9", "cp-10"],
                "deployedCommit": commit,
                "method": "scripts/hold-recovery-exercise.py, run by evidence-nightly.yml on its due date. No write "
                          "to production and no restore: the restore point is proved by rebuilding the site from "
                          "git and comparing it with what is served.",
                "plan": "docs/recovery-plan.md"})
    if due.month == TABLETOP_MONTH:
        chk, record = tabletop(plan_text)
        checks.append(chk)
        doc["tabletop"] = record
    doc["checks"] = [{k: v for k, v in c.items() if k in ("id", "title", "result", "detail")} for c in checks]
    doc["result"] = sr.result_of(doc["checks"])
    return sr.finish(doc, "the recovery exercise")


def run(previous, out, now, fedramp_id, commit, runtime_path, get=http_get, repo=REPO, runtime_loader=None,
        plan_path=PLAN):
    """Hold every due exercise that passes; the index is written either way
    (carried forward), and a failing exercise then fails the run."""
    today = now.date()
    due = sr.due_now(RV, previous, today)
    entries, files, failed = [], [], []
    if due:
        tree = site_tree(commit, repo)
        plan_text = Path(plan_path).read_text(encoding="utf-8")
        for d in due:
            doc = build(d, now, fedramp_id, tree, get, runtime_path, commit, plan_text, runtime_loader)
            if doc["result"] != "pass":
                for c in doc["checks"]:
                    if c["result"] != "pass":
                        print(f"::error::recovery exercise due {d}: {c['title']}: {c['detail']}")
                failed.append(d)
                continue
            entry, written = sr.write(out, RV, d, doc)
            entries.append(entry)
            files += written
    index = sr.index_doc(RV, previous, entries, now, fedramp_id)
    sr.write_json(out, RV.index, index)   # republished every run; `files` lists only the new, frozen ones
    return index, entries, files, failed


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--commit", required=True, help="the commit the published inventory was built from")
    ap.add_argument("--runtime-signal", required=True)
    ap.add_argument("--previous-index", default=None)
    ap.add_argument("--out", required=True)
    ap.add_argument("--new-files", default=None)
    ap.add_argument("--now", default=None, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    now = sr.now_utc(a.now)
    prev = Path(a.previous_index) if a.previous_index else None
    previous = json.loads(prev.read_text()) if prev and prev.is_file() else {}
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    index, entries, files, failed = run(previous, out, now, _offering.fedramp_id(), a.commit, a.runtime_signal)
    if a.new_files:
        Path(a.new_files).write_text("".join(f + "\n" for f in files))
    for e in entries:
        print(f"recovery exercise due {e['dueDate']}: {e['result']}")
    print(f"recovery exercises: {len(index['reviews'])} held; next due {index['nextDueDate']}")
    if failed:
        _fail(f"the exercise due {', '.join(map(str, failed))} did not pass; it is held again on the next run "
              "once fixed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
