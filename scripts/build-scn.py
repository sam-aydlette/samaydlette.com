#!/usr/bin/env python3
# =============================================================================
# SIGNIFICANT CHANGE NOTIFICATIONS + EVALUATION LOG  (SCN-*)
# =============================================================================
# Run by the deploy, after the build and before signing. Writes, into --out-dir:
#
#   scn/<SCN-ID>.json                         one notification per register row,
#                                             each validated against FedRAMP's
#                                             SCN schema (write_validated)
#   significant-change-notifications.json     the index: every notification,
#                                             its notices and their dates (HIS)
#   significant-change-notifications.md       the human-readable view (HRM)
#   significant-change-notifications.atom     the subscribable feed (NOM)
#   scn-evaluations.json / .md                the evaluation log (MAR, HRM)
#
# Both the index and the log only ever grow. The previous published copies are
# fetched by the deploy and passed in; a build that would drop or rewrite a
# published entry fails (SCN-CSO-HIS, SCN-CSO-MAR). A notice keeps the date it
# was first published, which is the date it was given: FedRAMP's rules name the
# notification method for every SCN notice as an update to the Certification
# Data, and this publication is that update. Nothing is sent to anyone.
#
# The evaluation log takes one entry per first-parent commit on main after the
# last one it holds: the SCN-Type, rationale and record from the merged pull
# request's description (or the commit message for a direct push), who merged
# it and when. With no previous log, it starts at the commit that introduced
# this builder, so a lost copy is rebuilt from git rather than restarted.
#
#   build-scn.py --previous-index prev-index.json --previous-log prev-log.json
# =============================================================================

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _fedramp_schema  # noqa: E402
import _offering  # noqa: E402
import _redact  # noqa: E402
import _scn  # noqa: E402

REPO = _scn.REPO
GENESIS_PATH = "scripts/build-scn.py"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MERGE_RE = re.compile(r"^Merge pull request #(\d+) from ")
RUN_ID_RE = re.compile(r"(actions/runs/|run )\d{6,}")

MECHANISMS = [
    {"mechanism": "Atom feed", "url": _scn.BASE + _scn.FEED_NAME,
     "description": "One entry per notice (adaptive after-finish; transformative initial plan, final plan, "
                    "after finish, after verification). Any feed reader can subscribe; no account needed."},
    {"mechanism": "Signed JSON index", "url": _scn.BASE + _scn.INDEX_NAME + ".json",
     "description": "Every notification in FedRAMP's SCN schema with each notice's publication date and "
                    "deadline; signed with Sigstore (.bundle beside it)."},
    {"mechanism": "Human-readable view", "url": _scn.BASE + _scn.INDEX_NAME + ".md",
     "description": "The same notifications as a Markdown document."},
]
ACCESS = ("All notifications and the evaluation log are public at the URLs above, in JSON and human-readable "
          "form; no request is needed. The register they are built from is docs/scn/scn-register.csv in the "
          "public repository.")
SHARING = ("Everything is published to everyone: the system holds no federal data and no agency customer, so "
           "there is nothing in a notification to withhold. A notification that ever needed to carry sensitive "
           "detail would publish a summary and say how to request the rest.")
NOTIFICATION = ("Notification is publication. FedRAMP's rules name the method for each SCN notice as an update to "
                "the FedRAMP Certification Data; publishing here is that update. Nothing is sent by email or to "
                "FedRAMP directly. A notice's publishedOn is the first deploy that published it.")


def _today():
    return datetime.now(timezone.utc).date()


def _load(path):
    if not path or not Path(path).is_file() or Path(path).stat().st_size == 0:
        return None
    return json.loads(Path(path).read_text())


# --- the evaluation log --------------------------------------------------------------

def _git(*args, root=REPO):
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True).stdout.strip()


def gh_pull(number):
    """The pull request's description and merger, via the GitHub API (gh, GH_TOKEN)."""
    repo = os.environ.get("GITHUB_REPOSITORY", "sam-aydlette/samaydlette.com")
    out = subprocess.run(["gh", "api", f"repos/{repo}/pulls/{number}"], check=True, capture_output=True, text=True)
    pr = json.loads(out.stdout)
    return {"body": pr.get("body") or "", "merged_by": (pr.get("merged_by") or {}).get("login"),
            "author": (pr.get("user") or {}).get("login")}


def _scrub(text):
    """Free text from a PR description, made safe to publish."""
    return LONG_NUMBER.sub("<number>", RUN_ID_RE.sub(r"\1<run>", _redact.redact_text(text)))


# A standalone number of 9 to 11 digits in published text is most likely a
# GitHub run ID; 12 digits is an AWS account ID, which the publication gate
# catches. Neither belongs in a notification.
LONG_NUMBER = re.compile(r"(?<![0-9A-Za-z])[0-9]{9,11}(?![0-9A-Za-z])")


def long_number_errors(name, text):
    return [f"{name}: a {len(m)}-digit number (a run ID?) would be published" for m in LONG_NUMBER.findall(text)]


def evaluation_entry(commit, subject, body, merged_on, author, lookup):
    m = MERGE_RE.match(subject)
    if m:
        pr = lookup(int(m.group(1)))
        text, evaluator, number = pr["body"], pr.get("merged_by") or pr.get("author"), int(m.group(1))
    else:
        text, evaluator, number = f"{subject}\n{body}", author, None
    entry = {"commit": commit, "merged_on": merged_on, "pull_request": number, "evaluator": evaluator or "unknown"}
    try:
        ev = _scn.parse_evaluation(text)
        entry.update(scn_type=ev["type"], rationale=_scrub(ev["rationale"]), scn_record=ev["record"], problem=None)
    except _scn.EvaluationError as exc:
        entry.update(scn_type=None, rationale=None, scn_record=None, problem=f"no valid evaluation: {exc}")
    return entry


def collect(previous_entries, root=REPO, lookup=gh_pull, head="HEAD"):
    """Entries for the first-parent commits after the last one logged."""
    if previous_entries:
        last = previous_entries[-1].get("commit", "")
        # Read from the published log: a full SHA or nothing, never an option.
        if not SHA_RE.match(last):
            raise SystemExit("::error::SCN log: the published log's last entry has no valid commit (fail-closed)")
        try:
            _git("merge-base", "--is-ancestor", last, head, root=root)
        except subprocess.CalledProcessError:
            raise SystemExit(f"::error::SCN log: last logged commit {last[:12]} is not an ancestor of {head}; "
                             "history was rewritten (fail-closed)") from None
        span = f"{last}..{head}"
        shas = _git("rev-list", "--first-parent", "--reverse", span, root=root).split()
    else:
        first = _git("log", "--first-parent", "--reverse", "--format=%H", head, "--", GENESIS_PATH, root=root).split()
        if not first:
            raise SystemExit(f"::error::SCN log: no commit introduces {GENESIS_PATH} (fail-closed)")
        parent = _git("rev-list", "--max-count=1", f"{first[0]}^1", root=root) if _has_parent(first[0], root) \
            else None
        span = f"{parent}..{head}" if parent else head
        shas = _git("rev-list", "--first-parent", "--reverse", span, root=root).split()
    out = []
    for sha in shas:
        subject, body, when, author = _git("show", "-s", "--format=%s%x00%b%x00%cI%x00%an", sha, root=root) \
            .split("\x00")
        out.append(evaluation_entry(sha, subject, body, when[:10], author, lookup))
    return out


def _has_parent(sha, root):
    try:
        _git("rev-parse", "--verify", "--quiet", f"{sha}^1", root=root)
        return True
    except subprocess.CalledProcessError:
        return False


def build_log(previous, new_entries, now, commit):
    prev = (previous or {}).get("entries", [])
    entries = prev + new_entries
    errors = _scn.append_only_errors(prev, entries, "commit")
    if errors:
        raise SystemExit("::error::SCN evaluation log is append-only: " + "; ".join(errors))
    return _offering.stamp_fedramp_id({
        "$comment": "SCN-CSO-MAR: the significant-change evaluation of every change merged to main, one entry per "
                    "first-parent commit. Append-only: each deploy adds the commits since the last entry, and "
                    "a deploy that would drop or rewrite an entry fails. Built by scripts/build-scn.py.",
        "generated_at": now.isoformat(),
        "commit": commit,
        "genesis_commit": (previous or {}).get("genesis_commit") or (entries[0]["commit"] if entries else None),
        "access": ACCESS,
        "entries": entries,
        "unrecorded": sum(1 for e in entries if e["problem"]),
    })


def render_log_md(log):
    out = ["# Significant-change evaluation log (SCN-CSO-MAR)", "",
           f"_Generated {log['generated_at']} from commit `{log['commit']}`. The signed JSON beside this file is "
           "the record; this is its rendering._", "",
           f"{len(log['entries'])} evaluations; {log['unrecorded']} without a valid evaluation.", "",
           "| Merged | Commit | PR | Type | Record | Evaluator | Rationale |", "|---|---|---|---|---|---|---|"]
    for e in reversed(log["entries"]):
        rationale = e["rationale"] or f"_{e['problem']}_"
        out.append("| {d} | `{c}` | {p} | {t} | {r} | {who} | {why} |".format(
            d=e["merged_on"], c=e["commit"][:12], p=f"#{e['pull_request']}" if e["pull_request"] else "direct",
            t=e["scn_type"] or "-", r=e["scn_record"] or "", who=e["evaluator"], why=rationale.replace("|", "\\|")))
    return "\n".join(out)


# --- notifications -------------------------------------------------------------------

def _fedramp_id(row):
    """The register's ID when FedRAMP has assigned one; until then the
    offering's (CDS-CSO-FID: FedRAMP's fallback, marked not real)."""
    v = row["fedramp_id"]
    return _offering.fedramp_id() if not v or v.startswith("<") else v


def scn_document(row, previous_notices, today):
    start = row["date_started"] or row["date_initiated"]
    plan = {"summary": row["plan_and_timeline"], "plannedStart": start}
    if row["date_finished"]:
        plan["plannedCompletion"] = row["date_finished"]
    doc = {
        "$schema": _fedramp_schema.stamp("scn"),
        "certificationPackageOverviewUri": _fedramp_schema.CPO_URI,
        "scnId": row["scn_id"],
        "serviceOfferingFedrampId": _fedramp_id(row),
        "serviceOfferingFedrampIdNote": None if _fedramp_id(row) != _offering.fedramp_id() else
            "Simulated: no FedRAMP ID has been assigned (the offering is not FedRAMP certified). This is "
            "FedRAMP's fallback, the provider name and acronym, marked so nobody mistakes it for a real ID.",
        "assessorName": row["assessor_name"],
        "relatedVulnerability": row["related_vulnerability"],
        "changeType": row["scn_type"].capitalize(),
        "changeTypeExplanation": row["categorization_rationale"],
        "changeDescription": row["short_description"],
        "reason": row["reason_for_change"],
        "customerImpact": row["customer_impact"],
        "planAndTimeline": plan,
        "impactAnalysis": _scn.SOURCE_URL + row["sia_reference"],
        "approver": {"name": row["approver_name"], "title": row["approver_title"]},
        "newRisksSummary": row["new_risks_summary"],
        "emergency": row["emergency"] == "yes",
        "notices": _scn.merge_notices(row, previous_notices, today),
        # SCN-CSO-ARI: what else a reviewer needs to judge the change.
        "additionalInformation": {
            "status": row["status"],
            "dateInitiated": row["date_initiated"],
            "dateFinished": row["date_finished"] or None,
            "verifiedOn": row["verified_on"] or None,
            "changes": [p.strip() for p in row["evaluation_prs"].split(";") if p.strip()],
            "record": _scn.SOURCE_URL + row["sia_reference"],
        },
    }
    if row["scn_type"] == "transformative":
        doc["transformative"] = {
            "planFinal": row["plan_final"] == "yes",
            "thirdPartyReview": {"humanValidationNeeded": row["tpr_human_validation"] == "yes",
                                 "assessorOrReasonNotEngaged": row["tpr_assessor_or_reason"]},
            "securityAssessmentReport": row["sar_reference"] or None,
            "documentationUpdate": {
                "documents": [d.strip() for d in row["docs_to_update"].split(";") if d.strip()],
                "updatedOn": row["docs_updated_on"] or None,
                "notRequiredBecause": row["docs_update_not_required"] or None,
                "deadline": (_scn.docs_update_deadline(row) or date.min).isoformat()
                if row["date_finished"] else None,
            },
        }
    return doc


def build_index(rows, previous_index, now, commit, out_dir):
    prev = {s["scnId"]: s.get("notices", []) for s in (previous_index or {}).get("notifications", [])}
    scn_dir = Path(out_dir) / "scn"
    scn_dir.mkdir(parents=True, exist_ok=True)
    docs = []
    for row in rows:
        doc = _offering.stamp_fedramp_id(scn_document(row, prev.get(row["scn_id"]), now.date()))
        path = scn_dir / f"{row['scn_id']}.json"
        _fedramp_schema.write_validated(doc, "scn", path)
        docs.append(json.loads(path.read_text()))
    late = [f"{d['scnId']} {n['stage']}" for d in docs for n in d["notices"] if not n["onTime"]]
    index = {
        "$comment": "SCN-CSO-HIS / SCN-CSO-HRM / SCN-CSO-NOM: every Significant Change Notification, each in "
                    "FedRAMP's SCN schema, with each notice's deadline and the date it was published. Never "
                    "pruned: a deploy that would drop a notification or re-date a notice fails. Built by "
                    "scripts/build-scn.py from docs/scn/scn-register.csv.",
        "generated_at": now.isoformat(),
        "commit": commit,
        "certificationPackageOverviewUri": _fedramp_schema.CPO_URI,
        "notification": NOTIFICATION,
        "notificationMechanisms": MECHANISMS,
        "access": ACCESS,
        "sharing": SHARING,
        "retention": "All notifications are kept, which exceeds the 12 months SCN-CSO-HIS requires.",
        "evaluationLog": _scn.BASE + _scn.LOG_NAME + ".json",
        "lateNotices": late,
        "notifications": docs,
    }
    errors = _scn.retention_errors(previous_index, index)
    if errors:
        raise SystemExit("::error::SCN notifications are retained (SCN-CSO-HIS): " + "; ".join(errors))
    return _offering.stamp_fedramp_id(index)


def render_index_md(index):
    out = ["# Significant Change Notifications", "",
           f"_Generated {index['generated_at']} from commit `{index['commit']}`. The signed JSON beside this "
           "file is the record; this is its rendering._", "",
           index["notification"], "",
           "## How to receive them (SCN-CSO-NOM)", ""]
    out += [f"- **{m['mechanism']}:** {m['url']} — {m['description']}" for m in index["notificationMechanisms"]]
    out += ["", f"**Access.** {index['access']}", "", f"**Sharing.** {index['sharing']}", "",
            f"**Retention.** {index['retention']}", "",
            f"**Evaluation log (SCN-CSO-MAR):** {index['evaluationLog']}", ""]
    if index["lateNotices"]:
        out += ["**Notices published after their deadline:** " + ", ".join(index["lateNotices"]), ""]
    for d in reversed(index["notifications"]):
        out += [f"## {d['scnId']} — {d['changeType']}{' (emergency)' if d['emergency'] else ''}", "",
                d["changeDescription"], "",
                f"- **Service Offering FedRAMP ID:** {d['serviceOfferingFedrampId'] or d['serviceOfferingFedrampIdNote']}",
                f"- **Assessor:** {d.get('assessorName') or '-'}",
                f"- **Related vulnerability:** {d.get('relatedVulnerability') or '-'}",
                f"- **Why this type:** {d['changeTypeExplanation']}",
                f"- **Reason:** {d['reason']}",
                f"- **Customer impact:** {d['customerImpact']}",
                f"- **Plan and timeline:** {d['planAndTimeline']['summary']}",
                f"- **Impact analysis:** {d['impactAnalysis']}",
                f"- **New risks:** {d['newRisksSummary'] or '-'}",
                f"- **Approver:** {d['approver']['name']}, {d['approver']['title']}",
                f"- **Status:** {d['additionalInformation']['status']}"]
        if "transformative" in d:
            t = d["transformative"]
            tpr = t["thirdPartyReview"]
            out += [f"- **Human validation needed:** {'yes' if tpr['humanValidationNeeded'] else 'no'}; "
                    f"{tpr['assessorOrReasonNotEngaged']}",
                    f"- **Security assessment report:** {t['securityAssessmentReport'] or '-'}",
                    f"- **Documentation update:** {', '.join(t['documentationUpdate']['documents']) or '-'}; "
                    f"updated {t['documentationUpdate']['updatedOn'] or 'not yet'}"]
        out += ["", "| Notice | Rule | Deadline | Published | On time |", "|---|---|---|---|---|"]
        out += [f"| {n['stage']} | {n['rule']} | {n['deadline']} | {n['publishedOn']} | "
                f"{'yes' if n['onTime'] else 'no'} |" for n in d["notices"]]
        out.append("")
    return "\n".join(out)


def render_feed(index):
    """Atom (RFC 4287): one entry per notice, dated when it was published."""
    entries = []
    for d in index["notifications"]:
        for n in d["notices"]:
            entries.append((n["publishedOn"], d, n))
    entries.sort(key=lambda e: (e[0], e[1]["scnId"], e[2]["stage"]), reverse=True)
    updated = (entries[0][0] if entries else index["generated_at"][:10]) + "T00:00:00Z"
    out = ['<?xml version="1.0" encoding="utf-8"?>',
           '<feed xmlns="http://www.w3.org/2005/Atom">',
           "  <title>samaydlette.com Significant Change Notifications</title>",
           f"  <subtitle>FedRAMP ID: {escape(index['fedRampId'])}</subtitle>",
           "  <id>tag:samaydlette.com,2026:significant-change-notifications</id>",
           f"  <updated>{updated}</updated>",
           f'  <link rel="self" href="{_scn.BASE}{_scn.FEED_NAME}"/>',
           f'  <link rel="alternate" type="application/json" href="{_scn.BASE}{_scn.INDEX_NAME}.json"/>',
           "  <author><name>samaydlette.com</name></author>"]
    for on, d, n in entries:
        title = f"{d['scnId']} ({d['changeType']}) {n['stage']} notice: {d['changeDescription'][:120]}"
        summary = (f"{d['changeDescription']} Rule {n['rule']}; deadline {n['deadline']}; published {on}"
                   f"{'' if n['onTime'] else ' (after the deadline)'}. Customer impact: {d['customerImpact']}")
        out += ["  <entry>",
                f"    <id>tag:samaydlette.com,2026:scn/{d['scnId']}/{n['stage']}</id>",
                f"    <title>{escape(title)}</title>",
                f"    <updated>{on}T00:00:00Z</updated>",
                f'    <link href="{_scn.BASE}{_scn.INDEX_NAME}.md"/>',
                f"    <summary>{escape(summary)}</summary>",
                "  </entry>"]
    out.append("</feed>")
    return "\n".join(out) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build the SCN notifications and evaluation log.")
    ap.add_argument("--register", default=str(_scn.REGISTER))
    ap.add_argument("--previous-index", help="the published index (absent on the first publish)")
    ap.add_argument("--previous-log", help="the published evaluation log (absent on the first publish)")
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--repo-root", default=str(REPO))
    ap.add_argument("--commit", default=os.environ.get("GITHUB_SHA", ""))
    ap.add_argument("--new-evaluations", help="JSON list of entries to append instead of reading git (tests)")
    a = ap.parse_args(argv)

    now = datetime.now(timezone.utc).replace(microsecond=0)
    header, rows = _scn.read_register(a.register)
    errors = _scn.validate_register(header, rows, a.repo_root)
    if errors:
        for e in errors:
            print(f"::error::scn-register: {e}", file=sys.stderr)
        return 1
    out = Path(a.out_dir)
    prev_index, prev_log = _load(a.previous_index), _load(a.previous_log)

    index = build_index(rows, prev_index, now, a.commit, out)
    if a.new_evaluations:
        new = json.loads(Path(a.new_evaluations).read_text())
    else:
        new = collect((prev_log or {}).get("entries", []), root=a.repo_root)
    log = build_log(prev_log, new, now, a.commit)

    outputs = {
        f"{_scn.INDEX_NAME}.json": json.dumps(index, indent=2) + "\n",
        f"{_scn.INDEX_NAME}.md": render_index_md(index) + "\n",
        _scn.FEED_NAME: render_feed(index),
        f"{_scn.LOG_NAME}.json": json.dumps(log, indent=2) + "\n",
        f"{_scn.LOG_NAME}.md": render_log_md(log) + "\n",
    }
    errors = [e for name, text in outputs.items() for e in long_number_errors(name, text)]
    if errors:
        for e in errors:
            print(f"::error::{e}", file=sys.stderr)
        return 1
    for name, text in outputs.items():
        (out / name).write_text(text)
    print(f"scn: {len(index['notifications'])} notifications ({len(index['lateNotices'])} notice(s) published "
          f"late); evaluation log {len(log['entries'])} entries (+{len(new)}, {log['unrecorded']} unrecorded)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
