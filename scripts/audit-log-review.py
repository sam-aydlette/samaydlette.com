#!/usr/bin/env python3
"""The audit-log review, run by the evidence nightly on every run (KSI-MLA-RVL, KSI-CMT-RVP; AU-6).

Nobody reads the logs by hand (DEC-195). Each run reads two record sources for
the window since the previous published review and judges every entry by rule:

  CloudTrail   LookupEvents (event history, us-east-1 and us-east-2) for the
               write events of the services that hold the system's trust:
               IAM, CloudFront, S3 bucket policies and public access blocks,
               KMS, Lambda, Cognito and CloudTrail itself. A write by one of
               the five CI roles (infrastructure/bootstrap), by AWS on its own
               account, or a Cognito app user's own sign-in flow is expected;
               any other principal is unexpected.
  GitHub       every commit on main in the window must belong to a merged pull
               request (one that does not is unexpected, and one that changes
               .github/workflows/ is named as such); a ruleset or environment
               updated in the window is a change made outside review.

What is unexpected becomes, with no person in the loop:
  * a process finding in the VDR (gate check audit-log.unexpected, run in
    detect-and-recover mode: it goes through GATE_EVENTS_FILE into the next
    VDR as a finding with a clock, VDR-CSO-FAV), and
  * an incident evaluation (IEC-CSO-EFR), by rule: an unexpected write that
    silences the audit record, disables or deletes a key, creates long-lived
    credentials or opens the bucket's public access is evaluated as a possible
    FedRAMP Reportable Incident, and `--enforce` then stops the nightly (gate
    check audit-log.reportable, block) after the review is published, so the
    incident path starts with a page, not with a person reading logs.

Every run also feeds a planted event set through the same rules: "Mallory
McHypothetical (simulated)" stops the trail and mints an access key. The run
fails unless it is caught and evaluated reportable. Published output carries
event names, times, regions and the kind of principal only: no ARN, account ID,
user or role name, IP address or commit author.

  audit-log-review.py --out vdr-audit-log-review.json [--previous PREV.json]
  audit-log-review.py --enforce vdr-audit-log-review.json
"""

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import urllib.error
from datetime import timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import _engagement  # noqa: E402
import _gates  # noqa: E402
import _offering  # noqa: E402
import _scheduled_review as sr  # noqa: E402

SCHEMA = "audit-log-review/1"
REGIONS = ("us-east-1", "us-east-2")
DEFAULT_WINDOW_HOURS = 36
MAX_WINDOW_DAYS = 7
# The CI roles' names, as infrastructure/bootstrap names them (read, never published).
CI_ROLES = {"github-actions-deploy-oidc": "deploy", "github-actions-plan-oidc": "plan",
            "github-actions-evidence-nightly-oidc": "nightly",
            "github-actions-package-maintenance-oidc": "package-maintenance",
            "github-actions-incident-reports-oidc": "incident-reports"}
WATCHED_SOURCES = {"iam.amazonaws.com": "IAM", "cloudfront.amazonaws.com": "CloudFront", "kms.amazonaws.com": "KMS",
                   "lambda.amazonaws.com": "Lambda", "cognito-idp.amazonaws.com": "Cognito",
                   "cloudtrail.amazonaws.com": "CloudTrail"}
# S3: only the bucket-policy and public-access writes.
S3_EVENTS = {"PutBucketPolicy", "DeleteBucketPolicy", "PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock",
             "PutAccountPublicAccessBlock", "DeleteAccountPublicAccessBlock", "PutBucketAcl"}
# A Cognito app user's own flows: the app's users, not a principal of the system.
COGNITO_USER_FLOWS = {"InitiateAuth", "RespondToAuthChallenge", "SignUp", "ConfirmSignUp", "ForgotPassword",
                      "ConfirmForgotPassword", "ChangePassword", "GlobalSignOut", "RevokeToken",
                      "AssociateSoftwareToken", "VerifySoftwareToken", "SetUserMFAPreference", "GetTokensFromRefreshToken",
                      "UpdateUserAttributes", "VerifyUserAttribute", "DeleteUser"}
# Unexpected writes evaluated as a possible FedRAMP Reportable Incident.
REPORTABLE = {"StopLogging": "the audit trail was stopped", "DeleteTrail": "the audit trail was deleted",
              "UpdateTrail": "the audit trail was reconfigured", "PutEventSelectors": "what the trail records changed",
              "CreateAccessKey": "a long-lived access key was created", "CreateUser": "an IAM user was created",
              "CreateLoginProfile": "a console password was created", "UpdateLoginProfile": "a console password changed",
              "DisableKey": "a KMS key was disabled", "ScheduleKeyDeletion": "a KMS key was scheduled for deletion",
              "DeleteBucketPublicAccessBlock": "a bucket's public access block was removed",
              "DeleteAccountPublicAccessBlock": "the account's public access block was removed"}

# The planted event set: plainly simulated, run through the same rules every time.
INTRUDER_EVENTS = [
    {"EventName": "StopLogging", "EventSource": "cloudtrail.amazonaws.com", "EventTime": "1999-12-31T23:59:00Z",
     "region": "us-east-2", "userIdentity": {"type": "IAMUser", "userName": sr.CAST["intruder"]}},
    {"EventName": "CreateAccessKey", "EventSource": "iam.amazonaws.com", "EventTime": "1999-12-31T23:59:30Z",
     "region": "us-east-1", "userIdentity": {"type": "IAMUser", "userName": sr.CAST["intruder"]}},
]
EXERCISE_NOTE = (f"{sr.CAST['intruder']} has been stopping the trail and minting access keys at 23:59 on "
                 "31 December 1999 every night since this review began. She is caught every time. She never learns.")


def _fail(msg):
    raise SystemExit(f"::error::audit-log review: {msg} (fail-closed)")


# --- reading ---------------------------------------------------------------------------

class AccessDenied(Exception):
    pass


def aws_lookup(region, start, end):
    """Every write event in `region` from `start` to `end`, from CloudTrail's event history."""
    args = ["aws", "cloudtrail", "lookup-events", "--region", region,
            "--lookup-attributes", "AttributeKey=ReadOnly,AttributeValue=false",
            "--start-time", start.isoformat(), "--end-time", end.isoformat(), "--output", "json"]
    p = subprocess.run(args, capture_output=True, text=True, timeout=300, check=False)  # nosec B603: fixed argv
    if p.returncode != 0:
        if "AccessDenied" in p.stderr or "UnauthorizedOperation" in p.stderr:
            raise AccessDenied(region)
        _fail(f"cloudtrail lookup-events failed in {region} (exit {p.returncode})")
    return json.loads(p.stdout or "{}").get("Events") or []


def _event(raw, region):
    """One LookupEvents entry as {EventName, EventSource, EventTime, region, userIdentity, errorCode}."""
    try:
        detail = json.loads(raw.get("CloudTrailEvent") or "{}")
    except json.JSONDecodeError:
        detail = {}
    return {"EventName": raw.get("EventName") or detail.get("eventName"),
            "EventSource": raw.get("EventSource") or detail.get("eventSource"),
            "EventTime": str(raw.get("EventTime") or detail.get("eventTime")),
            "region": region, "userIdentity": detail.get("userIdentity") or {},
            "errorCode": detail.get("errorCode")}


def _manual_settings():
    spec = importlib.util.spec_from_file_location("manual_settings_for_audit", HERE / "check-manual-settings.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def github_reader():
    ms = _manual_settings()
    headers = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    api = f"https://api.github.com/repos/{ms.REPO_SLUG}"
    return lambda path: ms._get_json(f"{api}{path}", headers, timeout=30)


def read_github(get, start):
    """{commits: [{at, pr, workflows}], settings: [{kind, name, updated_at}]} for the window."""
    since = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    commits = []
    page = 1
    while True:
        rows = get(f"/commits?sha=main&since={since}&per_page=100&page={page}")
        for c in rows:
            sha = c["sha"]
            prs = [p for p in get(f"/commits/{sha}/pulls") if p.get("merged_at")
                   and (p.get("base") or {}).get("ref") == "main"]
            wf = False
            if not prs:
                files = get(f"/commits/{sha}").get("files") or []
                wf = any(str(f.get("filename", "")).startswith(".github/workflows/") for f in files)
            commits.append({"at": (c.get("commit") or {}).get("committer", {}).get("date"),
                            "pr": prs[0]["number"] if prs else None, "workflows": wf})
        if len(rows) < 100:
            break
        page += 1
    settings = []
    for r in get("/rulesets"):
        detail = get(f"/rulesets/{r['id']}")
        settings.append({"kind": "ruleset", "name": detail.get("name"), "updated_at": detail.get("updated_at")})
    for e in get("/environments").get("environments") or []:
        settings.append({"kind": "environment", "name": e.get("name"), "updated_at": e.get("updated_at")})
    return {"commits": commits, "settings": settings}


# --- judging ---------------------------------------------------------------------------

def watched(ev):
    src = ev.get("EventSource")
    if src == "s3.amazonaws.com":
        return ev.get("EventName") in S3_EVENTS
    return src in WATCHED_SOURCES


def principal(ev):
    """(category, expected) for an event's principal. Names never leave this function."""
    ui = ev.get("userIdentity") or {}
    kind = ui.get("type") or "Unknown"
    if kind == "AWSService":
        return "aws-service", True
    if kind == "AssumedRole":
        issuer = ((ui.get("sessionContext") or {}).get("sessionIssuer") or {})
        role = issuer.get("userName") or ""
        if role in CI_ROLES:
            return f"ci-role:{CI_ROLES[role]}", True
        if "/aws-service-role/" in str(issuer.get("arn") or ""):
            return "aws-service-linked-role", True
        return "AssumedRole (not a CI role)", False
    if ev.get("EventSource") == "cognito-idp.amazonaws.com" and ev.get("EventName") in COGNITO_USER_FLOWS \
            and kind in ("Unknown", "") and not ui.get("arn"):
        return "cognito-app-user", True
    return kind, False


def evaluate(ev, now):
    """IEC-CSO-EFR: the automated incident evaluation of one unexpected event."""
    why = REPORTABLE.get(ev.get("EventName"))
    if why:
        reason = (f"Unexpected principal: {why}. That can hide or enable a compromise of the system's "
                  "integrity, so it is evaluated as a possible FedRAMP Reportable Incident until a reviewed change "
                  "explains it.")
    else:
        reason = ("Unexpected principal, but the write neither silences the audit record, disables a key, "
                  "creates long-lived credentials nor opens public access: a process finding (VDR-CSO-FAV), not "
                  "a reportable incident.")
    return {"evaluated_at": now.isoformat(), "reportable": bool(why), "basis": "IEC-CSO-EFR (automated rule)",
            "reason": reason, "federal_customer_data_considered": "The system holds no federal customer data."}


def judge(events, now):
    """(expected counts by principal category, [unexpected entries])."""
    counts, unexpected = {}, []
    for ev in events:
        if not watched(ev):
            continue
        cat, ok = principal(ev)
        if ok:
            counts[cat] = counts.get(cat, 0) + 1
            continue
        unexpected.append({"source": "cloudtrail", "service": WATCHED_SOURCES.get(ev["EventSource"], "S3"),
                           "event": ev.get("EventName"), "at": ev.get("EventTime"), "region": ev.get("region"),
                           "principalType": cat, **({"errorCode": ev["errorCode"]} if ev.get("errorCode") else {}),
                           "evaluation": evaluate(ev, now)})
    return dict(sorted(counts.items())), unexpected


def judge_github(gh, start, now):
    out = []
    for c in gh["commits"]:
        if c["pr"] is None:
            what = "a workflow change on main with no merged pull request" if c["workflows"] else \
                "a commit on main with no merged pull request"
            out.append({"source": "github", "event": what, "at": c["at"],
                        "evaluation": evaluate({"EventName": "GitHubChange"}, now)})
    for s in gh["settings"]:
        at = sr._ts(s.get("updated_at"))
        if at is not None and at >= start:
            out.append({"source": "github", "event": f"the {s['kind']} {s['name']!r} changed outside a pull request",
                        "at": s["updated_at"], "evaluation": evaluate({"EventName": "GitHubSetting"}, now)})
    return out


def window(previous, now):
    """[start, now]: from the previous review's end (at most MAX_WINDOW_DAYS back), else the last 36 hours."""
    prev_end = sr._ts(((previous or {}).get("window") or {}).get("to")) if isinstance(previous, dict) else None
    floor = now - timedelta(days=MAX_WINDOW_DAYS)
    start = prev_end if prev_end and floor <= prev_end <= now else now - timedelta(hours=DEFAULT_WINDOW_HOURS)
    return start.replace(microsecond=0), now.replace(microsecond=0)


def exercise(now):
    _, caught = judge(INTRUDER_EVENTS, now)
    ok = len(caught) == len(INTRUDER_EVENTS) and all(c["evaluation"]["reportable"] for c in caught)
    for c in caught:
        c["principalType"] = f"{c['principalType']} ({sr.CAST['intruder']})"
    return {"intruder": sr.CAST["intruder"], "planted": len(INTRUDER_EVENTS), "caught": ok, "events": caught,
            "note": EXERCISE_NOTE, "statement": _engagement.SHORT}


def build(cloudtrail, gh, start, now, fedramp_id, read_errors=()):
    counts, unexpected = judge(cloudtrail, now)
    unexpected += judge_github(gh, start, now) if gh is not None else []
    ex = exercise(now)
    checks = [
        {"id": "cloudtrail-read", "title": f"CloudTrail event history read in {', '.join(REGIONS)}",
         "result": "fail" if read_errors else "pass", "detail": "; ".join(read_errors) or f"{len(cloudtrail)} write "
                                                                                          "event(s) read"},
        {"id": "github-read", "title": "Commits on main, rulesets and environments read from GitHub",
         "result": "pass" if gh is not None else "fail",
         "detail": f"{len(gh['commits'])} commit(s), {len(gh['settings'])} setting(s)" if gh is not None
         else "GitHub could not be read"},
        {"id": "intruder-caught", "title": f"The planted events of {sr.CAST['intruder']} were caught and evaluated "
                                           "reportable", "result": "pass" if ex["caught"] else "fail",
         "detail": f"{len(ex['events'])} of {ex['planted']} caught"},
    ]
    reportable = sum(1 for u in unexpected if u["evaluation"]["reportable"])
    doc = {"schema": SCHEMA, "fedRampId": fedramp_id, "title": "Audit-log review (automated, every night)",
           "rules": ["KSI-MLA-RVL", "KSI-CMT-RVP"], "controls": ["au-6", "si-4", "cm-3"],
           "generated_at": now.isoformat(), "window": {"from": start.isoformat(), "to": now.isoformat()},
           "method": "scripts/audit-log-review.py: CloudTrail LookupEvents write events and GitHub's record of main, "
                     "judged by rule; nobody reads the logs by hand (DEC-195).",
           "expectedPrincipals": "The five CI roles (deploy, plan, nightly, package-maintenance, incident-reports), "
                                 "AWS acting on its own account, and Cognito app users' own sign-in flows.",
           "checks": checks, "result": sr.result_of(checks),
           "expected": counts, "unexpected": unexpected,
           "findings": {"unexpected": len(unexpected), "reportable": reportable,
                        "processFinding": "process-audit-log.unexpected" if unexpected else None},
           "exercise": ex}
    return sr.finish(doc, "the audit-log review")


def enforce(doc):
    """Block (gate check audit-log.reportable): a real event evaluated reportable stops the run."""
    reg = _gates.load_gate_modes()
    n = (doc.get("findings") or {}).get("reportable", 0)
    if n and _gates.blocks(reg, "audit-log.reportable"):
        print(f"::error::audit-log review: {n} unexpected write(s) evaluated as a possible FedRAMP Reportable "
              "Incident; see vdr-audit-log-review.json and docs/incident-response.md")
        return 1
    if doc.get("result") != "pass":
        print("::error::audit-log review: a check failed (see its checks)")
        return 1
    print(f"audit-log review: {doc['findings']['unexpected']} unexpected, none reportable; intruder caught")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default="vdr-audit-log-review.json")
    ap.add_argument("--previous", default=None, help="the published review this run follows (signature verified)")
    ap.add_argument("--cloudtrail-events", default=None, help="read events from this file instead of AWS (tests)")
    ap.add_argument("--github-records", default=None, help="read GitHub records from this file instead (tests)")
    ap.add_argument("--now", default=None, help=argparse.SUPPRESS)
    ap.add_argument("--enforce", default=None, metavar="REVIEW", help="exit 1 on a reportable event in REVIEW")
    a = ap.parse_args(argv)
    if a.enforce:
        return enforce(json.loads(Path(a.enforce).read_text()))
    now = sr.now_utc(a.now)
    prev_path = Path(a.previous) if a.previous else None
    previous = json.loads(prev_path.read_text()) if prev_path and prev_path.is_file() else None
    start, end = window(previous, now)
    errors = []
    if a.cloudtrail_events:
        events = json.loads(Path(a.cloudtrail_events).read_text())
    else:
        events = []
        for region in REGIONS:
            try:
                events += [_event(e, region) for e in aws_lookup(region, start, end)]
            except AccessDenied:
                _fail("the nightly role cannot call cloudtrail:LookupEvents (AccessDenied). Apply "
                      "infrastructure/bootstrap/evidence-nightly.tf (statement AuditLogReviewReads); the deploy's "
                      "secure-configuration comparison (role-reads-nightly) fails until it is applied")
    if a.github_records:
        gh = json.loads(Path(a.github_records).read_text())
    else:
        try:
            gh = read_github(github_reader(), start)
        except (OSError, ValueError, KeyError, urllib.error.URLError) as exc:
            errors.append(f"GitHub could not be read ({type(exc).__name__})")
            gh = None
    doc = build(events, gh, start, end, _offering.fedramp_id(), errors)
    if doc["unexpected"]:
        reg = _gates.load_gate_modes()
        _gates.record_event(reg, "audit-log.unexpected",
                            f"{len(doc['unexpected'])} unexpected change(s) in the audit-log window "
                            f"({doc['findings']['reportable']} evaluated reportable); see vdr-audit-log-review.json")
    Path(a.out).write_text(json.dumps(doc, indent=2) + "\n")
    print(f"audit-log review {start.isoformat()} to {end.isoformat()}: {len(events)} write event(s) read, "
          f"{len(doc['unexpected'])} unexpected, intruder {'caught' if doc['exercise']['caught'] else 'MISSED'}")
    # Published whatever its result; --enforce, after the publish, fails the run on a
    # failed check or a reportable event, so the record of a bad night is never lost.
    return 0


if __name__ == "__main__":
    sys.exit(main())
