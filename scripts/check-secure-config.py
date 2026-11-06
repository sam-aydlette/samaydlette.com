#!/usr/bin/env python3
"""Compare the live settings of the top-level and privileged accounts with the
Secure Configuration Guide's recommended defaults (SCG-ENH-CMP), and export
them as JSON (SCG-ENH-EXP): /.well-known/security-settings.json and .md.

Runs in the deploy, before the Security Decision Record is built. Every read is
read-only (AWS CLI with the deploy role; GitHub's API with the run's token). A
setting either matches its recommended value, or differs and is covered by the
in-force decision the guide cites (an accepted deviation), or is attested by a
decision because no API exposes it to this run. Anything else, a deviation no
decision covers or a setting that could not be read, fails the deploy: the
published comparison is then never stale or partial.

Published values are counts, booleans and policy values only: never an account
ID, an ARN, an IAM user or role name, or an email address.

It also checks the security.txt the deploy publishes (KSI-PIY-RVD, RFC 9116):
a Contact, a Policy, the Canonical URL, and an Expires date in the future and
no more than a year away. The result is `securityTxt` in the same record. An
invalid file is a warning, not a failure: the deploy does not stop on a date,
so nobody is committed to renewing the file by hand; the KSI method that reads
this result (infrastructure/schemas/ksi-methods.json, security-txt) stops
counting instead, and the Security Decision Record says why.
"""

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _offering  # noqa: E402
import _decisions  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
SOURCE = REPO / "data" / "secure-configuration.json"
SECURITY_TXT = REPO / "website" / ".well-known" / "security.txt"
SECURITY_TXT_CANONICAL = "https://samaydlette.com/.well-known/security.txt"
SCHEMA = "security-settings/1"
REGION = "us-east-2"
OPERATOR_GROUP = "operators"
# The CI roles' names, as infrastructure/bootstrap names them (read, never published).
ROLES = {"role-trust-deploy": "github-actions-deploy-oidc",
         "role-trust-plan": "github-actions-plan-oidc",
         "role-trust-nightly": "github-actions-evidence-nightly-oidc",
         "role-trust-maintenance": "github-actions-package-maintenance-oidc",
         "role-trust-incident": "github-actions-incident-reports-oidc",
         "role-trust-responder": "github-actions-quarantine-responder-oidc",
         "role-trust-quarantine-target": "samaydlette-com-quarantine-target"}
# The unattended roles' write scope: {check id: (role, inline policy name)}. The
# value compared is the object keys each may put (the bucket part of the S3 ARN
# removed), so a grant the deploy's publishers need but bootstrap does not yet
# hold is a deviation, and the deploy stops before the SDR is built.
ROLE_SCOPES = {"role-scope-maintenance": ("github-actions-package-maintenance-oidc", "package-maintenance-publish")}
# The unattended roles' read grants compared action for action: {check id: (role,
# inline policy name)}. The nightly's audit-log review needs cloudtrail:LookupEvents;
# a deploy whose bootstrap lacks it stops before the SDR is built.
ROLE_READS = {"role-reads-nightly": ("github-actions-evidence-nightly-oidc", "evidence-nightly-audit-log-review")}
# The quarantine responder's one policy: the actions it allows and the only
# managed policy its attach and detach may name (iam:PolicyARN), compared whole.
ROLE_RESPONDER = {"role-actions-responder": ("github-actions-quarantine-responder-oidc", "quarantine-responder")}
# The nightly's recovery-drill grant: "<action> <bucket>[/<key pattern>]" for
# every S3 grant in it, so a grant on any other bucket is a deviation. S3 ARNs
# carry no account, so the value is publishable.
ROLE_S3_GRANTS = {"role-scope-nightly-drill": ("github-actions-evidence-nightly-oidc", "evidence-nightly-recovery-drill")}
SUB_KEY = "token.actions.githubusercontent.com:sub"
READ_ONLY_MANAGED = {"ReadOnlyAccess", "SecurityAudit", "ViewOnlyAccess"}
READ_VERBS = ("Get", "List", "Describe", "Search", "BatchGet", "Lookup", "View")


class ReadError(Exception):
    """A setting could not be read."""


class AwsError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def aws(args):
    """Run a read-only AWS CLI call; JSON out, or AwsError with the error code."""
    p = subprocess.run(["aws", *args, "--output", "json"], capture_output=True, text=True, timeout=60)
    if p.returncode != 0:
        code = "Unknown"
        for word in ("NoSuchEntity", "AccessDenied", "AccessDeniedException", "NoSuchPublicAccessBlockConfiguration"):
            if word in p.stderr:
                code = word
                break
        raise AwsError(code)
    return json.loads(p.stdout or "{}")


# --- comparison -----------------------------------------------------------------------

def matches(recommended, current):
    """Recommended values are literals, {"at_least": n}, {"at_most": n}, lists
    (compared as sets) or objects of those (every key must match)."""
    if isinstance(recommended, dict):
        if set(recommended) == {"at_least"}:
            return isinstance(current, (int, float)) and not isinstance(current, bool) and current >= recommended["at_least"]
        if set(recommended) == {"at_most"}:
            return isinstance(current, (int, float)) and not isinstance(current, bool) and current <= recommended["at_most"]
        return isinstance(current, dict) and all(k in current and matches(v, current[k]) for k, v in recommended.items())
    if isinstance(recommended, list):
        return isinstance(current, list) and sorted(map(str, recommended)) == sorted(map(str, current))
    return type(recommended) is type(current) and recommended == current


def compare(src, current, in_force):
    """One result per setting. `current` is {check id: value or ReadError}."""
    out = []
    for s in src["settings"]:
        r = {"id": s["id"], "account": s["account"], "setting": s["setting"], "recommended": s["recommended"]}
        if s["check"] == "attested":
            dec = s.get("attested_by")
            r.update(current=None, result="attested" if dec in in_force else "not-read", decision=dec)
        else:
            val = current.get(s["check"], ReadError("no reader for this check"))
            if isinstance(val, ReadError):
                r.update(current=None, result="not-read", detail=str(val))
            elif matches(s["recommended"], val):
                r.update(current=val, result="matches")
            elif s.get("accepted_deviation") in in_force:
                r.update(current=val, result="accepted-deviation", decision=s["accepted_deviation"])
            else:
                r.update(current=val, result="deviation")
        out.append(r)
    return out


# --- readers --------------------------------------------------------------------------

def _guard(fn):
    try:
        return fn()
    except (AwsError, KeyError, TypeError, ValueError, subprocess.SubprocessError, FileNotFoundError) as exc:
        return ReadError(f"{type(exc).__name__}: {getattr(exc, 'code', '')}".rstrip(": "))


def _is_read_only(doc):
    for st in doc.get("Statement", []) if isinstance(doc.get("Statement"), list) else [doc.get("Statement")]:
        if not st or st.get("Effect") != "Allow":
            continue
        actions = st.get("Action", [])
        for a in [actions] if isinstance(actions, str) else actions:
            if a == "*" or ":" not in a:
                return False
            verb = a.split(":", 1)[1]
            if not (verb == "GET" or verb.startswith(READ_VERBS)):
                return False
    return True


def _policy_doc(raw):
    return json.loads(raw) if isinstance(raw, str) else raw


def read_aws(call, pool_id, now=None):
    """{check id: value or ReadError} for every AWS-backed check."""
    out = {}
    summary = _guard(lambda: call(["iam", "get-account-summary"])["SummaryMap"])
    virtual = _guard(lambda: [d.get("User", {}).get("Arn", "") for d in call(
        ["iam", "list-virtual-mfa-devices", "--assignment-status", "Assigned"])["VirtualMFADevices"]])

    def from_summary(key, conv):
        return summary if isinstance(summary, ReadError) else conv(summary[key])

    out["aws-root-mfa-enabled"] = from_summary("AccountMFAEnabled", lambda v: v == 1)
    out["aws-root-access-keys"] = from_summary("AccountAccessKeysPresent", int)
    if isinstance(virtual, ReadError) or isinstance(summary, ReadError):
        out["aws-root-mfa-type"] = virtual if isinstance(virtual, ReadError) else summary
    else:
        out["aws-root-mfa-type"] = summary["AccountMFAEnabled"] == 1 and not any(a.endswith(":root") for a in virtual)

    def password_policy():
        try:
            return call(["iam", "get-account-password-policy"])["PasswordPolicy"]
        except AwsError as e:
            if e.code == "NoSuchEntity":
                return {}
            raise
    out["aws-account-password-policy"] = _guard(password_policy)

    def bpa():
        account = call(["sts", "get-caller-identity"])["Account"]
        try:
            return call(["s3control", "get-public-access-block", "--account-id", account])["PublicAccessBlockConfiguration"]
        except AwsError as e:
            if e.code == "NoSuchPublicAccessBlockConfiguration":
                return {}
            raise
    out["aws-account-s3-bpa"] = _guard(bpa)

    def users():
        names = [u["UserName"] for u in call(["iam", "list-users"])["Users"]]
        groups = {n: [g["GroupName"] for g in call(["iam", "list-groups-for-user", "--user-name", n])["Groups"]]
                  for n in names}
        operators = [n for n in names if OPERATOR_GROUP in groups[n]]
        if len(operators) != 1:
            raise ValueError(f"expected one member of {OPERATOR_GROUP}, found {len(operators)}")
        return names, groups, operators[0]
    roster = _guard(users)
    if isinstance(roster, ReadError):
        for k in ("aws-iam-users", "operator-mfa-enabled", "operator-mfa-type", "operator-console-password",
                  "operator-access-keys"):
            out[k] = roster
    else:
        names, groups, op = roster
        out["aws-iam-users"] = _guard(lambda: sum(1 for n in names if n != op and not _user_read_only(call, n, groups[n])))
        out["operator-mfa-enabled"] = _guard(lambda: len(call(["iam", "list-mfa-devices", "--user-name", op])["MFADevices"]) > 0)
        if isinstance(virtual, ReadError):
            out["operator-mfa-type"] = virtual
        else:
            out["operator-mfa-type"] = _guard(lambda: len(call(["iam", "list-mfa-devices", "--user-name", op])["MFADevices"]) > 0
                                              and not any(a.endswith(f":user/{op}") for a in virtual))
        out["operator-console-password"] = _guard(lambda: _has_login_profile(call, op))
        out["operator-access-keys"] = _guard(lambda: _access_keys(call, op, now))

    for check, role in ROLES.items():
        out[check] = _guard(lambda role=role: _trust_subjects(call(["iam", "get-role", "--role-name", role])["Role"]))
    for check, (role, name) in ROLE_SCOPES.items():
        out[check] = _guard(lambda role=role, name=name: _put_keys(call(
            ["iam", "get-role-policy", "--role-name", role, "--policy-name", name])["PolicyDocument"]))

    for check, (role, name) in ROLE_READS.items():
        out[check] = _guard(lambda role=role, name=name: _allowed_actions(call(
            ["iam", "get-role-policy", "--role-name", role, "--policy-name", name])["PolicyDocument"]))
    for check, (role, name) in ROLE_RESPONDER.items():
        out[check] = _guard(lambda role=role, name=name: _responder_scope(call(
            ["iam", "get-role-policy", "--role-name", role, "--policy-name", name])["PolicyDocument"]))
    for check, (role, name) in ROLE_S3_GRANTS.items():
        out[check] = _guard(lambda role=role, name=name: _s3_grants(call(
            ["iam", "get-role-policy", "--role-name", role, "--policy-name", name])["PolicyDocument"]))

    def cognito():
        if not pool_id:
            raise ValueError("no user pool id was given")
        p = call(["cognito-idp", "describe-user-pool", "--region", REGION, "--user-pool-id", pool_id])["UserPool"]
        pw = p["Policies"]["PasswordPolicy"]
        return {"MfaConfiguration": p.get("MfaConfiguration"),
                "AllowAdminCreateUserOnly": p["AdminCreateUserConfig"]["AllowAdminCreateUserOnly"],
                **{k: pw.get(k) for k in ("MinimumLength", "RequireUppercase", "RequireLowercase",
                                          "RequireNumbers", "RequireSymbols")}}
    out["cognito-pool-policy"] = _guard(cognito)
    return out


def _has_login_profile(call, user):
    try:
        call(["iam", "get-login-profile", "--user-name", user])
        return True
    except AwsError as e:
        if e.code == "NoSuchEntity":
            return False
        raise


def _user_read_only(call, user, groups):
    """True when a user can only read: every attached policy is an AWS read-only
    policy, every inline policy allows only read verbs, the same for its groups,
    and it has no console password."""
    if _has_login_profile(call, user):
        return False
    managed = [p["PolicyName"] for p in call(["iam", "list-attached-user-policies", "--user-name", user])["AttachedPolicies"]]
    inline = [_policy_doc(call(["iam", "get-user-policy", "--user-name", user, "--policy-name", n])["PolicyDocument"])
              for n in call(["iam", "list-user-policies", "--user-name", user])["PolicyNames"]]
    for g in groups:
        managed += [p["PolicyName"] for p in call(["iam", "list-attached-group-policies", "--group-name", g])["AttachedPolicies"]]
        inline += [_policy_doc(call(["iam", "get-group-policy", "--group-name", g, "--policy-name", n])["PolicyDocument"])
                   for n in call(["iam", "list-group-policies", "--group-name", g])["PolicyNames"]]
    return all(m in READ_ONLY_MANAGED for m in managed) and all(_is_read_only(d) for d in inline)


def _access_keys(call, user, now=None):
    now = now or datetime.now(timezone.utc)
    keys = [k for k in call(["iam", "list-access-keys", "--user-name", user])["AccessKeyMetadata"] if k["Status"] == "Active"]
    ages = [(now - datetime.fromisoformat(k["CreateDate"].replace("Z", "+00:00"))).days for k in keys]
    return {"active": len(keys), "oldest_age_days": max(ages) if ages else 0}


def _put_keys(raw):
    """The object keys an inline policy allows s3:PutObject on, without the bucket
    (an S3 object ARN is arn:aws:s3:::<bucket>/<key>; it carries no account)."""
    doc = _policy_doc(raw)
    keys = []
    sts = doc.get("Statement", [])
    for st in [sts] if isinstance(sts, dict) else sts:
        actions = st.get("Action", [])
        if st.get("Effect") != "Allow" or "s3:PutObject" not in ([actions] if isinstance(actions, str) else actions):
            continue
        res = st.get("Resource", [])
        for r in [res] if isinstance(res, str) else res:
            if not r.startswith("arn:aws:s3:::") or "/" not in r:
                raise ValueError("a PutObject resource is not an S3 object ARN")
            keys.append(r.split("/", 1)[1])
    return sorted(keys)


def _allowed_actions(raw):
    """The actions an inline policy allows, sorted (no resources: no ARN, no account)."""
    doc = _policy_doc(raw)
    sts = doc.get("Statement", [])
    out = set()
    for st in [sts] if isinstance(sts, dict) else sts:
        if st.get("Effect") == "Allow":
            acts = st.get("Action", [])
            out |= set([acts] if isinstance(acts, str) else acts)
    return sorted(out)


def _statements(doc):
    sts = doc.get("Statement", [])
    return [sts] if isinstance(sts, dict) else sts


def _list(v):
    return [v] if isinstance(v, str) else list(v or [])


ATTACH_ACTIONS = {"iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:AttachUserPolicy", "iam:DetachUserPolicy"}


def _responder_scope(raw):
    """{allow, attach_only, trust_root_denied}: the actions allowed; the managed
    policy ARNs every attach/detach grant is conditioned to (an unconditioned
    grant reads as ["*"]); and how many trust-root roles the explicit Deny names
    (a count: role names are not published)."""
    doc = _policy_doc(raw)
    allow, only, denied = set(), set(), set()
    for st in _statements(doc):
        acts = set(_list(st.get("Action", [])))
        if st.get("Effect") == "Allow":
            allow |= acts
            if acts & ATTACH_ACTIONS:
                arns = set()
                for test, block in (st.get("Condition") or {}).items():
                    if test in ("ArnEquals", "StringEquals"):
                        arns |= set(_list(block.get("iam:PolicyARN", [])))
                only |= arns or {"*"}
        elif st.get("Effect") == "Deny" and ATTACH_ACTIONS <= acts:
            denied |= {r.rsplit("/", 1)[-1] for r in _list(st.get("Resource", [])) if ":role/" in r and "*" not in r}
    return {"allow": sorted(allow), "attach_only": sorted(only), "trust_root_denied": len(denied)}


def _s3_grants(raw):
    """Sorted "<action> <bucket>[/<key>]" for every Allow in an S3-only policy."""
    out = set()
    for st in _statements(_policy_doc(raw)):
        if st.get("Effect") != "Allow":
            continue
        for r in _list(st.get("Resource", [])):
            if not r.startswith("arn:aws:s3:::"):
                raise ValueError("a grant in the recovery-drill policy is not on an S3 resource")
            out |= {f"{a} {r[len('arn:aws:s3:::'):]}" for a in _list(st.get("Action", []))}
    return sorted(out)


def _trust_subjects(role):
    doc = _policy_doc(role["AssumeRolePolicyDocument"])
    subs = []
    for st in doc.get("Statement", []):
        for cond in (st.get("Condition") or {}).values():
            v = cond.get(SUB_KEY)
            if v is not None:
                subs += [v] if isinstance(v, str) else list(v)
    return sorted(subs)


def read_github(github):
    """{check id: value or ReadError} from check-manual-settings' github result."""
    if github.get("status") == "not_observed" or not github.get("facts"):
        err = ReadError(github.get("detail") or "GitHub settings were not observed")
        return {k: err for k in ("github-prod-reviewer", "github-nightly-branches", "github-main-checks")}
    f = github["facts"]
    return {"github-prod-reviewer": f["prod_required_reviewers"],
            "github-nightly-branches": f["evidence_nightly_branches"],
            "github-main-checks": {"required": f["main_required_checks"], "enforced_for": f["main_checks_enforced_for"]}}


REPOSITORY_CHECKS = ("github-rulesets", "github-dependabot-alerts", "github-workflow-permissions",
                     "github-dependabot-updates")


def read_repository(repo):
    """{check id: value or ReadError} from check-manual-settings' repository read."""
    out = {k: ReadError(v) for k, v in (repo.get("errors") or {}).items()}
    for k, v in (repo.get("facts") or {}).items():
        out[k] = {"undeclared": v["undeclared"], "write_all": v["write_all"]} \
            if k == "github-workflow-permissions" else v
    return {k: out.get(k, ReadError("not read")) for k in REPOSITORY_CHECKS}


def _manual_settings():
    spec = importlib.util.spec_from_file_location("manual_settings", REPO / "scripts" / "check-manual-settings.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# --- security.txt (KSI-PIY-RVD) -------------------------------------------------------

def security_txt(text, now):
    """RFC 9116 validity of the published security.txt: {file, checks, result}."""
    fields = {}
    for k, v in re.findall(r"^([A-Za-z-]+):\s*(\S.*?)\s*$", text or "", re.M):
        fields.setdefault(k.lower(), []).append(v)
    expires = (fields.get("expires") or [None])[0]
    try:
        exp = datetime.fromisoformat(expires.replace("Z", "+00:00")) if expires else None
    except ValueError:
        exp = None
    checks = [
        {"id": "contact", "ok": bool(fields.get("contact")) and all(v.startswith(("https://", "mailto:"))
                                                                 for v in fields.get("contact", [])),
         "detail": "Contact is an https: or mailto: URI"},
        {"id": "policy", "ok": all(v.startswith("https://") for v in fields.get("policy", [])) and
         bool(fields.get("policy")), "detail": "Policy names the disclosure policy over https"},
        {"id": "canonical", "ok": SECURITY_TXT_CANONICAL in fields.get("canonical", []),
         "detail": f"Canonical is {SECURITY_TXT_CANONICAL}"},
        {"id": "expires", "ok": exp is not None and len(fields.get("expires", [])) == 1
         and now < exp <= now + timedelta(days=366),
         "detail": f"exactly one Expires, in the future and no more than a year away ({expires or 'none'})"},
    ]
    return {"file": "website/.well-known/security.txt", "rfc": "RFC 9116", "checks": checks,
            "result": "pass" if all(c["ok"] for c in checks) else "fail"}


# --- output ---------------------------------------------------------------------------

def build(src, results, now, security_txt_result=None):
    tally = {}
    for r in results:
        tally[r["result"]] = tally.get(r["result"], 0) + 1
    return {"schema": SCHEMA, "emitted_at": now.isoformat(timespec="seconds"),
            "guide_version": src["version"],
            "guide": "https://samaydlette.com/.well-known/secure-configuration-guide.json",
            "description": "Every security setting of the top-level administrative and privileged accounts, read live "
                           "during the deploy and compared with the Secure Configuration Guide's recommended defaults "
                           "(SCG-ENH-CMP); this file is the machine-readable export of those settings (SCG-ENH-EXP).",
            "summary": dict(sorted(tally.items())), "settings": results,
            **({"securityTxt": security_txt_result} if security_txt_result else {})}


def failures(doc):
    return [r for r in doc["settings"] if r["result"] in ("deviation", "not-read")]


def _v(v):
    return json.dumps(v, sort_keys=True)


def render_markdown(doc):
    out = ["# Security settings: live comparison with the Secure Configuration Guide", "",
           f"- **Read:** {doc['emitted_at']} | **Guide version:** {doc['guide_version']}",
           f"- **Summary:** {', '.join(f'{k} {v}' for k, v in doc['summary'].items())}",
           f"- {doc['description']}", "",
           "| Setting | Account | Recommended | Current | Result | Decision |", "|---|---|---|---|---|---|"]
    for r in doc["settings"]:
        cur = "—" if r["current"] is None else _v(r["current"])
        out.append(f"| `{r['id']}` | {r['account']} | `{_v(r['recommended'])}` | `{cur}` | {r['result']} | "
                   f"{r.get('decision', '—')} |")
    st = doc.get("securityTxt")
    if st:
        out += ["", f"**security.txt ({st['rfc']}):** {st['result']}: "
                + ", ".join(f"{c['id']} {'ok' if c['ok'] else 'FAILS'}" for c in st["checks"])]
    out += ["", "---", "_Source of truth: the signed `security-settings.json`._"]
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Compare live account settings with the Secure Configuration Guide.")
    ap.add_argument("--source", default=str(SOURCE))
    ap.add_argument("--decisions", default=None)
    ap.add_argument("--cognito-pool-id", default="")
    ap.add_argument("--github-settings", default=None,
                    help="a check-manual-settings.py output to take the GitHub facts from (default: read GitHub now)")
    ap.add_argument("--account", action="append", default=None,
                    help="compare only the settings of this account (repeatable); the nightly compares github-owner")
    ap.add_argument("--security-txt", default=str(SECURITY_TXT), help="the security.txt the deploy publishes")
    ap.add_argument("--output", default="security-settings.json")
    ap.add_argument("--md-output", default="security-settings.md")
    a = ap.parse_args(argv)
    src = json.loads(Path(a.source).read_text())
    if a.account:
        src = {**src, "settings": [s for s in src["settings"] if s["account"] in a.account]}
    in_force = {r["id"] for r in _decisions.in_force(_decisions.load(a.decisions))}
    if a.github_settings:
        checks = json.loads(Path(a.github_settings).read_text())["checks"]
        github = next((c for c in checks if c["id"] == "github_settings"), {"status": "not_observed"})
    else:
        github = _manual_settings().check_github()
    aws_needed = any(not s["account"].startswith("github") for s in src["settings"])
    current = {**(read_aws(aws, a.cognito_pool_id) if aws_needed else {}), **read_github(github),
               **read_repository(_manual_settings().check_repository())}
    now = datetime.now(timezone.utc)
    sec_txt = security_txt(Path(a.security_txt).read_text(encoding="utf-8"), now)
    doc = _offering.stamp_fedramp_id(build(src, compare(src, current, in_force), now, sec_txt))
    Path(a.output).write_text(json.dumps(doc, indent=2) + "\n")
    Path(a.md_output).write_text(render_markdown(doc) + "\n")
    bad = failures(doc)
    for r in bad:
        print(f"::error::secure configuration: {r['id']} is {r['result']}"
              + (f" ({r['detail']})" if r.get("detail") else ""))
    for c in sec_txt["checks"]:
        if not c["ok"]:
            print(f"::warning::security.txt: {c['id']} fails: {c['detail']} (KSI-PIY-RVD method not counted)")
    print(f"security-settings: {doc['summary']}; security.txt {sec_txt['result']}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
