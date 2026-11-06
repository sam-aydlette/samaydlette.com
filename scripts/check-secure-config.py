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
"""

import argparse
import importlib.util
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _offering  # noqa: E402
import _decisions  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
SOURCE = REPO / "data" / "secure-configuration.json"
SCHEMA = "security-settings/1"
REGION = "us-east-2"
OPERATOR_GROUP = "operators"
# The CI roles' names, as infrastructure/bootstrap names them (read, never published).
ROLES = {"role-trust-deploy": "github-actions-deploy-oidc",
         "role-trust-plan": "github-actions-plan-oidc",
         "role-trust-nightly": "github-actions-evidence-nightly-oidc"}
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


# --- output ---------------------------------------------------------------------------

def build(src, results, now):
    tally = {}
    for r in results:
        tally[r["result"]] = tally.get(r["result"], 0) + 1
    return {"schema": SCHEMA, "emitted_at": now.isoformat(timespec="seconds"),
            "guide_version": src["version"],
            "guide": "https://samaydlette.com/.well-known/secure-configuration-guide.json",
            "description": "Every security setting of the top-level administrative and privileged accounts, read live "
                           "during the deploy and compared with the Secure Configuration Guide's recommended defaults "
                           "(SCG-ENH-CMP); this file is the machine-readable export of those settings (SCG-ENH-EXP).",
            "summary": dict(sorted(tally.items())), "settings": results}


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
    doc = _offering.stamp_fedramp_id(build(src, compare(src, current, in_force), datetime.now(timezone.utc)))
    Path(a.output).write_text(json.dumps(doc, indent=2) + "\n")
    Path(a.md_output).write_text(render_markdown(doc) + "\n")
    bad = failures(doc)
    for r in bad:
        print(f"::error::secure configuration: {r['id']} is {r['result']}"
              + (f" ({r['detail']})" if r.get("detail") else ""))
    print(f"security-settings: {doc['summary']}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
