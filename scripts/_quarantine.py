"""The quarantine responder (KSI-IAM-SUS; AC-2(3), AC-2(13), IR-4): an IAM
principal named by a reportable audit-log finding is secured with no person in
the loop.

scripts/audit-log-review.py calls `respond` for every unexpected CloudTrail
write it evaluates as a possible FedRAMP Reportable Incident. When the event
names an IAM user or role, the responder:

  1. refuses, without any IAM call, a principal of the CI/CD trust root (the
     five CI roles and the responder itself): quarantining the trust root is a
     person's decision, and the role cannot do it anyway (an explicit Deny in
     infrastructure/bootstrap/quarantine-responder.tf);
  2. attaches AWS's managed deny-all policy (QUARANTINE_POLICY_ARN) to the user
     or role, the only policy its role may attach (the IAM condition
     iam:PolicyARN), so every request the principal makes is denied from the
     next request on, sessions already issued included;
  3. reads the attachment back, and
  4. pages the operator through the evidence-alerts SNS topic (the same topic
     the evidence watchdog's alarms use), naming the principal in the page; the
     page is private, so the published record names only its kind. Every
     reportable event pages, refused and impossible quarantines included.

Why a managed policy, not an inline one: IAM has no condition key for an
inline policy's name or document, so a role allowed to put "the quarantine
inline policy" could put any inline policy (an Allow of everything) and is an
administrator in all but name. Attach and detach can be conditioned on the
policy's ARN, so this role can only ever attach deny-all.

Nothing removes a real quarantine automatically: the operator removes it after
the incident procedure (docs/incident-response.md). The nightly drill
(`drill`, run by the audit-log review on every run) quarantines a permissionless
stand-in role, verifies the deny, removes it and verifies the removal; a
planted request to quarantine a trust-root role must be refused with no IAM
call. The drill does not page: a nightly page would teach the operator to
ignore pages. tests/test_quarantine_responder.py exercises the paging call
against a stub.

The AWS CLI runs under the responder's own profile (configured by
evidence-nightly.yml, step "Quarantine responder credentials (profile only)"),
never under the nightly role's environment credentials. Published output carries
event names, times and principal kinds only: no ARN, account ID, user or role
name.
"""

import json
import os
import re
import subprocess
import time

QUARANTINE_POLICY_ARN = "arn:aws:iam::aws:policy/AWSDenyAll"
QUARANTINE_POLICY = "AWSDenyAll (AWS managed: denies every action)"
PROFILE = "quarantine-responder"
REGION = "us-east-2"
RESPONDER_ROLE = "github-actions-quarantine-responder-oidc"
# The drill's stand-in principal: a role with no permissions that nobody can assume.
TARGET_ROLE = "samaydlette-com-quarantine-target"
TARGET_ADDRESS = "aws_iam_role.quarantine_target (infrastructure/bootstrap/quarantine-responder.tf)"
# The CI/CD trust root: never quarantined by a machine (also denied in IAM).
TRUST_ROOT = frozenset({"github-actions-deploy-oidc", "github-actions-plan-oidc",
                        "github-actions-evidence-nightly-oidc", "github-actions-package-maintenance-oidc",
                        "github-actions-incident-reports-oidc", RESPONDER_ROLE})
ALERT_TOPIC = "samaydlette-com-evidence-alerts"
# IAM's own character set and length for user and role names: anything else in
# an event is not passed to the AWS CLI (defence in depth; the CLI is called
# with an argument list, never a shell).
IAM_NAME = re.compile(r"[\w+=,.@-]{1,128}", re.ASCII)
VERIFY_TRIES = 6
VERIFY_DELAY_SECONDS = 2.0


class IamError(Exception):
    """An IAM or SNS call failed; the message carries the error code only."""


def target_of(event):
    """("role" | "user", name) for the IAM principal an event names, or (None, why)."""
    ui = event.get("userIdentity") or {}
    kind = ui.get("type")
    if kind in ("IAMUser", "AssumedRole"):
        issuer = (ui.get("sessionContext") or {}).get("sessionIssuer") or {}
        name = ui.get("userName") if kind == "IAMUser" else issuer.get("userName")
        if name and not (isinstance(name, str) and IAM_NAME.fullmatch(name)):
            return None, "a principal whose name is not a valid IAM user or role name"
    if kind == "IAMUser" and ui.get("userName"):
        return "user", ui["userName"]
    if kind == "AssumedRole":
        issuer = (ui.get("sessionContext") or {}).get("sessionIssuer") or {}
        if issuer.get("type") == "Role" and issuer.get("userName"):
            if "/aws-service-role/" in str(issuer.get("arn") or "") or "/aws-reserved/" in str(issuer.get("arn") or ""):
                return None, "an AWS service-linked or reserved role, which IAM does not let a policy be attached to"
            return "role", issuer["userName"]
        return None, "an assumed-role session whose role the event does not name"
    if kind == "Root":
        return None, "the account root user, which no IAM policy can restrict"
    return None, f"a {kind or 'unknown'} principal, not an IAM user or role"


# --- the AWS side -------------------------------------------------------------------------

def _env(profile):
    """The environment for a responder call: its own profile, never the nightly
    role's environment credentials."""
    env = {k: v for k, v in os.environ.items()
           if k not in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE")}
    env["AWS_PROFILE"] = profile
    return env


def _code(stderr):
    for word in ("AccessDenied", "NoSuchEntity", "LimitExceeded", "UnmodifiableEntity", "NotFound",
                 "AuthorizationError", "ExpiredToken", "InvalidClientTokenId"):
        if word in stderr:
            return word
    return "Unknown"


class AwsCli:
    """The responder's IAM and SNS calls through the AWS CLI, under its own profile."""

    def __init__(self, profile=PROFILE, region=REGION):
        self.profile, self.region = profile, region

    def _run(self, args):
        p = subprocess.run(["aws", *args, "--output", "json"], capture_output=True, text=True,  # nosec B603
                           timeout=60, check=False, env=_env(self.profile))
        if p.returncode != 0:
            raise IamError(f"aws {args[0]} {args[1]}: {_code(p.stderr)}")
        return json.loads(p.stdout or "{}")

    def attach(self, kind, name):
        self._run(["iam", f"attach-{kind}-policy", f"--{kind}-name", name, "--policy-arn", QUARANTINE_POLICY_ARN])

    def detach(self, kind, name):
        self._run(["iam", f"detach-{kind}-policy", f"--{kind}-name", name, "--policy-arn", QUARANTINE_POLICY_ARN])

    def attached(self, kind, name):
        out = self._run(["iam", f"list-attached-{kind}-policies", f"--{kind}-name", name])
        return [p.get("PolicyArn") for p in out.get("AttachedPolicies") or []]

    def page(self, subject, message):
        account = self._run(["sts", "get-caller-identity"])["Account"]
        topic = f"arn:aws:sns:{self.region}:{account}:{ALERT_TOPIC}"
        self._run(["sns", "publish", "--region", self.region, "--topic-arn", topic,
                   "--subject", subject[:99], "--message", message])


def _verify(iam, kind, name, want_attached, sleep=time.sleep):
    """Read the attachment back until it shows the wanted state (IAM is
    eventually consistent); True when it does."""
    for i in range(VERIFY_TRIES):
        if (QUARANTINE_POLICY_ARN in iam.attached(kind, name)) == want_attached:
            return True
        if i < VERIFY_TRIES - 1:
            sleep(VERIFY_DELAY_SECONDS)
    return False


# --- responding ---------------------------------------------------------------------------

def quarantine(iam, kind, name, sleep=time.sleep):
    """Attach the deny-all policy and read it back: (action, detail). Refuses the
    trust root before any call."""
    if kind == "role" and name in TRUST_ROOT:
        return "refused", "a CI/CD trust-root role: quarantining it is the operator's decision (and IAM denies it)"
    try:
        iam.attach(kind, name)
        if not _verify(iam, kind, name, True, sleep):
            return "failed", "the deny-all policy did not read back as attached"
    except IamError as exc:
        return "failed", str(exc)
    return "quarantined", f"{QUARANTINE_POLICY} attached and read back"


def respond(event, iam, now, sleep=time.sleep):
    """The published record of the response to one reportable event, and
    whether it was handled (quarantined, refused by design, or not an IAM
    principal). Pages on a quarantine and on a failure."""
    kind, name = target_of(event)
    rec = {"event": event.get("EventName"), "at": event.get("EventTime"), "respondedAt": now.isoformat()}
    if kind is None:
        rec.update(action="not-applicable", detail=f"The event names {name}.", principalKind="other")
    elif iam is None:
        rec.update(action="failed", principalKind=kind,
                   detail="The responder's credentials were not available to this run.")
    else:
        action, detail = quarantine(iam, kind, name, sleep)
        rec.update(action=action, detail=detail, principalKind=kind)
    # Every reportable event pages, whatever the response: a refused or
    # impossible quarantine needs a person even more than a successful one.
    if iam is not None:
        what = f"IAM {kind} {name}" if kind else "a principal"
        try:
            iam.page(f"Quarantine {rec['action']}: {what}",
                     f"The nightly audit-log review evaluated {rec['event']} at {rec['at']} by {what} as a possible "
                     f"FedRAMP Reportable Incident. Response: {rec['action']} ({rec['detail']}). "
                     "Follow docs/incident-response.md; the quarantine stays until a person removes it.")
            rec["paged"] = True
        except IamError as exc:
            rec["paged"] = False
            rec["detail"] += f" The page failed ({exc})."
    else:
        rec["paged"] = False
    rec["handled"] = rec["action"] in ("quarantined", "refused", "not-applicable") and rec["paged"]
    return rec


# --- the nightly drill --------------------------------------------------------------------

class Recording:
    """Wraps an IAM client and counts its calls (the drill proves a refusal made none)."""

    def __init__(self, inner):
        self.inner, self.calls = inner, 0

    def __getattr__(self, attr):
        fn = getattr(self.inner, attr)

        def call(*a, **k):
            self.calls += 1
            return fn(*a, **k)
        return call


def drill(iam, judge, planted, forged, now, sleep=time.sleep):
    """Quarantine the stand-in role the planted event names, verify the deny,
    remove it and verify the removal; then feed the forged trust-root request
    through the same function, which must be refused with no IAM call.
    `judge` is the audit-log review's rule set; `planted` must reach the
    responder only by being judged unexpected and reportable."""
    steps, checks = [], []

    def check(cid, title, ok, detail):
        checks.append({"id": cid, "title": title, "result": "pass" if ok else "fail", "detail": detail})

    _, caught = judge([planted], now)
    detected = len(caught) == 1 and caught[0]["evaluation"]["reportable"]
    check("detected", "The planted event was judged unexpected and reportable by the audit-log rules", detected,
          f"{len(caught)} of 1 caught" + (", evaluated reportable" if detected else ""))
    kind, name = target_of(planted)
    stand_in = (kind, name) == ("role", TARGET_ROLE)
    check("stand-in", "The principal the planted event names is the drill's stand-in role and nothing else",
          stand_in, f"the event names {'the stand-in role ' + TARGET_ADDRESS if stand_in else 'another principal'}")
    if iam is None:
        check("quarantined", "The stand-in role was quarantined and the deny read back", False,
              "the responder's credentials were not available to this run")
    elif detected and stand_in:
        action, detail = quarantine(iam, kind, name, sleep)
        steps.append({"step": "quarantine", "result": action, "detail": detail})
        check("quarantined", "The stand-in role was quarantined and the deny read back", action == "quarantined",
              detail)
        removed = False
        try:
            iam.detach(kind, name)
            removed = _verify(iam, kind, name, False, sleep)
            detail = "detached and read back as gone" if removed else "still attached after detaching"
        except IamError as exc:
            detail = str(exc)
        steps.append({"step": "release", "result": "released" if removed else "failed", "detail": detail})
        check("released", "The drill's quarantine was removed and its removal read back", removed, detail)
    rec = Recording(iam) if iam is not None else None
    fk, fname = target_of(forged)
    action, detail = quarantine(rec, fk, fname, sleep) if rec is not None else ("failed", "no credentials")
    refused = action == "refused" and rec is not None and rec.calls == 0
    check("trust-root-refused", "A planted request to quarantine a CI/CD trust-root role was refused with no IAM call",
          refused, f"{action}; {rec.calls if rec else 0} IAM call(s) made")
    return {"checks": checks, "steps": steps, "result": "pass" if all(c["result"] == "pass" for c in checks)
            else "fail"}
