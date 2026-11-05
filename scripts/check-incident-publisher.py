#!/usr/bin/env python3
"""Deploy preflight: the unattended incident report publisher is in place.

The FedRAMP incident report records (IEC-CSO-IIR/OIR/FIR/AIR) describe the
system as it is after a successful deploy, so a deploy must not succeed
without the prerequisites they rely on. Run early in the deploy job, before
anything is applied, this fails the deploy unless:

  1. the repository variable AWS_INCIDENT_REPORTS_ROLE_ARN is set, and
  2. it names the role infrastructure/bootstrap/incident-reports.tf creates
     (github-actions-incident-reports-oidc, an IAM role ARN), and
  3. the `incident-reports` GitHub Environment exists and deploys only from
     main (a custom branch policy naming exactly `main`).

Check 3 reads GitHub's API with the job token. A missing environment (404)
fails. If the token cannot read the environment at all (any other error), the
check is reported as not observed and the deploy continues on checks 1-2:
the deploy's later incident-publisher job assumes the role from that
environment, so a wrong environment still fails the deploy there.

Whether the role itself works is proved later in the same run: the
`incident-publisher` job calls .github/workflows/incident-reports.yml, which
assumes the role, publishes, and fails the deploy if it cannot.

Prints no ARN or account ID. Exit 0 pass, 1 fail.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Any

EXPECTED_ROLE_NAME = "github-actions-incident-reports-oidc"
ENVIRONMENT = "incident-reports"
EXPECTED_BRANCHES = {"main"}
ROLE_ARN_RE = re.compile(r"^arn:aws(-[a-z]+)*:iam::[0-9]{12}:role/(?:[\w+=,.@-]+/)*([\w+=,.@-]+)$")


def check_variable(role_arn: str | None) -> list[str]:
    if not role_arn or not role_arn.strip():
        return ["the repository variable AWS_INCIDENT_REPORTS_ROLE_ARN is not set: apply "
                "infrastructure/bootstrap/incident-reports.tf and set it from the incident_reports_role_arn output"]
    m = ROLE_ARN_RE.match(role_arn.strip())
    if not m:
        return ["AWS_INCIDENT_REPORTS_ROLE_ARN is not an IAM role ARN"]
    if m.group(2) != EXPECTED_ROLE_NAME:
        return [f"AWS_INCIDENT_REPORTS_ROLE_ARN names a role other than {EXPECTED_ROLE_NAME}"]
    return []


def check_environment(env: dict[str, Any] | None, branch_policies: list[str] | None) -> tuple[list[str], str]:
    """(problems, note). env None = the environment does not exist."""
    if env is None:
        return [f"the {ENVIRONMENT} GitHub Environment does not exist"], ""
    policy = env.get("deployment_branch_policy") or {}
    if not policy.get("custom_branch_policies") or policy.get("protected_branches"):
        return [f"the {ENVIRONMENT} environment does not restrict deployments to a custom branch list"], ""
    if branch_policies is None:
        return [], "branch policies not observed"
    if set(branch_policies) != EXPECTED_BRANCHES:
        return [f"the {ENVIRONMENT} environment deploys from {sorted(branch_policies) or 'no branch'}, "
                "not only main"], ""
    return [], f"{ENVIRONMENT} deploys only from main"


def _get(url: str, token: str | None) -> Any:
    if not url.startswith("https://"):
        raise ValueError("refusing non-HTTPS URL")
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "samaydlette-preflight"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=15) as r:  # noqa: S310
        return json.loads(r.read().decode())


def read_environment(repo: str, token: str | None) -> tuple[str, dict[str, Any] | None, list[str] | None]:
    """("ok"|"missing"|"unreadable", environment, branch policy names)."""
    api = f"https://api.github.com/repos/{repo}/environments/{ENVIRONMENT}"
    try:
        env = _get(api, token)
    except urllib.error.HTTPError as exc:
        return ("missing" if exc.code == 404 else "unreadable"), None, None
    except Exception:  # noqa: BLE001 (any other failure: not observed)
        return "unreadable", None, None
    try:
        pols = _get(f"{api}/deployment-branch-policies", token)
        names = [p.get("name", "") for p in pols.get("branch_policies", [])]
    except Exception:  # noqa: BLE001
        names = None
    return "ok", env, names


def evaluate(role_arn: str | None, env_state: str, env: dict[str, Any] | None,
             branch_policies: list[str] | None) -> tuple[list[str], list[str]]:
    """(problems, notes) for one run; pure, for tests."""
    problems = check_variable(role_arn)
    notes = []
    if env_state == "unreadable":
        notes.append(f"the {ENVIRONMENT} environment could not be read with the job token; not observed "
                     "(the incident-publisher job still fails the deploy if the role cannot be assumed from it)")
    else:
        p, note = check_environment(env if env_state == "ok" else None, branch_policies)
        problems += p
        if note:
            notes.append(note)
    return problems, notes


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fixture", default=None,
                    help="JSON {role_arn, env_state, environment, branch_policies} instead of live reads (tests)")
    a = ap.parse_args(argv)
    if a.fixture:
        with open(a.fixture) as fh:
            fx = json.load(fh)
        problems, notes = evaluate(fx.get("role_arn"), fx["env_state"], fx.get("environment"),
                                   fx.get("branch_policies"))
    else:
        state, env, pols = read_environment(os.environ.get("GITHUB_REPOSITORY", "sam-aydlette/samaydlette.com"),
                                            os.environ.get("GITHUB_TOKEN"))
        problems, notes = evaluate(os.environ.get("INCIDENT_REPORTS_ROLE_ARN"), state, env, pols)
    for n in notes:
        print(f"incident publisher preflight: {n}")
    for p in problems:
        print(f"::error::incident publisher preflight: {p}")
    if not problems:
        print("incident publisher preflight: role variable names the incident-reports role; ok")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
