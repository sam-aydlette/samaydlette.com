#!/usr/bin/env python3
"""Check the settings a person applies by hand, on every deploy.

Three parts of this system are configured outside Terraform, by the operator:

  github_settings   the prod environment's required reviewer, the
                    evidence-nightly environment's main-only branch policy, and
                    main's required status checks (GitHub settings)
  dnssec            the DS record at the registrar that anchors the DNSSEC chain
  sns_subscription  the confirmed email subscription on the evidence-alarm topic

Applying them stays a human act. This script makes each one observed: it reads
the live setting, compares it with what is expected here (in code, changed only
in review), and writes one result per check for the trust center. It never
fails the build. A check it cannot perform is reported as not observed, never
as ok. Results carry counts and names of settings only: no ARN, account ID,
email address or reviewer identity.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from typing import Any

SCHEMA = "manual-settings/1"
REPO_SLUG = os.environ.get("GITHUB_REPOSITORY", "sam-aydlette/samaydlette.com")
DOMAIN = os.environ.get("DOMAIN_NAME", "samaydlette.com")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-2")
TOPIC_NAME = DOMAIN.replace(".", "-") + "-evidence-alerts"

# What the hand-applied settings must be. Changing an expectation is a reviewed
# code change, like any other policy.
EXPECTED_REQUIRED_CHECKS = {"Unit tests (pytest + opa test)", "OPA Compliance Check", "Security Scan", "scn-tag"}
EXPECTED_NIGHTLY_BRANCHES = {"main"}
DOH_RESOLVERS = {
    "Cloudflare": "https://cloudflare-dns.com/dns-query",
    "Google": "https://dns.google/resolve",
}
DS_RECORD_TYPE = 43


def _get_json(url: str, headers: dict[str, str] | None = None, timeout: float = 15) -> Any:
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-HTTPS URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "samaydlette-trust-center", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (scheme checked above)
        return json.loads(r.read().decode())


def _result(id_: str, status: str, detail: str, facts: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"id": id_, "status": status, "detail": detail, "facts": facts or {}}


# ---------------------------------------------------------------------------

def evaluate_github(environments: dict[str, Any], nightly_branches: list[str], branch: dict[str, Any]) -> dict[str, Any]:
    envs = {e["name"]: e for e in environments.get("environments", [])}
    problems: list[str] = []

    prod = envs.get("prod")
    reviewers = 0
    if prod is None:
        problems.append("the prod environment does not exist")
    else:
        for rule in prod.get("protection_rules", []):
            if rule.get("type") == "required_reviewers":
                reviewers = len(rule.get("reviewers") or [])
        if reviewers < 1:
            problems.append("the prod environment has no required reviewer")

    if "evidence-nightly" not in envs:
        problems.append("the evidence-nightly environment does not exist")
    elif set(nightly_branches) != EXPECTED_NIGHTLY_BRANCHES:
        problems.append(f"evidence-nightly deploys from {sorted(nightly_branches) or 'any branch'}, not only main")

    protection = branch.get("protection") or {}
    checks = protection.get("required_status_checks") or {}
    required = set(checks.get("contexts") or [])
    missing = sorted(EXPECTED_REQUIRED_CHECKS - required)
    if not branch.get("protected"):
        problems.append("main is not protected")
    if missing:
        problems.append(f"main does not require: {', '.join(missing)}")
    if checks.get("enforcement_level") != "everyone":
        problems.append("main's required checks do not apply to administrators")

    facts = {"prod_required_reviewers": reviewers, "evidence_nightly_branches": sorted(nightly_branches),
             "main_required_checks": sorted(required), "main_checks_enforced_for": checks.get("enforcement_level")}
    if problems:
        return _result("github_settings", "attention", "; ".join(problems).capitalize() + ".", facts)
    return _result("github_settings", "ok",
                   f"prod deploys need {reviewers} reviewer approval; the nightly environment deploys only from main; "
                   f"main requires {len(required)} status checks, for everyone. "
                   "Other branch-protection settings need admin access and are not observed.", facts)


def check_github() -> dict[str, Any]:
    headers = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    api = f"https://api.github.com/repos/{REPO_SLUG}"
    try:
        environments = _get_json(f"{api}/environments", headers)
        policies = _get_json(f"{api}/environments/evidence-nightly/deployment-branch-policies", headers)
        branch = _get_json(f"{api}/branches/main", headers)
    except Exception as exc:  # noqa: BLE001 (any failure means the setting was not observed)
        return _result("github_settings", "not_observed", f"GitHub's API could not be read ({type(exc).__name__}).")
    return evaluate_github(environments, [p.get("name", "") for p in policies.get("branch_policies", [])], branch)


# ---------------------------------------------------------------------------

def evaluate_dnssec(answers: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """answers: resolver name -> DNS-JSON response to a DS query for the domain."""
    validated, with_ds = [], []
    for name, resp in sorted(answers.items()):
        if resp.get("Status") == 0 and resp.get("AD") is True:
            validated.append(name)
        if any(a.get("type") == DS_RECORD_TYPE for a in resp.get("Answer", []) or []):
            with_ds.append(name)
    facts = {"resolvers": sorted(answers), "validated_by": validated, "ds_seen_by": with_ds}
    if len(validated) == len(answers) and len(with_ds) == len(answers):
        return _result("dnssec", "ok", f"The DS record is published and {len(validated)} independent validating "
                       f"resolvers ({', '.join(validated)}) authenticate {DOMAIN}.", facts)
    return _result("dnssec", "attention",
                   f"DNSSEC did not validate on every resolver: DS seen by {with_ds or 'none'}, "
                   f"authenticated by {validated or 'none'}.", facts)


def check_dnssec() -> dict[str, Any]:
    answers: dict[str, dict[str, Any]] = {}
    for name, url in DOH_RESOLVERS.items():
        try:
            answers[name] = _get_json(f"{url}?name={DOMAIN}&type=DS", {"Accept": "application/dns-json"})
        except Exception:  # noqa: BLE001, S112 (a resolver we cannot reach is left out, and reported)
            continue
    if not answers:
        return _result("dnssec", "not_observed", "No DNS-over-HTTPS resolver could be reached.")
    result = evaluate_dnssec(answers)
    unreached = sorted(set(DOH_RESOLVERS) - set(answers))
    if unreached and result["status"] == "ok":
        result["detail"] += f" Not reached: {', '.join(unreached)}."
    return result


# ---------------------------------------------------------------------------

def evaluate_sns(attributes: dict[str, str]) -> dict[str, Any]:
    confirmed = int(attributes.get("SubscriptionsConfirmed", "0"))
    pending = int(attributes.get("SubscriptionsPending", "0"))
    facts = {"confirmed": confirmed, "pending": pending}
    if confirmed >= 1 and pending == 0:
        return _result("sns_subscription", "ok", f"{confirmed} confirmed subscription(s) receive the evidence alarms.", facts)
    if confirmed == 0:
        return _result("sns_subscription", "attention",
                       "No confirmed subscription: evidence alarms reach no one." + (f" {pending} awaiting confirmation." if pending else ""), facts)
    return _result("sns_subscription", "attention", f"{confirmed} confirmed, {pending} awaiting confirmation.", facts)


def check_sns() -> dict[str, Any]:
    try:
        account = subprocess.run(["aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text"],
                                 capture_output=True, text=True, check=True, timeout=30).stdout.strip()
        out = subprocess.run(["aws", "sns", "get-topic-attributes", "--region", AWS_REGION, "--topic-arn",
                              f"arn:aws:sns:{AWS_REGION}:{account}:{TOPIC_NAME}", "--output", "json"],
                             capture_output=True, text=True, check=True, timeout=30).stdout
        attributes = json.loads(out).get("Attributes", {})
    except (subprocess.SubprocessError, FileNotFoundError, json.JSONDecodeError) as exc:
        return _result("sns_subscription", "not_observed", f"The alarm topic could not be read ({type(exc).__name__}).")
    return evaluate_sns(attributes)


def main() -> None:
    ap = argparse.ArgumentParser(description="Observe the hand-applied settings for the trust center.")
    ap.add_argument("--output", default="manual-settings.json")
    a = ap.parse_args()
    checks = [check_github(), check_dnssec(), check_sns()]
    doc = {"schema": SCHEMA, "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "checks": checks}
    with open(a.output, "w") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    for c in checks:
        print(f"check-manual-settings: {c['id']}: {c['status']} ({c['detail']})", file=sys.stderr)


if __name__ == "__main__":
    main()
