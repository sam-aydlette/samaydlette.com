"""Who may sign each artifact published under /.well-known/.

A published artifact is signed keylessly by the workflow that writes it, so the
identities a verifier must accept for a file are exactly the workflows that put
it. Several workflows write the same files:

  * the deploy (deploy-with-opa.yml) writes everything it builds;
  * the evidence nightly (evidence-nightly.yml) rewrites the VDR family
    (`vdr-*`) twice a day;
  * the package maintainer (package-maintenance.yml) rewrites the SDR, CPO and
    OCR daily, and alone writes the quarterly issue index, issued reports,
    snapshot indexes and Quarterly Reviews (`ocr-issue*`, `snapshot-*`,
    `quarterly-reviews*`, `quarterly-review-*`);
  * the incident publisher (incident-reports.yml) rewrites the incident log,
    the delivery log and every report (`incident-*`);
  * the simulated assessor (simulated-assessor.yml) signs its own assessment;
    the deploy relays that file and its bundle unchanged.

Every allowed-signer list (the assessor guide, the trust manifest,
scripts/verify-published.sh, docs/verification.md) reads or matches this table.
tests/test_publishers.py derives each file's writers from the workflows' publish
steps and fails when this table, or any of those lists, disagrees.
"""

REPO_URL = "https://github.com/sam-aydlette/samaydlette.com"
WF = f"{REPO_URL}/.github/workflows"
ISSUER = "https://token.actions.githubusercontent.com"

WORKFLOWS = {
    "deploy": "deploy-with-opa.yml",
    "nightly": "evidence-nightly.yml",
    "maintenance": "package-maintenance.yml",
    "incident": "incident-reports.yml",
    "assessor": "simulated-assessor.yml",
}
IDENTITIES = {k: f"{WF}/{wf}@refs/heads/main" for k, wf in WORKFLOWS.items()}

# (file-name prefixes, the identities that write them, the usual one first).
_RULES = (
    (("simulated-assessment",), ("assessor",)),
    (("vdr-",), ("deploy", "nightly")),
    (("security-decision-record", "certification-package-overview", "ongoing-certification-report"),
     ("deploy", "maintenance")),
    (("ocr-issue", "snapshot-", "quarterly-reviews", "quarterly-review-"), ("maintenance",)),
    (("incident-",), ("deploy", "incident")),
)


def signers(name):
    """The identity keys allowed to sign a published file, by its file name."""
    base = name.rsplit("/", 1)[-1]
    for prefixes, who in _RULES:
        if base.startswith(prefixes):
            return list(who)
    return ["deploy"]
