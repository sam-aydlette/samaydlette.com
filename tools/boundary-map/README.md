# Independent corroboration (local only)

`corroborate.py` checks the published evidence against sources the pipeline does
not control: RAMPART on TAP (The Analogy Platform) and, where TAP has no working
collector, the upstream source read directly. It needs a running local TAP
session with the aws_core and github_core collectors configured (read-only), so
it never runs in CI.

    python3 tools/boundary-map/corroborate.py --collect

writes `docs/boundary/corroboration.json` (schema `rampart-corroboration/2`).
Commit it in a PR; the next deploy signs it and publishes it at
`/.well-known/boundary-corroboration.json`, and the trust center shows one line
per section and asks for a new run after 30 days.

Each section is `agrees`, `differs` or `not_checked`. A section that compared
nothing, or could not read its source, is `not_checked`, never `agrees`. The
overall `result` is `agrees` only when every section agrees, `differs` when any
section differs, and `incomplete` otherwise.

| Section | Source | What it compares |
| --- | --- | --- |
| `boundary` | TAP aws_core | The published map against the live account: resources, classification tags, relationships. Detail in the top-level keys, unchanged from schema 1. |
| `signatures` | TAP sigstore_core | Every signed artifact in the governed freshness config (bundles and in-toto attestations) re-verified with sigstore-python against the production trust root, pinned to the identities of the workflows that write each file (`scripts/_signers.py`, not its cadence); an attestation's subject must be the published bytes. The report itself and the KMS-signed runtime signal are excluded. |
| `provenance` | TAP github_core | Each run named in a signing certificate against GitHub's record of it: workflow, commit, branch, trigger, conclusion. Runs older than TAP's run window are listed as not checked. |
| `live_configuration` | TAP aws_core | Each property a published artifact claims about a live resource (a component's `baseline_configuration`, or a `terraform.compliance` pass under `s3.rego` and `tagging.rego`) against what AWS reports. Fields the collector leaves empty are not checked. What TAP cannot read is listed in `not_covered`. |
| `runtime_signing_key` | AWS KMS via TAP's credential | The runtime signing key's public half from KMS against the published PEM and the pinned record; the runtime signal verified with the builder's own code against the KMS key. |
| `vulnerabilities` | TAP github_core | Open Dependabot alerts against the VDR's findings and dispositions. Not checked until TAP's GitHub credential can read Dependabot alerts. |
| `ksi_catalog` | FedRAMP/rules at upstream HEAD, direct | Every KSI the signal claims exists in FedRAMP's current rules. TAP's KSI catalog collector fails the current upstream schema, so this one is read directly. |

Not covered by any source today: the availability numbers, the OPA and Terraform
verdicts themselves, the Checkov and tfsec findings, framework coverage counts,
human-process KSIs and lockfile completeness.

The report fails closed on any ARN, account ID or email address. GitHub run IDs
and IAM user names are used to match, never written.
