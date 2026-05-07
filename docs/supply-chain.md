# Supply Chain Risk Management

This document satisfies KSI-TPR-03 and KSI-TPR-04.

## In-scope third-party components

The system depends on a small, named set of third-party components:

- **npm packages** in the runtime KSI Lambda — listed in `infrastructure/lambda/package-lock.json`. Currently the AWS SDK v3 clients for S3 and CloudFront, transitively about 108 packages.
- **GitHub Actions** in the deploy workflow — pinned to specific SHAs for the load-bearing actions (`actions/checkout`, `setup-terraform`, `setup-node`, `configure-aws-credentials`, `upload-artifact`, `download-artifact`, `tfsec-action`, `checkov-action`, `codeql-action`, `github-script`). The cosign installer is currently tag-pinned with a TODO to SHA-pin.
- **Terraform providers** — `hashicorp/aws` and `hashicorp/archive`, version-constrained in `infrastructure/main.tf`.
- **OPA binary** — pinned to a specific version with a SHA-256 check in the workflow.
- **Cosign binary** — installed via the Sigstore action; the binary version is pinned by the action's release.

Every component above is listed in the canonical inventory at `/.well-known/ksi-signal.json`, named by Package URL where applicable.

## Risk identification (KSI-TPR-03)

The canonical inventory makes any third-party component immediately addressable for review. A query of `pkg:npm/<name>@<version>` against any vulnerability database returns relevant CVEs without manual reconciliation. The same is true for the (currently empty) container image and HBOM slots if those become populated in the future.

GitHub Actions are reviewed when first added. SHA-pinning prevents transparent upstream replacement. When an action's pin is updated, the diff in the workflow file is the review record.

The risk surface is intentionally small. A static site does not execute uploaded code, store user data, or process untrusted input beyond what static HTTP serving requires; the supply-chain blast radius is correspondingly small.

## Risk monitoring (KSI-TPR-04)

Multiple gates run automatically:

- **Dependabot vulnerability alerts** (configured via [`.github/dependabot.yml`](../.github/dependabot.yml)) — on by default for npm and GitHub Actions; alerts are emailed to the repo owner and surfaced in the GitHub Security tab.
- **Dependabot version updates** — weekly PRs for npm dependencies in `infrastructure/lambda/`, weekly for pinned GitHub Actions, monthly for Terraform providers.
- **Checkov** (in the `security-scan` CI job, on every pull request) — policy-as-code scanner over the Terraform configuration with a SARIF report uploaded to GitHub's Security tab.
- **tfsec** (in the `security-scan` CI job, on every pull request) — Terraform-specific static analysis covering AWS misconfigurations.
- **Secret scanning** — GitHub-default, with push protection enabled.

Together these provide Software Composition Analysis (Dependabot, against the GitHub Advisory Database) and IaC scanning (Checkov + tfsec, against their respective rule sets), gated on every pull request before merge to `main`.

The PURL-based inventory in the canonical KSI signal also enables external monitoring without depending on GitHub's tools. Any consumer fetching the canonical inventory can correlate `npm_package` components against the OSV database, the GitHub Advisory Database, or any other PURL-aware vulnerability source — including a future portfolio-level monitor that watches signals from many systems and alerts when any of them ingests a known-bad component.

## Honest qualifier

This is a one-person, low-blast-radius static site. The supply-chain attack surface is correspondingly small, and the controls described here are calibrated to that surface, not to a service handling federal customer data. That said, the gate this repo runs is more substantial than "small" might suggest: SCA via Dependabot, IaC scanning via Checkov + tfsec, and a Sigstore-signed canonical inventory all run on the deploy path.

Two structural notes about the third-party-risk story for this kind of system:

- **Transparency replaces a private TPRM function.** The canonical inventory is public, the signature chain is publicly verifiable, and the documentation set is in the repo. The third party doing the review is the public itself. There is no closed audit relationship to maintain because every artifact that would feed one is already published.
- **The canonical inventory is the SBOM-equivalent.** Every npm package appears in `components[]` with its PURL and lockfile integrity hash; every static artifact appears with its SHA-256. A separate SBOM document (CycloneDX, SPDX) re-expressing the same information would be redundant for this system, and is not currently a requirement.

A SaaS or IaaS at scale would add depth proportional to its blast radius: contractual notification requirements with key suppliers (which require leverage a small operator does not have), formal third-party assessments, and review cadence keyed to risk level. The shape of the controls — PURL-based identification, automated monitoring, signed provenance, public verifiability — generalizes; the depth and the negotiating posture do not.
