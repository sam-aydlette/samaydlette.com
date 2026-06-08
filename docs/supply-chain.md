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
- **Syft + Grype SCA** (in the deploy workflow, when the Silk Reeling app is built) — Syft generates a CycloneDX SBOM of the assembled Lambda artifact (`_pkg`, including the `pip`-installed Python dependencies) and of the frontend dependency tree (`_silk_src/frontend`, which carries a `package-lock.json`); Grype scans the SBOMs for known vulnerabilities. The merged Grype output (`grype.json`) is fed to the VDR aggregator (`scripts/build-vdr-report.py --grype`), so Python (PyPI) and client-side JS CVEs are evaluated on the same PAIN/IRV/LEV/KEV scale as every other source and are subject to the same Class C SLAs. This closes the detection gap the Silk Reeling app would otherwise open: its dependency ecosystems (PyPI, the SPA's npm tree) are not covered by the Dependabot configuration in this repo, because the app's manifests live in the separate `silk-reeling-mirror` source repo and are pulled in only at build time (`VDR-CSO-DET`).
- **Secret scanning** — GitHub-default, with push protection enabled.

Together these provide Software Composition Analysis — Dependabot (against the GitHub Advisory Database) for the in-repo npm / GitHub Actions / Terraform components, and Syft+Grype (against the Grype vulnerability database) for the Silk Reeling app's PyPI and client-JS components — plus IaC scanning (Checkov + tfsec, against their respective rule sets), gated on every pull request and every deploy before merge to `main`.

### Silk Reeling Mirror app dependencies

The gated Silk Reeling app introduces two dependency sets whose manifests live in the
`silk-reeling-mirror` source repo, not here:

- **Python (PyPI)** — `silk-reeling-mirror/backend/requirements-lambda.txt`, installed into the Lambda package at build time (numpy, the Anthropic SDK, and transitive wheels built for the `cp313`/`manylinux` runtime ABI).
- **Client-side JS (npm)** — `silk-reeling-mirror/frontend`, resolved via `npm ci` and built to a static bundle that ships to the browser (the SPA does the pose extraction client-side).

Both are scanned at build/deploy time by the Syft+Grype step above, which is the
authoritative detection source for these components in *this* system's VDR. As a
complementary, continuous control, **Dependabot `pip` and `npm` ecosystems should be
enabled in the `silk-reeling-mirror` repo itself** — that is where the manifests live,
so that is where autonomous daily Dependabot alerting belongs. (Enabling `pip`/`npm`
Dependabot in *this* repo would point at paths that do not exist here and is therefore
not done.)

The PURL-based inventory in the canonical KSI signal also enables external monitoring without depending on GitHub's tools. Any consumer fetching the canonical inventory can correlate `npm_package` components against the OSV database, the GitHub Advisory Database, or any other PURL-aware vulnerability source — including a future portfolio-level monitor that watches signals from many systems and alerts when any of them ingests a known-bad component.

Two structural notes about the third-party-risk story for this system:

- **Transparency replaces a private TPRM function.** The canonical inventory is public, the signature chain is publicly verifiable, and the documentation set is in the repo. There is no closed audit relationship to maintain because every artifact that would feed one is already published.
- **The canonical inventory is the SBOM-equivalent.** The compliance Lambda's npm packages appear directly in `components[]` with their PURL and lockfile integrity hash, and every static artifact appears with its SHA-256. The Silk Reeling app's Python (PyPI) and SPA (npm) dependencies are inventoried by ingesting the Syft CycloneDX SBOMs (`sbom-python.json`, `sbom-js.json`) produced by the SCA step into the same `components[]` at build time — so they too appear, by PURL, sourced from the SBOM rather than a lockfile. A separate stand-alone SBOM document re-expressing the same information would be redundant.
