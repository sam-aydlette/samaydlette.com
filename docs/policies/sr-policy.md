# SR — Supply Chain Risk Management

Supply chain risk management is documented in [`supply-chain.md`](../supply-chain.md). The system has three external supply-chain inputs:

1. **AWS services:** under inheritance from AWS East/West Moderate FedRAMP authorization (Package ID: AGENCYAMAZONEW). Treated as authorized infrastructure; no per-component vetting beyond the AWS authorization package.
2. **GitHub Actions runners and the GitHub-hosted dependencies of the workflow:** Dependabot monitors actions; the workflow's `GITHUB_TOKEN` permissions are scoped per job; pinned to commit SHAs where used.
3. **npm dependencies of the Lambda runtime:** Dependabot monitors weekly; PURL-named in the canonical inventory; pinned via `package-lock.json`. Vulnerability findings flow into the VDR aggregator (see RA).

Significant changes to any supply-chain input trigger SCN evaluation per the criteria in CM. A new AWS service activation is at minimum an Adaptive change. A library upgrade with breaking changes is Adaptive; a like-for-like patch is Routine Recurring per `SCN-RTR-NNR`. Replacement of a critical third-party service is Transformative.

**20x rule integration.** Significant Change Notifications applied to supply-chain changes (`SCN-* family`). KSI-TPR (Third-Party Risk). KSI-SCM (Supply Chain Management).

**Review cadence.** Continuous via Dependabot; annual structural review.
