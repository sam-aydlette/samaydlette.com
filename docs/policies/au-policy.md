# AU — Audit and Accountability

Three log sources comprise the auditable record: CloudWatch Logs (Lambda execution and invocation history), CloudTrail (account-wide AWS API calls), and GitHub Actions workflow logs (deploy chain, OPA gate decisions, signing events). All three are write-once from the producing service; the deployer principal has no IAM action for deleting CloudTrail logs without a privilege escalation that the OPA gate would block. CloudWatch retention is 7 days (cost trade-off, documented in [`security-review.md`](../security-review.md)); CloudTrail retention follows the AWS-default for management events.

The runtime KSI emitter publishes a daily artifact at `/.well-known/ksi-signal-runtime.json` that constitutes a public, signed audit summary of the system's live state. The build-time VDR report (see RA) is similarly public per deploy.

**20x rule integration.** Aligns with KSI-MLA (Monitoring, Logging, and Auditing). Persistent log review cadence is in [`security-review.md`](../security-review.md).

**Review cadence.** Quarterly review of CloudTrail; annual structural review.
