# AU — Audit and Accountability

Three log sources comprise the auditable record: CloudWatch Logs (Lambda execution and invocation history), CloudTrail (account-wide AWS API calls), and GitHub Actions workflow logs (deploy chain, OPA gate decisions, signing events). All three are write-once from the producing service; the deployer principal has no IAM action for deleting CloudTrail logs without a privilege escalation that the OPA gate would block. CloudWatch retention is 7 days (cost trade-off, documented in [`security-review.md`](../security-review.md)); CloudTrail retention follows the AWS-default for management events.

The runtime KSI emitter publishes a daily artifact at `/.well-known/ksi-signal-runtime.json` that constitutes a public, signed audit summary of the system's live state. The build-time VDR report (see RA) is similarly public per deploy.

**20x rule integration.** Aligns with KSI-MLA (Monitoring, Logging, and Auditing). The persistent log review (KSI-MLA-RVL) is automated: `scripts/audit-log-review.py` runs every night ([`architecture-decisions.md`](../architecture-decisions.md#audit-log-review-ksi-mla-rvl)).

**Verification.** Machine-checked on every deploy and every night (`scripts/check-non-machine-vv.py`), and re-checked, with its sha256, in each Annual Security Review (`scripts/hold-security-review.py`); a change is a reviewed pull request. The audit log itself is reviewed every night by `scripts/audit-log-review.py`.
