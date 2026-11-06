# Annual Security Review

This document satisfies KSI-PIY-RIS (persistent review of the effectiveness of investments in achieving security objectives), and with it KSI-PIY-RES, KSI-SVC-EIS and KSI-INR-RPI.

## How the review is held

Nobody holds it by hand (DEC-195 lists the only recurring human acts that remain). `scripts/hold-security-review.py` runs in `package-maintenance.yml`, which every deploy calls, at the deployed commit. On the due date (first due 2026-11-06, then each year on the same day) the script builds the review from the system's own data and publishes it, signed, as `/.well-known/security-review-<date>.json` with its readable view; the index `/.well-known/security-reviews.json` records each one's sha256. The checks:

- **Documents:** every policy, procedure, plan and record in `data/non-machine-resources.json` passes its machine checks, with its sha256 and whether it changed since the last review.
- **Component types:** every component type added to the inventory since the last review is named in the threat model (`docs/architecture-decisions.md`).
- **Operations:** decisions made in the last 12 months, any in-force decision past its review date, the findings in the VDR, and the incident record; an incident pattern that recurs fails the review (KSI-INR-RPI).
- **Investment:** the recurring cost of every billable thing, from `data/recurring-costs.json` (each line with the repository file that creates it; the figures are AI-drafted estimates for the operator to correct), and the pipeline's run time from GitHub's run history.

A simulated reviewer, Rev Yewer (simulated), signs each check off (DEC-194). A failing check fails the run and nothing is published for that date; the fix is a code or document change, and the review is held again on the next run. `scripts/check-scheduled-review.py` fails the run from the day after a due date with no review published. The same index records the acknowledgement of the [rules of behavior](rules-of-behavior.md) (PL-4).

## History: the 2026 entry (written by hand before the review was automated)

### Recurring costs (USD/year)

- Lambda compliance executions: ~$0 (within AWS free tier; daily + on-demand)
- EventBridge rules: ~$0 (one daily rule; within free tier)
- CloudWatch logs: ~$0–1 (small logs; within free tier)
- KMS customer-managed key (encryption at rest): ~$12
- Secrets Manager (2 secrets): ~$10
- TLS certificate (ACM): $0 (free)
- DNS (Route 53 hosted zone + queries): ~$6
- S3 storage + requests: ~$1
- CloudFront (Price Class 100): ~$0–30 depending on traffic
- **Total recurring (AWS list pricing):** ~$30 plus variable CloudFront egress
- **With domain registration:** add ~$13/year

### Time invested (hours)

- Initial build of canonical inventory + KSI signal infrastructure: ~40 hours
- OSCAL Rev 5 generator: ~16 hours
- Documentation set (this doc and siblings): ~6 hours
- Incident response: 0 hours (no incidents)

### Controls in place vs. considered

See README "Conscious Trade-offs for Budget Reality." Excluded controls (WAF, multi-AZ, S3 access logging) remain consciously excluded for the same reasons. New for 2026: deploy-time KSI signal signing via Sigstore keyless; runtime KSI emitter; OSCAL Rev 5 SSP generator (since retired, replaced by the Security Decision Record).

### Effectiveness signals

- Incidents: 0
- Drift events caught by runtime emitter: 0 (not yet running on schedule at time of first review; deploys to date have been hand-triggered)
- OPA gate failures caught pre-deploy: substantial (the accessibility cascade was caught and fixed during initial build, after fixing the subshell-scope bug in `terraform-plan.sh`)
- Sigstore-verified deploys: equal to deploy count
- Dependabot: enabled this year; baseline established

### Decisions for next year

- Continue current control set
- Verify runtime emitter has produced at least one drift signal event in a controlled test (deliberately misconfigure a non-production resource and confirm the daily Lambda flags it)
- Close [POAM-001](../data/decisions.json) by completing the GitHub OIDC migration (done: the key was deleted and the item is now DEC-001, remediated; POAM-001 was replaced by that record)
- Consider whether OSCAL artifact should be signed independently or covered by the same Sigstore bundle as the KSI signal
- Cost target: maintain recurring overhead on the order of $30/year (KMS key, Secrets Manager, Route 53; serverless compute within the free tier)

## History: quarterly continuous-monitoring reviews

Kept as history; no longer kept up. The Quarterly Review (`CCM-QTR-MTG`) is now held automatically by `package-maintenance.yml` with simulated attendees (DEC-194) and published as `/.well-known/quarterly-review-<date>.json`.

### 2026-Q2 (initial review, 2026-05-08)

- Runtime KSI emitter: deployed, running daily on EventBridge schedule, no drift events recorded.
- Deploy-time vs. runtime signal reconciliation: components match; validations pass on both sides.
- VDR posture: 1 finding (N1, deduplicate-of-CKV_AWS_50, suppressed in next push), 0 blocking, 15 risk-accepted.
- POA&M activity (the POA&M has since been replaced by the decision register): POAM-001 through POAM-018 in place; first AWS access-key rotation due ~2026-08-08.
- independent-assessment-style external assessment (self-performed) completed 2026-05-08; findings recorded in SAR-001 through SAR-009.
- Decisions: proceed with SAR-002 / SAR-003 inventory expansions; close SAR-007 (ledger), SAR-008 (deduplicate tfsec finding), SAR-009 (emergency-change procedure).
- Next review due: 2026-08-08 (or sooner upon Transformative change per SCN).

## History: AWS access key rotation log (retired)

No longer kept: CI moved to GitHub OIDC roles and the deployer access key was deleted (DEC-001, remediated), so there is no key to rotate. No rotation was ever logged.
