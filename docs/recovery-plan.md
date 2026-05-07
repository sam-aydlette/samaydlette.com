# Recovery Plan

This document satisfies KSI-RPL-02 and KSI-RPL-04, given the recovery objectives declared per KSI-RPL-01:

- **Recovery Time Objective (RTO):** 21 days. The world will be fine without my opinions for three weeks.
- **Recovery Point Objective (RPO):** 24 hours. Backups are the daily git commits and S3 object versioning, both of which exceed this granularity by orders of magnitude.

## Scope

In-scope loss scenarios:

- Total loss of the AWS account — recover into a new account
- Loss of the S3 bucket only — recover from git
- Loss of the GitHub repository — recover from any local clone
- Loss of the deployer credentials — issue new ones
- Loss of the domain — re-register; CDN reconfigures from Terraform
- Loss of the CI workflow's ability to sign — fall back to unsigned deploys until restored

Out of scope:

- Loss of the human (the author). The site is static and self-hosting; it will continue serving through CloudFront's cached responses and S3 storage for an extended period after any human change. There is no formal succession plan because there is no formal succession requirement. People will manage.

## Recovery procedure

End-state target: site reachable at https://samaydlette.com over TLS, content matching the most recent commit on `main`, runtime KSI signal publishing on schedule.

```bash
# 1. Restore the source from any clone (the local working copy, GitHub, or any
# other replica). Git's distributed model means the source is essentially
# unloseable as long as one clone survives.
git clone https://github.com/sam-aydlette/samaydlette.com.git
cd samaydlette.com

# 2. Reprovision AWS resources. If recovering into the existing account, the
# Terraform state is intact and a plain `make pipeline` is sufficient. If
# recovering into a new account, the existing-resource references must be
# recreated first (S3 bucket named after the domain, CloudFront distribution,
# ACM certificate in us-east-1) before terraform.tfvars is populated and the
# pipeline runs.
cd infrastructure
cp terraform.tfvars.example terraform.tfvars
# Edit existing_cloudfront_distribution_id, existing_ssl_certificate_arn,
# existing_s3_bucket_name with the new resource IDs.
make pipeline

# 3. Verify.
curl -I https://samaydlette.com/
curl -s https://samaydlette.com/.well-known/ksi-signal.json | jq '.signal_id, .emitted_at'
```

The full procedure is bounded by AWS resource creation latency (CloudFront takes about 20 minutes to deploy globally) and DNS propagation (up to 48 hours, typically much less). Realistic recovery is hours, not days. The 21-day RTO is generous on purpose — it's the time the operator is willing to wait, not the time the system needs.

## Backup alignment (KSI-RPL-03)

- **Source code:** Distributed across every git clone in existence. RPO is "the time since the last fetch on any clone," which in practice is minutes.
- **Site content:** Source-controlled and additionally backed up in the S3 bucket itself, which has versioning enabled. Any object can be rolled back to a prior version within S3's standard retention.
- **Infrastructure config:** Terraform configuration is in the repo. State for managed resources (Lambda, IAM role, EventBridge rule) is in `infrastructure/terraform.tfstate`; for a hard recovery into a new account it can be reconstructed via `terraform import` against the recreated resources.
- **Build artifacts (KSI signals, bundles):** Reproducible from any commit on `main` by re-running the pipeline. No backup required because they are deterministically regenerable.

The 24-hour RPO is comfortably met. Any change committed to `main` reaches the bucket within the time of one CI run (~5 minutes). The data loss window in the worst case is "whatever is in flight in an open editor at the moment of catastrophe," which is upper-bounded by the operator's typing speed, not by any backup cadence.

## Recovery testing (KSI-RPL-04)

KSI-RPL-04 calls for persistent testing of recovery capability. The site's infrastructure was rebuilt from `terraform.tfvars.example` during the construction of this implementation; effective wall-clock time from "git clone" to "curl returns content" was under one hour, well inside RTO. That counts as a real recovery exercise with a much-larger-than-tabletop scope.

A formal tabletop is run annually, recorded below using this template:

```
## YYYY-MM-DD: Recovery tabletop

- **Scenario:** <e.g., "S3 bucket deleted">
- **Steps executed:** <what was actually done, in order>
- **Wall-clock time to recover:** <duration>
- **Issues found:** <gaps or surprises>
- **Follow-up items:** <issues filed>
```

### 2026-05-06: Initial implementation as recovery test

- **Scenario:** Build the entire infrastructure from scratch; treat it as if no AWS resources existed.
- **Steps executed:** Configure terraform.tfvars, run `make init`, fix the OPA gate failures (h1 accessibility cascade), wire up the runtime Lambda, sign and publish.
- **Wall-clock time:** Single working day, including substantial new feature development that wouldn't be in a real recovery.
- **Issues found:** Pre-existing OPA accessibility regex bug surfaced when the subshell-scope bug in `terraform-plan.sh` was fixed.
- **Follow-up items:** None — both fixed inline.

## Honest qualifier

This recovery plan is written for a one-person operation with no SLAs to anyone. The 21-day RTO is internally honest; an externally-facing service would use a number two orders of magnitude smaller and require backup infrastructure ready to take over. The mechanics of this plan generalize; the timelines do not. If something here ever does need to be recovered in minutes rather than weeks, the gap will be infrastructure that's ready to fail-over to (multi-region active-passive, or at least pre-staged Terraform in a second account), not a different procedure.
