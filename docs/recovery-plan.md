# Recovery Plan

This document satisfies KSI-RPL-ARP and KSI-RPL-TRC, given the recovery objectives declared per KSI-RPL-RRO:

- **Recovery Time Objective (RTO):** 21 days. The world will be fine without my opinions for three weeks.
- **Recovery Point Objective (RPO):** 24 hours. Backups are the frequent git commits and S3 object versioning, both of which exceed this granularity by orders of magnitude.

The same two objectives are governed as data in [`data/recovery-objectives.json`](../data/recovery-objectives.json) (schema `infrastructure/schemas/recovery-objectives.schema.json`), which the Chaos Gremlin restore drill and the availability check below measure against. _AI-drafted (2026-11-06); for the operator's review._

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
make pipeline   # infrastructure only — this publishes nothing

# 3. Restore content and the published evidence. `make pipeline` stops at
# `terraform apply`: website content and every artifact under /.well-known/ are
# published only by the CI deploy job, behind the reconciliation gate and the
# prod environment approval. Push to `main` and approve the deploy. There is no
# local publish path, by design — a partial, unsigned artifact set over the
# published one is the failure mode the gate exists to prevent.

# 4. Verify.
curl -I https://samaydlette.com/
curl -s https://samaydlette.com/.well-known/ksi-signal.json | jq '.signal_id, .emitted_at'
```

The full procedure is bounded by AWS resource creation latency (CloudFront takes about 20 minutes to deploy globally) and DNS propagation (up to 48 hours, typically much less). Realistic recovery is hours, not days. The 21-day RTO is generous on purpose — it's the time the operator is willing to wait, not the time the system needs.

## Backup alignment (KSI-RPL-ABO)

- **Source code:** Distributed across every git clone in existence. RPO is "the time since the last fetch on any clone," which in practice is minutes.
- **Site content:** Source-controlled and additionally backed up in the S3 bucket itself, which has versioning enabled. Any object can be rolled back to a prior version within S3's standard retention.
- **Infrastructure config:** Terraform configuration is in the repo. State for managed resources (Lambda, IAM role, EventBridge rule) is in the S3 backend (`infrastructure/backend.tf`: bucket samaydlette-com-tfstate, object key "infrastructure/terraform.tfstate"); for a hard recovery into a new account it can be reconstructed via `terraform import` against the recreated resources.
- **Build artifacts (KSI signals, bundles):** Reproducible from any commit on `main` by re-running the pipeline. No backup required because they are deterministically regenerable.

The 24-hour RPO is comfortably met. Any change committed to `main` reaches the bucket within the time of one CI run (~5 minutes). The data loss window in the worst case is "whatever is in flight in an open editor at the moment of catastrophe," which is upper-bounded by the operator's typing speed, not by any backup cadence.

## Recovery testing (KSI-RPL-TRC)

KSI-RPL-TRC calls for persistent testing of recovery capability. The site's infrastructure was rebuilt from `terraform.tfvars.example` during the construction of this implementation; effective wall-clock time from "git clone" to "curl returns content" was under one hour, well inside RTO. That counts as a real recovery exercise with a much-larger-than-tabletop scope.

Recovery is exercised by machine every month (DEC-195: nobody runs it by hand). `scripts/hold-recovery-exercise.py` runs in `evidence-nightly.yml` on the first of each month (first due 2026-11-01) and publishes `/.well-known/vdr-recovery-exercise-<date>.json`, signed, with the index `/.well-known/vdr-recovery-exercises.json`. Each exercise checks:

- **Restore point:** every file the deploy uploads is rebuilt from the deployed commit in git and compared byte for byte (sha256, the deploy's cache-busting query string aside) with what the site serves. The source of a restore and the live site are proved identical without writing to production.
- **Configuration:** versioning on every bucket and point-in-time recovery on the state-lock table are re-validated by the signed runtime signal of the deployed commit.
- **Tabletop (each November):** every in-scope loss scenario above is walked through with a simulated incident commander, Bea Kupp (simulated), and a simulated scenario injector, Dee Saster (simulated) (DEC-194); a scenario without a stated recovery, or a plan without its Recovery procedure section, fails the tabletop.

A failing exercise fails the nightly and is not published; it is held again on the next run once fixed. `scripts/check-scheduled-review.py` fails the nightly from the day after a due date with no exercise published.

### The Chaos Gremlin restore drill (KSI-RPL-TRC, KSI-RPL-RRO)

_AI-drafted (2026-11-06); for the operator's review._

The recovery exercise proves the source of a restore matches production without writing to it. The Chaos Gremlin drill proves a restore actually works, monthly (first due 2026-12-01), in `evidence-nightly.yml` (`scripts/hold-chaos-gremlin.py`), with no person in the loop:

1. A sample of deployed site objects is copied into a scratch bucket (`infrastructure/bootstrap/recovery-drill.tf`: versioned, public access blocked, encrypted, every version expired after 7 days). Production is only read.
2. The Chaos Gremlin (simulated) deletes some of them and overwrites others with gremlin graffiti.
3. Each damaged object is restored from its last version before the damage, read back and compared (sha256) with the file the deployed commit builds.
4. The restore is timed against the RTO and the restore point's age against the RPO (`data/recovery-objectives.json`); a planted forged restore (the graffiti presented as restored) must be caught.

Each drill is published signed as `/.well-known/vdr-drill-chaos-gremlin-<date>.json`, indexed in `/.well-known/vdr-drill-chaos-gremlins.json`. A failing drill fails the nightly; `scripts/check-scheduled-review.py` fails it from the day after a due date with no drill published.

Separately, every availability incident in the independent 30-day measurement (`/.well-known/availability.json`) is compared with the RTO on every SDR build (method `availability-rto` in `infrastructure/schemas/ksi-methods.json`): an outage, ongoing ones measured to now, longer than 21 days fails it.

## History: recovery tests recorded by hand

The entry below was written by hand before the exercise was automated, and is kept as a record.

### 2026-05-06: Initial implementation as recovery test

- **Scenario:** Build the entire infrastructure from scratch; treat it as if no AWS resources existed.
- **Steps executed:** Configure terraform.tfvars, run `make init`, fix the OPA gate failures (h1 accessibility cascade), wire up the runtime Lambda, sign and publish.
- **Wall-clock time:** Single working day, including substantial new feature development that wouldn't be in a real recovery.
- **Issues found:** Pre-existing OPA accessibility regex bug surfaced when the subshell-scope bug in `terraform-plan.sh` was fixed.
- **Follow-up items:** None — both fixed inline.
