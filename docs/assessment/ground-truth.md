# Ground Truth — live state vs. published artifacts (Task 0)

**Date:** 2026-06-13
**Operator identity:** `arn:aws:iam::975050324277:user/saydlette-dev` (local AWS CLI)
**Account:** 975050324277 — matches the work order's expected account ✓
**Method:** live AWS API reads (`aws` CLI), public artifact fetches (`curl`), and Terraform/docs inspection. No production changes were made.

This file is the Task 0 deliverable: what exists, what each artifact claims, and every discrepancy, each tied to a finding ID.

---

## 1. Environment block — confirmed

| Item | Work-order assumption | Confirmed state |
|---|---|---|
| Regions | us-east-2 site/app/S3/CW/APIGW/Secrets; us-east-1 ACM/CloudFront/KMS | **Confirmed.** Lambdas, S3, log groups in us-east-2. ACM/CloudFront/Route53 KMS in us-east-1 (per Terraform; CloudFront/Route53 readable). |
| AWS account | 975050324277 | **Confirmed** via `sts get-caller-identity`. |
| Terraform backend / state | "[confirm]" | **Local state — no remote backend.** `infrastructure/main.tf` `terraform{}` block declares only `required_version`/`required_providers`; no `backend` block. State is local to the runner; CI relies on per-resource import steps in the workflow. |
| Deploy trigger | push to `main` → `deploy-with-opa.yml` | **Confirmed.** `on: push: branches:[main]`, plus `pull_request`, a daily `schedule` (07:17 UTC), and `workflow_dispatch`. |
| Staging / non-prod workspace | "[confirm]" | **None found.** Single prod workspace; all applies land in prod. |
| CI → AWS auth | — | **Long-lived access keys** (`secrets.AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`) in two jobs. Confirms **C-1 / POAM-001**. |
| GitHub OIDC provider | "may already exist" | **Does not exist.** `iam list-open-id-connect-providers` → empty. Task 2 creates it. |
| Local tools | terraform, aws, OPA/Conftest, jq, python, Steampipe | aws 2.27, terraform 1.6.3, jq 1.8, python 3.13, opa present, steampipe 1.1.3, gh 2.93 — all OK. **`conftest` MISSING** (use `opa eval` for the gate). |

## 2. Operator credential scope — material constraint (shapes run mode)

The local `saydlette-dev` user is **scoped, not admin**. Probed surface:

| Can read **and** apply | Cannot access at all (AccessDenied) |
|---|---|
| IAM, Lambda, Route 53, CloudFront, ACM, EventBridge, S3, CloudWatch Logs + Metrics | API Gateway (`apigateway:GET`), Secrets Manager (`ListSecrets`), Cognito (`ListUserPools`), KMS (`ListKeys`), SQS, Signer, Bedrock (`ListFoundationModels`), Resource Explorer |

**Consequence + resolution:** several in-scope services — API Gateway, Secrets Manager, Cognito, KMS, Bedrock, SQS, Signer — were initially denied. Per operator decision (2026-06-13), local read access was broadened: an inline **read-only** policy `assessment-readonly-2026-06` was attached to `saydlette-dev` granting metadata/read actions on those services (deliberately **excluding `secretsmanager:GetSecretValue`** — metadata only, never secret values). All Task 0 census reads now succeed.

**Applies remain CI-only (PR-only mode).** State is local and CI performs per-resource imports, so applying from a local workstation would risk diverging from CI's state. The broadened creds are used for **read-based Done-checks only**; all `terraform apply`s go through CI on merge. Genuinely write-only verifications (e.g., confirming an authorizer is attached post-deploy) still defer to apply-time and are labelled per task.

## 3. Live resource census (confirmed via API)

- **S3:** one bucket `samaydlette.com`. Encryption = **`AES256` (SSE-S3), `BucketKeyEnabled: false`** → confirms **D-1 / POAM-011/018** (narrative claims KMS; config is SSE-S3). Server access logging: not enabled → **C-3 / POAM-005**.
- **Lambda (us-east-2):**
  - `samaydlette-com-opa-compliance` — nodejs22.x, role `…-lambda-opa-role`. No DLQ, no reserved concurrency.
  - `samaydlette-com-silk-reeling` — python3.13, role `…-silk-reeling-role`. **No DLQ** (POAM-013), **no reserved concurrency** (POAM-012), **no code-signing config** (POAM-015). Env vars reference **two Secrets Manager secrets**: `…-anthropic-api-key` (**F-3/POAM-020**) and `…-basic-auth` (**F-4**). Confirms the Anthropic interconnection and Basic Auth are live.
  - The two functions are **distinct ARNs/roles** — so **B-3's "duplicate ARN"** is an inventory-representation issue, and it already reads correctly in the live signal (see §4).
- **CloudWatch Logs (us-east-2):** `/aws/lambda/…-silk-reeling` retention = **7 days** (**C-2 / POAM-017**, vs Moderate AU-11 = 365). `/aws/lambda/…-opa-compliance` retention = never-expire. **Neither log group is KMS-encrypted** (Task 6).
- **API Gateway (us-east-2):** one HTTP API (v2) `samaydlette-com-silk-reeling`, id `25ogqmrhuc`, endpoint `https://25ogqmrhuc.execute-api.us-east-2.amazonaws.com`. No REST (v1) APIs. This is the in-boundary interface fronting the app Lambda — **absent from the canonical inventory** (F-1/B-1). Authorizer / throttling / access-logging state to be set in Task 3.
- **Secrets Manager (us-east-2):** two secrets — `samaydlette-com-silk-reeling-basic-auth` and `samaydlette-com-silk-reeling-anthropic-api-key`. **Rotation disabled** on both (relates to POAM-019). Both **absent from the canonical inventory** (F-1/B-1); both slated for removal in Tasks 3–4.
- **Bedrock (us-east-2):** `list-foundation-models` returns Claude models in-region (sonnet-4 / opus-4.x / haiku-4.5 family), so the migration target is reachable at the API level. **FedRAMP authorization status** for Bedrock in this region/partition is a compliance fact to confirm from a current source in Task 4 (hard checkpoint #3).
- **Route 53 / CloudFront:** readable; DNSSEC status and CloudFront logging to be confirmed at apply-time (**D-3**, **C-3/POAM-005**).

## 4. Published artifacts vs. live (fetched from the site)

Live `/.well-known/ksi-signal.json` (emitted 2026-06-13T15:00:27Z, commit `3b3d8b22` = current `main` HEAD):
- **195 components.** Types present: cdn_distribution, dns_zone, event_schedule, external_service, function, html_artifact, iam_policy, iam_role, log_group, npm_package, object_store, pypi_package, tls_certificate.
- **No `api_gateway` type. No `secrets_manager` type.** → confirms **F-1 / B-1**: the API Gateway fronting the app and the two Secrets Manager secrets the app Lambda demonstrably uses are **absent from the canonical inventory**, even though the live Lambda env proves they exist in-boundary.
- **Impact level: absent.** No `impact_level` / `fips_199` / `categorization` field anywhere in the signal → **F-2 / Decision 1**: the single-source impact value (Moderate / Class C) is not asserted in the signal at all. (`docs/poam.md` does say "Moderate"; the signal does not.)
- Both Lambdas present as distinct components with correct ARNs → **B-3 already remediated** in the live signal.
- `external_service` entries: sigstore-fulcio, sigstore-rekor, github-oidc, github-repo, duo-mfa, github-advisory-db, cisa-kev. (The Anthropic API interconnection is represented via the secret, not an explicit `external_service` here — to reconcile in Task 4.)

Live `/.well-known/vdr-report.json` (emitted 2026-06-13T15:00:46Z):
- 18 risk-accepted entries; `poam_ref`s cover POAM-003…018 **but include 3 `null` refs** → confirms **B-2 / F-6**.
- **`findings: [] ` (0), no source entries** → confirms **P-1**: ZAP/DAST is not ingested; a skipped scan reads as "0 findings."

Freshness (**P-1**): at time of check the served signal's commit **equals** `main` HEAD and `emitted_at` is current — so the latest deploy published fresh artifacts. But there is **no freshness gate** (invariant f) protecting against the stale-publish failure mode; the protection, not the current snapshot, is what's missing.

`README.md`: claims **"323 controls"** (line 13). The work order cited 192-vs-331; the number has since moved (cycle-2, PR #93, now merged). True count to be reconciled from pipeline output in Task 1.

`docs/poam.md`: **Impact Level: Moderate (FedRAMP Rev 5; equiv. 20x Class C)** — already Moderate. POAM-001 remediation text still restricts OIDC `sub` to `repo:…:*`; Task 2 tightens to `ref:refs/heads/main`/Environment. Some entries still carry "Original Risk Rating: Low" (e.g. POAM-002) — Decision 1 requires removing "system is Low" rationales and giving Moderate-level acceptance rationales.

## 5. Hard-checkpoint status from Task 0

- **No contradiction with the settled decisions.** Impact level is already Moderate in the POA&M; no "system is Low" *categorization* found (only per-item legacy risk ratings to clean up).
- **App is deployed as described** (both Lambdas live; app behind API Gateway with Basic Auth + Anthropic interconnection).
- **No unrecognized in-scope resources** — the omitted API GW / Secrets Manager are the expected F-1/B-1 findings, not surprises.
- **Bedrock: reachable in-region** (after the read-grant). Claude models list in us-east-2. The remaining Task 4 check is the **FedRAMP-authorization compliance fact** (not an API call) — confirm from a current source before relying on it; if not authorized in this region/partition, that is hard checkpoint #3.

## 6. Run-mode determination

**PR-only** (mode b). Local creds can apply a subset but cannot touch API GW / Secrets Manager / Cognito / KMS / Bedrock / SQS / Signer, and state is local with CI doing imports — so applying locally would risk diverging from CI's apply path. All applies go through CI on merge; local creds are used for read-based Done-checks where permitted, with denied-service checks deferred to apply-time and labelled per PR.
