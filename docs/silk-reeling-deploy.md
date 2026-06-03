# Silk Reeling Mirror — deployment branch (DRAFT)

Branch `deploy/silk-reeling-mirror`. **Not applied, not pushed.** This documents
what the branch adds, how to exercise the compliance pipeline against it, the
findings to expect, and the POA&M responses to apply *after* you've seen the scan.

## What this branch adds (infrastructure only)

- `infrastructure/silk-reeling.tf` — the gated app:
  - App **Lambda** (Python zip — browser does the ML, so no OpenCV/MediaPipe).
  - **Function URL** with `authorization_type = AWS_IAM` (no public invoke).
  - **Least-priv IAM** role/policy (logs + `GetSecretValue` on two ARNs + `kms:Decrypt` on one key).
  - Explicit **CloudWatch log group** (retention + tags).
  - Customer-managed **KMS key** (rotation enabled) + two **Secrets Manager** secrets (basic-auth, Anthropic key).
  - `aws_lambda_permission` letting only the site's CloudFront distribution invoke the Function URL.
- `variables.tf` — `create_silk_reeling` (default **false**), `silk_reeling_package_path`, `silk_reeling_max_concurrency`.
- `outputs.tf` — Function URL, secret ARNs (for out-of-band value injection), manual CloudFront wiring pointer.

All gated by `create_silk_reeling = false` → inert until explicitly enabled.

## Security model

- **Two-layer access control:** CloudFront OAC (SigV4) → AWS_IAM Function URL (direct public calls denied) **and** in-app HTTP Basic Auth (constant-time compare).
- **Secrets in Secrets Manager** (CMK-encrypted), read via least-priv IAM. **Values injected out-of-band** (`put-secret-value` in CI from a GitHub secret) — plaintext never enters Terraform state. This config creates only the secret containers (+ a `SET_OUT_OF_BAND` placeholder with `ignore_changes`).
- **Reserved concurrency** caps blast radius/cost.

## Exercise the compliance pipeline (the test)

```bash
# placeholder package so plan can hash it (or build the real one)
printf 'def handler(e,c): return {}\n' > lambda_handler.py && zip silk-reeling.zip lambda_handler.py
cd infrastructure && terraform init -backend=false
make plan   # or: terraform plan -var create_silk_reeling=true -var silk_reeling_package_path=./silk-reeling.zip
```

Watch the OPA gate (`scripts/terraform-plan.sh`), Checkov, and tfsec evaluate the
new resources, and review the generated VDR.

## Expected findings

| Check | Result | Why |
| ----- | ------ | --- |
| CKV_AWS_115 (Lambda concurrency) | **pass** | reserved concurrency is set (doesn't lean on POAM-012) |
| CKV_AWS_116/117/173/50/272 (Lambda DLQ/VPC/env-CMK/X-Ray/signing) | suppressed | global skip-check IDs already in `.checkov.yaml` (POAM-010..015) |
| CKV_AWS_258 (Function URL auth ≠ None) | **pass** | Function URL is `AWS_IAM` |
| CKV_AWS_149 (Secrets Manager CMK) | **pass** | CMK set |
| CKV_AWS_7 (KMS rotation) | **pass** | `enable_key_rotation = true` |
| **CKV2_AWS_57 (Secrets Manager rotation)** | **NEW finding** | no auto-rotation → see POAM-019 |

> ⚠️ **Gap worth your attention:** the global `CKV_AWS_117` suppression (POAM-010)
> was written for the daily compliance Lambda with the rationale *"no internet
> egress."* The app Lambda **does** egress (to the Anthropic API), so that
> rationale doesn't fit it — the global suppression silently covers a resource it
> wasn't reasoned about. Flagged as **POAM-020** for an explicit decision rather
> than relying on the inherited skip. This is exactly the kind of thing the test
> should surface.

## Proposed POA&M responses (apply after reviewing the scan)

Add to `.checkov.yaml` `skip-check:` (verify the exact CKV id against your run):

```yaml
  # POAM-019 — Secrets Manager automatic rotation not enabled (SC-12, SC-28).
  # Third-party API key + operator-set basic-auth credential; no programmatic
  # rotation source. Manual rotation documented. Risk-adjusted to Low.
  - CKV2_AWS_57
```

Add to the `docs/poam.md` configuration-findings table:

```
| POAM-019 | SC-12, SC-28 | Secrets Manager automatic rotation not enabled | Checkov | CKV2_AWS_57 | aws-secretsmanager::silk-reeling | N2 | Moderate | Low | Yes | Risk-accepted |
| POAM-020 | SC-7 | App Lambda internet egress without VPC/NAT controls | Architectural decision | — | aws-lambda::silk-reeling | N2 | Moderate | Low | Yes | Risk-accepted |
| POAM-021 | IA-2, AC-3 | App access gated by operator-set HTTP Basic Auth (no SSO/SAML) | Architectural / Customer Responsibility | — | silk-reeling::auth | N2 | Moderate | Low | Yes | Risk-accepted |
```

Rationales:
- **POAM-019** — Neither secret has a programmatic rotation source (Anthropic key is third-party; basic-auth is operator-set). Rotate manually via `put-secret-value`; revisit annually.
- **POAM-020** — App Lambda egresses to one known TLS endpoint (Anthropic API); placed outside a VPC to avoid NAT cost; no sensitive data at rest. Supersedes the inherited POAM-010 rationale for this resource.
- **POAM-021** — Access is an operator-configured username/password (**customer responsibility; operator-accepted risk**). **SAML federation to a customer IdP is the recommended stronger control**, not implemented (no IdP). Credentials in Secrets Manager (CMK), TLS-only, constant-time compare.

## Prerequisites before `apply` (NOT in this branch)

1. **App refactor** (silk_reeling_mirror repo, see its `docs/DEPLOY.md`): lazy `pose_extractor`, stateless single-request `/analyze` returning analysis+feedback, Mangum handler (`lambda_handler.handler`), CORS lock, browser loads the model from a static URL.
2. **CI build**: package the Lambda zip → `silk_reeling_package_path`; build the frontend → S3 under `/silk-reeling/`.
3. **Inject secret values** out-of-band from GitHub secrets.
4. **Manual CloudFront wiring**: OAC + origin (Function URL) + `/silk-reeling/*` behavior (CachingDisabled, forward `Authorization`).
5. **Grant the CI IAM principal** lambda/iam/secretsmanager/kms permissions (mirrors the `create_response_headers_policy` pattern).

## Boundary

Local branch only — not applied, not pushed. Review, run `make plan`, then decide.
