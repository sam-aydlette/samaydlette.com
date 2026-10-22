# Silk Reeling Mirror — deployment

The gated app deploys with the site (`create_silk_reeling = true`). This documents
what it adds, how the compliance pipeline evaluates it, the findings, and the POA&M
responses.

## What it adds (infrastructure)

- `infrastructure/silk-reeling.tf` — the gated app:
  - App **Lambda** (Python zip — browser does the ML, so no OpenCV/MediaPipe).
  - **API Gateway HTTP API** in front of the Lambda (AWS_PROXY integration). Two
    routes: `ANY /api/{proxy+}` carries a **Cognito JWT authorizer**; `$default`
    serves the SPA unauthenticated so the login page can load. The stage enforces
    **throttling** and writes **access logs** to a CMK-encrypted CloudWatch log
    group. This replaces a Lambda **Function URL**, which this AWS account blocks
    for public access.
  - **Least-priv IAM** role/policy (logs + `GetSecretValue` on the one app secret + `kms:Decrypt` on one key).
  - Explicit **CloudWatch log group** (retention + tags) for the Lambda.
  - Customer-managed **KMS key** (rotation enabled) + one **Secrets Manager** secret (the Anthropic API key).
  - `aws_lambda_permission` letting **API Gateway** (`apigateway.amazonaws.com`) invoke the Lambda.
- `infrastructure/cognito.tf` — the **Cognito** user pool, Hosted-UI domain and app
  client: admin-created users, required TOTP MFA, OAuth2 PKCE login.
- `infrastructure/bootstrap/cloudfront.tf` — the `/silk-reeling/*` CloudFront
  behavior (API Gateway origin, caching disabled, forwards the `Authorization`
  bearer header, prefix-strip viewer-request function). This lives in the
  operator-applied bootstrap stack, not in this config.
- `variables.tf` — `create_silk_reeling` (default **false**), `silk_reeling_package_path`, `silk_reeling_max_concurrency`.
- `outputs.tf` — API Gateway endpoint and secret ARN (for out-of-band value injection).

All gated by `create_silk_reeling = false` → inert until explicitly enabled. The
production deploy sets it to true (see Status below).

## Security model

- **Identity at the gateway:** Cognito is the identity provider (required TOTP
  MFA). The `/api/*` routes are gated by a Cognito **JWT authorizer** at API
  Gateway (POAM-022 closed), and the app also validates the JWT in-Lambda so it
  stays standalone-deployable. Stage throttling provides rate limiting (POAM-023
  closed). This replaced the original single shared-credential HTTP Basic Auth
  (POAM-021 closed, 2026-06-22; see the history below).
- **Secrets in Secrets Manager** (CMK-encrypted), read via least-priv IAM. **Values injected out-of-band** (`put-secret-value` in CI from a GitHub secret) — plaintext never enters Terraform state. This config creates only the secret container; the value is seeded post-apply.
- **External interconnection:** the Lambda sends a derived movement summary to the
  Anthropic API (POAM-020, open and risk-accepted; see below).

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
| CKV_AWS_149 (Secrets Manager CMK) | **pass** | CMK set |
| CKV_AWS_7 (KMS rotation) | **pass** | `enable_key_rotation = true` |
| **CKV2_AWS_57 (Secrets Manager rotation)** | suppressed | false positive (was POAM-019): third-party key with no programmatic rotation source; manual rotation is verified daily by the runtime KSI emitter. See `.checkov.yaml` and the False Positives register in `docs/poam.md` |
| CKV_AWS_309 (API GatewayV2 route authorizer) | **pass** | `/api/*` routes carry the Cognito JWT authorizer (POAM-022 closed) |
| CKV_AWS_76 (API Gateway access logging) | **pass** | stage access logs to a CMK-encrypted log group (POAM-024 closed) |

> ⚠️ **Gap worth your attention:** the global `CKV_AWS_117` suppression (POAM-010)
> was written for the daily compliance Lambda with the rationale *"no internet
> egress."* The app Lambda **does** egress (to the Anthropic API), so that
> rationale doesn't fit it — the global suppression silently covers a resource it
> wasn't reasoned about. Flagged as **POAM-020** for an explicit decision rather
> than relying on the inherited skip. This is exactly the kind of thing the test
> should surface.

## POA&M responses (history: 2026-06 rollout)

> The rest of this section and the next record the original rollout. Since then
> POAM-019 has been reclassified as a false positive, POAM-021/022/023 have been
> closed by the Cognito migration, and the basic-auth secret has been removed.
> `docs/poam.md` is the current record.

> Status: **POAM-019, POAM-020, and POAM-021 are all finalized** in
> `docs/poam.md`. The checkov scan confirmed POAM-019 (`CKV2_AWS_57`), now
> suppressed in `.checkov.yaml`. The scan also surfaced **`CKV2_AWS_64`** (KMS
> key policy not defined), which was **fixed** in `silk-reeling.tf` with an
> explicit least-privilege key policy rather than accepted. Snippets below are
> retained for reference.

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
| POAM-020 | SA-9, CA-3 | Interconnection with Anthropic API — non-FedRAMP-authorized external service; derived movement metrics cross the authorization boundary | Architectural decision | — | interconnection::anthropic-api | N2 | Moderate | Low | Yes | Risk-accepted |
| POAM-021 | IA-2, AC-3 | App access gated by operator-set HTTP Basic Auth (no SSO/SAML) | Architectural / Customer Responsibility | — | silk-reeling::auth | N2 | Moderate | Low | Yes | Risk-accepted |
```

Rationales:
- **POAM-019** — Neither secret has a programmatic rotation source (Anthropic key is third-party; basic-auth is operator-set). Rotate manually via `put-secret-value`; revisit annually.
- **POAM-020** — The app Lambda **interconnects with the Anthropic API, which is not FedRAMP-authorized** (SA-9). Data crossing the boundary is the **derived deviation summary only** (joint-angle metrics, scores, hotspots, exercise id) over TLS — no video, no raw landmarks, no PII. Must be documented in the SSP as a **CA-3 interconnection + data flow**. **Remediation: route feedback through Claude on AWS Bedrock** (FedRAMP-authorized, in-boundary) — removes the external interconnection entirely. The earlier "no-VPC" point is subsumed: egress is to this one documented endpoint.
- **POAM-021** — Access is an operator-configured username/password (**customer responsibility; operator-accepted risk**). **SAML federation to a customer IdP is the recommended stronger control**, not implemented (no IdP). Credentials in Secrets Manager (CMK), TLS-only, constant-time compare.

## External interconnection: Anthropic (SSP + SA-9) — per operator note

The Lambda's call to Anthropic is an **external system interconnection** and must
be modeled in the SSP, not just risk-noted:

- **SSP (CA-3):** add an `interconnection` component for the Anthropic API to
  `system-implementation.components`, and a **`data-flow`** description under
  `system-characteristics`. The generator (`scripts/build-oscal-ssp.py`) currently
  emits `authorization-boundary` but **no `data-flow`/`network-architecture`** —
  those sections need adding.
- **Data flow across the boundary:** browser → Lambda (pose frames, transient,
  not persisted) → **Anthropic** receives only the *derived deviation summary*
  (joint deviations, scores, hotspots, exercise id) over TLS; response is markdown
  feedback. **No video, no raw landmarks, no PII** leave the boundary.
- **POA&M (SA-9):** POAM-020 — use of a non-FedRAMP-authorized external service.
  Risk-accepted given low data sensitivity + TLS, **or remediated** via Bedrock.

### Remediation: Claude on AWS Bedrock (closes POAM-020)

Routing feedback through **Claude on AWS Bedrock** instead of the Anthropic API:
- Keeps the call **inside the AWS authorization boundary** as a leveraged AWS
  service, so there is **no external interconnection** and **no SA-9 finding**,
  provided Bedrock's FedRAMP authorization for the region and impact level is
  confirmed against the FedRAMP Marketplace at the time of the change.
- **Removes the Anthropic API key secret** — the Lambda authenticates to Bedrock
  via IAM (`bedrock:InvokeModel` on the specific model ARN); one fewer secret to
  store/rotate (also softens POAM-019).
- App change: `feedback.py` calls Bedrock (Claude messages API on Bedrock) rather
  than the Anthropic SDK.
- Terraform change: drop the Anthropic secret; add `bedrock:InvokeModel` to the
  Lambda role; keep the CMK + basic-auth secret.

If compliance is the goal, Bedrock is the cleaner posture: it converts a
risk-accepted external interconnection into an in-boundary, FedRAMP-authorized
service call.

## Prerequisites for `apply` (completed during the 2026-06-03 rollout)

1. **App refactor** (silk_reeling_mirror repo, see its `docs/DEPLOY.md`): lazy `pose_extractor`, stateless single-request `/analyze` returning analysis+feedback, Mangum handler (`lambda_handler.handler`), CORS lock, browser loads the model from a static URL.
2. **CI build**: package the Lambda zip → `silk_reeling_package_path`; build the frontend → S3 under `/silk-reeling/`.
3. **Inject secret values** out-of-band from GitHub secrets.
4. **Manual CloudFront wiring**: origin = the API Gateway endpoint host + `/silk-reeling/*` behavior (CachingDisabled, forward `Authorization`, attach the prefix-strip viewer-request function). No OAC. (Then: the app's Basic Auth was the gate. Now: the behavior lives in `infrastructure/bootstrap/cloudfront.tf` and the Cognito JWT authorizer is the gate.)
5. **Grant the CI IAM principal** lambda/iam/secretsmanager/kms permissions (mirrors the `create_response_headers_policy` pattern).

## Status

**Deployed and live in production** since 2026-06-03 (PR #82); latest redeploy
2026-06-06. The prerequisites listed above were completed during that rollout, and the
production deploy pipeline sets `create_silk_reeling = true`. The change is formally
recorded as an Adaptive significant change in
[SCN-2026-001](scn/SCN-2026-001-silk-reeling.md). _(This section previously read "local
branch only — not applied, not pushed"; that described the original draft proposal and
is superseded.)_
