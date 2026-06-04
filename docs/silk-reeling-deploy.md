# Silk Reeling Mirror — deployment

The gated app deploys with the site (`create_silk_reeling = true`). This documents
what it adds, how the compliance pipeline evaluates it, the findings, and the POA&M
responses.

## What it adds (infrastructure)

- `infrastructure/silk-reeling.tf` — the gated app:
  - App **Lambda** (Python zip — browser does the ML, so no OpenCV/MediaPipe).
  - **API Gateway HTTP API** (`$default` route/stage, AWS_PROXY integration) in
    front of the Lambda. **No Gateway authorizer** — the app's Basic Auth gates
    every request and must read the `Authorization` header itself (POAM-022). This
    replaces a Lambda **Function URL**, which this AWS account blocks for public
    access.
  - **Least-priv IAM** role/policy (logs + `GetSecretValue` on two ARNs + `kms:Decrypt` on one key).
  - Explicit **CloudWatch log group** (retention + tags) for the Lambda.
  - Customer-managed **KMS key** (rotation enabled) + two **Secrets Manager** secrets (basic-auth, Anthropic key).
  - `aws_lambda_permission` letting **API Gateway** (`apigateway.amazonaws.com`) invoke the Lambda.
- `variables.tf` — `create_silk_reeling` (default **false**), `silk_reeling_package_path`, `silk_reeling_max_concurrency`.
- `outputs.tf` — API Gateway endpoint, secret ARNs (for out-of-band value injection), manual CloudFront wiring pointer.

All gated by `create_silk_reeling = false` → inert until explicitly enabled.

## Security model

- **Single-layer, app-enforced access control:** the API Gateway HTTP API has no
  authorizer and passes the viewer's `Authorization` header through unchanged; the
  in-Lambda HTTP Basic Auth (constant-time compare) gates every request, regardless
  of how the endpoint is reached. A Gateway JWT/IAM authorizer is incompatible with
  Basic Auth (both use the `Authorization` header), so it is consciously omitted
  (POAM-022). Brute-force throttling (WAF/rate-limit) is not yet in place (POAM-023).
- **Secrets in Secrets Manager** (CMK-encrypted), read via least-priv IAM. **Values injected out-of-band** (`put-secret-value` in CI from a GitHub secret) — plaintext never enters Terraform state. This config creates only the secret containers; values are seeded post-apply.

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
| **CKV2_AWS_57 (Secrets Manager rotation)** | suppressed | no auto-rotation → POAM-019 |
| **CKV_AWS_309 (API GatewayV2 route authorizer)** | suppressed | no authorizer by design → POAM-022 |
| **CKV_AWS_76 (API Gateway access logging)** | suppressed | access logging deferred → POAM-024 |

> ⚠️ **Gap worth your attention:** the global `CKV_AWS_117` suppression (POAM-010)
> was written for the daily compliance Lambda with the rationale *"no internet
> egress."* The app Lambda **does** egress (to the Anthropic API), so that
> rationale doesn't fit it — the global suppression silently covers a resource it
> wasn't reasoned about. Flagged as **POAM-020** for an explicit decision rather
> than relying on the inherited skip. This is exactly the kind of thing the test
> should surface.

## POA&M responses

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
- Keeps the call **inside the AWS authorization boundary** — Bedrock is
  FedRAMP-authorized (leveraged authorization), so there is **no external
  interconnection** and **no SA-9 finding**.
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

## Prerequisites before `apply` (NOT in this branch)

1. **App refactor** (silk_reeling_mirror repo, see its `docs/DEPLOY.md`): lazy `pose_extractor`, stateless single-request `/analyze` returning analysis+feedback, Mangum handler (`lambda_handler.handler`), CORS lock, browser loads the model from a static URL.
2. **CI build**: package the Lambda zip → `silk_reeling_package_path`; build the frontend → S3 under `/silk-reeling/`.
3. **Inject secret values** out-of-band from GitHub secrets.
4. **Manual CloudFront wiring**: origin = the API Gateway endpoint host + `/silk-reeling/*` behavior (CachingDisabled, forward `Authorization`, attach the prefix-strip viewer-request function). No OAC — the app's Basic Auth is the gate.
5. **Grant the CI IAM principal** lambda/iam/secretsmanager/kms permissions (mirrors the `create_response_headers_policy` pattern).

## Boundary

Local branch only — not applied, not pushed. Review, run `make plan`, then decide.
