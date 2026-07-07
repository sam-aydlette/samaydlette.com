# SCN-2026-002 — Significant Change Notification & Security Impact Analysis
## Silk Reeling authentication replacement: HTTP Basic Auth → Amazon Cognito + JWT authorizer

| | |
| --- | --- |
| **SCN ID** | SCN-2026-002 |
| **System** | samaydlette.com (FedRAMP 20x KSI Certification + OSCAL Rev 5 Moderate SSP) |
| **SCN type** | **Adaptive** (`SCN-ADP`) — backfilled record |
| **Status** | Implemented — live in production since 2026-06-22 (Task 3); post-implementation verification complete 2026-07-06 |
| **Date initiated** | 2026-06-20 |
| **Approver** | Sam Aydlette — System Owner / Authorizing Operator |
| **Authoritative source** | CR26 corpus (`final_consolidated_rules_2026/2026-markdown`) |

This document is the human-readable SCN record (`SCN-CSO-INF`) and the copy of the
security impact analysis. Its machine-readable counterpart is the matching row in
[`scn-register.csv`](scn-register.csv).

**Backfill note (recorded 2026-07):** the change itself shipped 2026-06-22 through
the normal gated PR flow and closed POAM-021/022/023, but no SCN record was created
at the time. Because replacing the end-user authentication mechanism is a
security-relevant change to an existing component — not routine-recurring
maintenance — it categorizes as Adaptive under `SCN-CSO-EVA`, and this record
backfills the register so the SCN history is complete (`SCN-CSO-HIS`). The git/PR
history of the change remains the audit record (`SCN-CSO-MAR`).

## 1. Categorization (SCN-CSO-EVA)

Replaces the app's shared-credential HTTP Basic Auth gate with individual accounts
in an Amazon Cognito user pool (mandatory TOTP MFA, 14-character minimum password,
admin-only account creation) and moves enforcement from the Lambda to an API
Gateway JWT authorizer on the data routes. No FedRAMP Certification class change,
no federal customer data, no new external interconnection — so not Transformative.
A change to the authentication model of a public-facing surface is not
routine-recurring maintenance. Resolves to **Adaptive**.

## 2. Required information (SCN-CSO-INF)

- **Short description:** Basic Auth retired; Cognito user pool + Hosted UI (OAuth2
  code + PKCE) added; JWT authorizer attached to `ANY /api/{proxy+}`; `$default`
  route remains open serving only the SPA shell; API stage throttled (20 req/s,
  burst 10) and access-logged; SPA receives its public Cognito config from
  `/.well-known/silk-reeling-auth.json`.
- **Reason:** POAM-021/022/023 remediation — replace the single-factor shared
  credential, the authorizer-less API, and the unthrottled credential endpoint.
- **Customer impact:** app users now sign in with an invited individual account and
  mandatory TOTP MFA. No agency customers exist; no notification parties.
- **New/changed components:** `aws_cognito_user_pool` (+ domain, + pinned app
  client), `aws_apigatewayv2_authorizer` (JWT), stage throttling + access-log
  settings, silk-reeling auth-config publication.

## 3. Architecture change — delta to the authorization boundary

The end-user ingress (flow H in the authorization-boundary DFD) changes from
"Basic Auth validated inside the Lambda" to "Cognito-issued JWT validated by the
API Gateway authorizer at the edge, before any application code runs". The Cognito
user pool joins the boundary as an identity-provider component; the shared
credential in Secrets Manager was removed. No new egress.

## 4. Security impact analysis — control families touched

- **IA-2 / IA-2(1) / IA-2(2) / IA-8:** single-factor shared credential replaced by
  individual accounts with mandatory TOTP MFA; SSP dispositions move from
  not-applicable/risk-accepted to implemented (derived from the inventory's
  identity_provider component).
- **AC-7:** Cognito account lockout replaces "no lockout" (POAM-021/023).
- **SC-5:** stage throttling bounds credential-guessing and request floods
  (POAM-023).
- **AU-2/AU-3:** API access logging enabled to a CMK-encrypted log group
  (POAM-024).
- **SC-12/SC-28:** the Basic Auth shared secret was deleted; remaining app secret
  is the Anthropic API key (unchanged, rotation-verified daily).

### Verification plan (Adaptive requires post-implementation verification)

Confirm live: JWT authorizer present on data routes and absent on `$default`;
Cognito pool enforces MFA ON + 14-char policy + admin-only creation; stage
throttling and access logging active; SPA config served; page loads (200) while
unauthenticated data API calls are rejected (401).

### Verification result — COMPLETE (2026-07-06)

Verified against live AWS (us-east-2) via read-only CLI: `get-authorizers` shows
the JWT authorizer (issuer = the pool, audience = the pinned client) on
`ANY /api/{proxy+}`; `$default` is `NONE` (SPA shell only);
`describe-user-pool` shows `MfaConfiguration: ON`, minimum length 14 with all
character classes, `AllowAdminCreateUserOnly: true`; `get-stages` shows
`ThrottlingRateLimit: 20`, `ThrottlingBurstLimit: 10` and access logging to the
CMK-encrypted API log group; `/.well-known/silk-reeling-auth.json` serves the
matching client id. POAM-021/022/023 closure notes in `docs/poam.md` record the
same outcome.

## 5. New risks / vulnerabilities summary (SCN-ADP-NTF)

The shared-credential and unthrottled-endpoint risks (POAM-021/023) are retired.
Residual: TOTP is not phishing-resistant — WebAuthn/FIDO2 remains the documented
upgrade path, tracked directionally with POAM-025; Cognito availability becomes a
sign-in dependency (AWS-managed). No new interconnections; no notification
parties (SCN-CSO-NOM is met by the published certification data).
