# Plan of Action and Milestones (POA&M)

**Cloud Service Provider:** Sam Aydlette
**Cloud Service Offering:** samaydlette.com
**Impact Level:** Moderate (FedRAMP Rev 5; equivalent to 20x Class C)
**POA&M Date:** 2026-05-08

This POA&M follows the field structure of the FedRAMP Rev 5 *Appendix O: Plan of Action and Milestones* template. Field names align with the official template; the format is condensed to Markdown for readability outside an Excel context. Per Rev 5 convention, this is the single register for all tracked weaknesses regardless of disposition; risk-accepted items are carried here with status `Risk-accepted`.

The authoritative machine-readable form is the OSCAL POA&M at [`/.well-known/oscal-poam.json`](/.well-known/oscal-poam.json), generated on every deploy by [`scripts/build-oscal-poam.py`](../scripts/build-oscal-poam.py). The OSCAL JSON and this Markdown document are kept in sync — both reflect the same set of items. When updating one, update the other in the same change. The Markdown is the human view; the OSCAL JSON is the machine view; both are required per FedRAMP NTC-0009 (machine-readable plus text-based equivalent).

The FedRAMP Excel template separates findings across tabs by lifecycle and source: Open POA&M Items (vulnerability-management items), Closed POA&M Items, Configuration Findings (software / IaC configuration scanner findings — Checkov, tfsec, etc.), PL-2 Findings (3PAO-detected SSP/documentation deficiencies), and Record of Changes. This document mirrors that structure as separate sections.

The 20x VDR rules call risk-accepted entries "Accepted Vulnerabilities" (`VDR-RPT-AVI`); the same items appear in machine-readable form at `/.well-known/vdr-report.json`, with `poam_ref` cross-references back to the entries below.

Status values: **Open** · **In progress** · **Closed** · **Risk-accepted**.

---

## Open POA&M Items


*No items are currently open.* POAM-001 (deployer credentials) and POAM-002 (runtime-signal signing) are Closed below; the remaining assessment findings are tracked as Configuration Findings (risk-accepted), False Positives, or PL-2 Findings.

---

## Configuration Findings (POAM-003 through POAM-018)

Configuration Findings are findings about how software and infrastructure are configured, surfaced by IaC and configuration scanners (Checkov, tfsec) rather than by vulnerability scanners. They are tracked as POA&M items but live on a separate tab in the FedRAMP Excel template because the lifecycle is different from vulnerability findings. Each entry below is either a Checkov-reported configuration weakness or an explicit architectural decision; all are risk-accepted with documented rationale **except: POAM-011/POAM-018 (closed under Task 6); POAM-005/POAM-017/POAM-024 (closed under Task 7); POAM-006/POAM-013 (closed under Task 8b); POAM-012/POAM-015 (reclassified as false positives under Task 8b — see the False Positives register); POAM-021/POAM-022/POAM-023 (closed under Task 3 — Cognito); POAM-019 (reclassified as a false positive under Task 3 — SC-12 met via verified manual rotation); and POAM-025 (open operational requirement — root/operator hardware MFA, surfaced by the 2026-06-22 Prowler scan)** (closure notes below the table).

The source of truth for the rationale is the inline `#checkov:skip=ID:reason` annotation in `infrastructure/main.tf` (or, for POAM-016, the architectural decision record in [`docs/recovery-plan.md`](recovery-plan.md)). All entries have been evaluated per VDR-EVA-* (PAIN N1-N5, internet-reachability, likely-exploitability) and carry the corresponding `VDR-RPT-AVI` fields in the published `/.well-known/vdr-report.json`. None is in CISA KEV.

| POA&M ID | Controls | Weakness Name | Detector Source | Source Identifier | Asset Identifier | PAIN | Original Risk | Adj. Risk | Risk Adj. | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| POAM-005 | AU-2, AU-3 | S3 access logging not enabled | Checkov | CKV_AWS_18 | aws-s3-bucket::website-prod | N1 | Low | — | No | Closed (Task 7) |
| POAM-006 | SI-12 | S3 lifecycle configuration not defined | Checkov | CKV_AWS_300 | aws-s3-bucket::website-prod | N1 | Low | — | No | Closed (Task 8b) |
| POAM-007 | SC-7, SI-4 | CloudFront WAF not attached | Checkov | CKV_AWS_68 | aws-cloudfront-distribution | N2 | Moderate | Low | Yes | Risk-accepted |
| POAM-009 | CP-2, CP-7 | CloudFront origin failover not configured | Checkov | CKV_AWS_86 | aws-cloudfront-distribution | N1 | Low | — | No | Risk-accepted |
| POAM-010 | SC-7 | Lambda VPC configuration absent | Checkov | CKV_AWS_117 | aws-lambda::compliance-monitor | N1 | Low | — | No | Risk-accepted |
| POAM-011 | SC-12, SC-28 | Lambda env vars not customer-key encrypted | Checkov | CKV_AWS_173 | aws-lambda::compliance-monitor | N1 | Low | — | No | Closed (Task 6) |
| POAM-013 | SI-4 | Lambda DLQ not configured | Checkov | CKV_AWS_116 | aws-lambda::compliance-monitor | N1 | Low | — | No | Closed (Task 8b) |
| POAM-017 | AU-11 | CloudWatch log retention < 1 year (7-day retention) | Checkov | CKV_AWS_338 | aws-cloudwatch-log-group | N1 | Low | — | No | Closed (Task 7) |
| POAM-018 | SC-28 | CloudWatch log group not customer-key encrypted | Checkov | CKV_AWS_158 | aws-cloudwatch-log-group | N1 | Low | — | No | Closed (Task 6) |
| POAM-020 | SA-9, CA-3 | Interconnection with Anthropic API (non-FedRAMP-authorized external service) | Architectural decision | silk-reeling-deploy.md | interconnection::anthropic-api | N2 | Moderate | Low | Yes | Risk-accepted |
| POAM-025 | IA-2(1), IA-2(2), IA-2(8), CM-6 | Root + operator MFA is virtual TOTP, not hardware/phishing-resistant | Prowler | root-account-hardware-mfa-enabled; iam_user_hardware_mfa_enabled | aws-account::root; aws-iam-user::saydlette-dev | N2 | Moderate | Low | Yes | Open (operational requirement) |
| POAM-021 | IA-2(2), AC-7 | App access via single-factor shared-credential HTTP Basic Auth (no MFA, no lockout) | Architectural decision | silk-reeling-deploy.md | silk-reeling::access-control | N2 | Moderate | Low | Yes | Closed (Task 3) |
| POAM-022 | IA-2, AC-3 | API Gateway HTTP API route specifies no authorizer (app-layer Basic Auth is the access control) | Checkov | CKV_AWS_309 | aws-apigatewayv2::silk-reeling | N2 | Moderate | Low | Yes | Closed (Task 3) |
| POAM-023 | AC-7, SC-5 | No brute-force / rate-limit protection on the Basic Auth endpoint (no lockout, no WAF) | Security review | security-review.md | silk-reeling::access-control | N2 | Moderate | Low | Yes | Closed (Task 3) |
| POAM-024 | AU-2, AU-3 | API Gateway HTTP API access logging not enabled | Checkov | CKV_AWS_76 | aws-apigatewayv2::silk-reeling | N1 | Low | — | No | Closed (Task 7) |

**POAM-011 and POAM-018 closed (Task 6, 2026-06-16) — encryption-consistency remediation.** Both were risk-accepted on the rationale that the contents were non-sensitive and AWS-default encryption sufficed. Rather than carry them as standing acceptances, the system was brought to a single at-rest standard: *every* Lambda environment block and *every* CloudWatch log group is now encrypted with a customer-managed CMK. Specifically — the compliance Lambda's environment and log group use a new `aws_kms_key.at_rest` CMK; the route53 query-log group (when enabled) uses the same CMK; and the silk-reeling Lambda's environment uses the existing `aws_kms_key.silk_reeling` CMK (its role already held `kms:Decrypt` on that key). With no Lambda env or log group left unencrypted, the global Checkov suppressions for `CKV_AWS_173` and `CKV_AWS_158` were **removed** from `.checkov.yaml` — the checks now pass on their own, so the remediation is enforced by the gate rather than asserted. The website S3 bucket remains on SSE-S3 (AES-256, AWS-managed keys) by deliberate decision: it holds only public static content and persists no user data, so a customer CMK there would add cost and key-management burden without protecting anything sensitive (the app's pose extraction is client-side; nothing is stored at rest).

**POAM-020 (added with the gated Silk Reeling app):** The app Lambda calls the
Anthropic API, a non-FedRAMP-authorized external service (SA-9). The only data
crossing the authorization boundary is the derived deviation summary (per-joint
metrics, scores, hotspots, exercise id) over TLS — no video, raw landmarks, or
personal data. The interconnection and its data flow are modeled in the OSCAL SSP
(`system-implementation.components[type=interconnection]` and
`system-characteristics.data-flow`), emitted by `scripts/build-oscal-ssp.py` only
when the app is present in the canonical inventory. **Supply-chain / data-handling
due diligence (SA-9):** acceptance of derived metrics crossing to a
non-FedRAMP-authorized service rests on Anthropic's commercial API terms — under
which API inputs/outputs are not used to train models and are retained only
transiently for trust-and-safety. This is the stated basis for the risk acceptance
and is an **assumption to re-verify against the then-current Anthropic commercial
terms at each annual security review**; a change in those terms reopens this POA&M.
**Remediation:** migrate feedback to Claude on AWS Bedrock (FedRAMP-authorized,
in-boundary), which removes the external interconnection. Applies only while the
app is deployed. **POAM-019**
(Secrets Manager automatic rotation, Checkov CKV2_AWS_57) was **reclassified as a
false positive under Task 3** — see the False Positives register. With the
basic-auth secret removed (Task 3), the only remaining app secret is the
third-party Anthropic API key, which has no programmatic rotation source (AWS
cannot mint a new upstream key), so automatic rotation is infeasible by
construction rather than a deferred fix. SC-12 rotation is met by documented
annual manual rotation, and — this is what makes it a false positive and not an
accepted risk — rotation currency is now **verified automatically**: the runtime
KSI emitter reads the secret's `LastChangedDate` daily and fails an SC-12
validation if rotation lapses past the cadence.

**POAM-021 (added with the gated Silk Reeling app):** Access to the gated app is
authenticated by an operator-configured username/password (HTTP Basic Auth) —
single-factor, shared credential, with no MFA (IA-2(2)) and no account lockout
(AC-7). This is a **customer-responsibility control**: the operator configures
and owns the credential and accepts the residual risk. At the system's Moderate
categorization this is a real IA-2(2)/AC-7 weakness, accepted only on an interim
basis while remediation is implemented (see **Remediation** below: Cognito MFA +
API Gateway authorizer, Task 3). The interim acceptance rests on the compensating
controls, not on the categorization: the credential is held in Secrets Manager
(CMK), transmitted only over TLS, and compared in constant time. The credential gate runs in the Lambda itself, so it
applies to every request regardless of how the API Gateway endpoint is reached.
**Risk acceptance:** the operator, acting as the **sole customer and sole user** of
the system, has approved this operational requirement and accepted the residual
risk — no third party bears it, so the acceptance is complete and authoritative.
It is valid **only while the operator remains the sole customer**: onboarding any
real user is a re-assessment trigger, and **any customer onboarded must explicitly
accept this risk (recorded in the CRM) or adopt the upgrade path below**.
**Upgrade path (available on request — not a deficiency):** federation to a
customer IdP via SAML/OIDC, or native WebAuthn/FIDO2 with FIPS-AAGUID attestation,
would provide phishing-resistant MFA (IA-2(1)) and move authentication to
`customer-configured`; offered on request, not pre-built. FedRAMP control
origination is tracked per-control in the OSCAL SSP (`control-origination` props)
and is surfaced in the forthcoming CRM/SCuBA as a customer-accepted shared
responsibility.

**POAM-022 (API Gateway no authorizer):** An API Gateway HTTP API fronts the app
Lambda and its `$default` route specifies no authorizer (Checkov CKV_AWS_309).
This is deliberate: access control is enforced in the Lambda via HTTP Basic Auth,
and a Gateway-level JWT/IAM authorizer would consume the `Authorization` header the
app needs to read. API Gateway replaces a Lambda Function URL (which this AWS
account blocks for public access); the Gateway passes the viewer's `Authorization`
header through unchanged and the app rejects any request lacking a valid
credential. **Remediation:** if the app later federates to an IdP (see POAM-021), a
JWT authorizer on the route supersedes this acceptance. Applies only while the app
is deployed.

**POAM-023 (no brute-force protection):** The Basic Auth endpoint has no account
lockout (AC-7) and no rate limiting / WAF (SC-5) in front of it, so credential
guessing is not throttled. Surfaced by the `software-security` review. At the
system's Moderate categorization this is a real AC-7/SC-5 weakness, accepted only
on an interim basis pending remediation (see **Remediation** below: API Gateway
usage-plan throttling + Cognito lockout, Task 3). The interim acceptance rests on
the compensating controls, not the categorization: the credential is a
high-entropy operator-set secret compared in constant time, and a single shared
credential is the only valid pair (no user enumeration). **Assessor
posture:** a 3PAO penetration test may re-rate an unauthenticated-reachable,
unthrottled credential endpoint above Low regardless of the compensating controls
above; the operator's accepted position is explicitly conditional — any evidence of
credential-guessing in the Lambda execution logs (`/aws/lambda/samaydlette-com-silk-reeling`)
or CloudFront logs triggers **immediate** implementation of the deferred WAF
rate-rule rather than continued acceptance, and an assessor finding that re-rates
the residual is treated as that trigger. **Remediation:** attach AWS WAF with a
rate-based rule to the CloudFront distribution, or add an API Gateway usage-plan
throttle; deferred on cost (~$120/yr WAF, consistent with POAM-007). Applies only
while the app is deployed.

**POAM-017 and POAM-024 closed (Task 7) — audit logging + retention.** *POAM-017:*
every CloudWatch log group now has 365-day retention (AU-11) — the route53 query-log
and silk-reeling Lambda groups were raised from 7 days; the compliance group was
already 365 (Task 6). *POAM-024:* the silk-reeling HTTP API stage now emits one JSON
access-log line per request to a new CMK-encrypted, 365-day log group
(`/aws/apigateway/samaydlette-com-silk-reeling`), authorized by a scoped CloudWatch
Logs delivery resource policy. With these in place the global `CKV_AWS_338` and
`CKV_AWS_76` suppressions were **removed** from `.checkov.yaml`, so both checks now
pass on their own.

**POAM-005 closed (Task 7) — S3 server access logging.** The website bucket now
writes S3 server access logs to a dedicated, locked-down log bucket
(`samaydlette-com-logs`: public access blocked, ownership-enforced/ACLs disabled,
encrypted, ~13-month lifecycle), authorized by a bucket policy that grants the S3
log-delivery service write access to the `s3-access/` prefix from this account and
source bucket only. The global `CKV_AWS_18` suppression is **removed**; the log
target carries a narrow inline skip (it cannot log to itself). CloudFront access
logging (C-3, the visitor-request audit) is enabled out-of-band to the same bucket
under the `cloudfront/` prefix.

**POAM-006 and POAM-013 closed (Task 8b) — infra hygiene under Moderate.**
*POAM-006:* the versioned website bucket now has a lifecycle configuration (abort
incomplete multipart uploads after 7 days; expire non-current versions after 90
days; current/live versions are never expired). *POAM-013:* the compliance Lambda
now has an SQS dead-letter queue (`...-opa-compliance-dlq`, SSE-SQS, 14-day
retention) via `dead_letter_config`, so a failed daily async run is captured for
inspection (SI-4). The `CKV_AWS_300` and `CKV_AWS_116` suppressions are removed.

**POAM-012 and POAM-015 reclassified as false positives (Task 8b).** On review
under Moderate, neither is a real gap (see the False Positives register): *POAM-012*
(reserved concurrency / SC-5) does not apply to a daily internal EventBridge
function with no DoS exposure — SC-5 is met at the boundary, and the account is
hard-capped at 10 concurrency, making reservation infeasible anyway; *POAM-015*
(AWS Signer / SI-7, SA-12) flags the absence of one specific tool, but software
integrity is met via the Sigstore source-signing chain plus the OIDC/GitOps chain
of custody. Per the "POA&M only for real gaps" policy, both move to the register
rather than being carried as risk acceptances.

**POAM-021, POAM-022, and POAM-023 closed (Task 3) — Cognito authentication.** The
shared HTTP Basic Auth credential is replaced by Amazon Cognito: per-user accounts
with **required TOTP MFA**, a strong password policy, and Cognito's built-in
brute-force lockout (**POAM-021**). The Silk Reeling HTTP API's `/api/*` routes now
carry a **Cognito JWT authorizer at the gateway** (**POAM-022**, `CKV_AWS_309`
suppression removed); the `$default` route stays unauthenticated only so the SPA /
Hosted-UI login page can load. The stage enforces **rate-limit throttling**
(**POAM-023**). The app also validates the JWT at the app layer (so it stays
standalone-deployable) and the basic-auth secret is removed — which also resolves
POAM-019: the sole remaining secret (the Anthropic key) has no programmatic
rotation source, so `CKV2_AWS_57` is reclassified as a false positive with SC-12
met via verified manual rotation (see its entry in the False Positives register).

**POAM-025 (added from the 2026-06-22 Prowler scan, `fedramp_20x_ksi_low` baseline).**
The root account and the operator IAM user (`saydlette-dev`) authenticate with a
**virtual TOTP** MFA, not a hardware/phishing-resistant authenticator. 800-53
IA-2(1)/(2) (MFA present) is **met**; the gap is against the *phishing-resistant*
objective (IA-2(8), CR26 KSI-IAM-APM) and the hardware-MFA target that the
operator has adopted into the system's **CM-6** configuration baseline (CIS/STIG
hardening). This is therefore **not** a false positive (the control is in-scope via
CM-6 + the adopted baseline) and **not** a risk-adjustment (the gap is real) — it
is an **operational requirement** the operator accepts on interim grounds: a
hardware token is not yet on hand. **Compensating control:** virtual MFA is enabled
on both principals now. **Remediation:** enroll a hardware MFA token (or FIDO2
passkey — phishing-resistant and free) on root and on `saydlette-dev`; milestone
deferred pending token acquisition. The finding is kept live (not suppressed) so it
reports until remediated. The same scan's other findings were remediated live
(deleted the unused `*:*` `CLI_admin` role and the dormant `steampipe-user`; applied
the AWS FSBP account password policy; relocated the operator's policies to an
`operators` group) or routed to Task 12 (S3 deny-non-TLS; org-of-one + SCPs for the
region/governance findings); three were dismissed as false positives (below).

**Standard fields for all of POAM-003 through POAM-018:**

- **Point of Contact:** Sam Aydlette (operator)
- **Resources Required:** None at present (risk-accepted). If reactivated, cost and operator time per item; see the rationale in `infrastructure/main.tf`.
- **Original Detection Date:** 2026-05-06 (initial implementation review)
- **Scheduled Completion Date:** Not applicable (risk-accepted; revisit annually per [`security-review.md`](security-review.md))
- **Status Date:** 2026-05-08
- **Vendor Dependency:** No
- **Last Vendor Check-in Date:** —
- **Vendor Dependent Product Name:** —
- **Remediation Plan (per item):** Reactivate the Checkov check by removing the `#checkov:skip=` annotation in `infrastructure/main.tf`, then implement the missing control. Cost varies per item.
- **Weakness Description (per item):** see the inline `#checkov:skip=` rationale in `infrastructure/main.tf`, mirrored verbatim into the VDR report's `risk_accepted[].explanation` field.

If the threat profile or scope changes — for example, if the system starts processing PII, adds customer-facing forms, or starts handling federal customer data — any of these is reopened, reclassified, and a remediation path established.

---

## Closed POA&M Items

### POAM-001 — Long-lived AWS access keys for the deployer

| Field | Value |
| --- | --- |
| POA&M ID | POAM-001 |
| Controls | IA-2, IA-5, AC-2 |
| Weakness Name | Long-lived AWS access keys for the deployer |
| Weakness Description | The CI deployer authenticates to AWS using an IAM user's access key + secret access key, stored in GitHub Actions encrypted secrets. If either secret leaks, the credentials remain valid until manually rotated. |
| Weakness Detector Source | CodeGuard rule `codeguard-0-iac-security` (avoid long-lived service credentials in favor of workload identity). |
| Weakness Source Identifier | codeguard-0-iac-security |
| Asset Identifier | `aws-iam-user::github-actions-deployer`; `github-secret::AWS_ACCESS_KEY_ID`; `github-secret::AWS_SECRET_ACCESS_KEY` |
| Point of Contact | Sam Aydlette (operator) |
| Resources Required | Operator time (~half day); no additional cost. |
| Remediation Plan | Migrate to GitHub OIDC role assumption against AWS. Provision an `aws_iam_openid_connect_provider` for `token.actions.githubusercontent.com` and a deployer role whose trust policy restricts `sub` to this repo's `main` pushes, pull requests, and the `prod` Environment (not `:*`). Switch the workflow's `aws-actions/configure-aws-credentials` step from access-key inputs to `role-to-assume`. Verify, then delete the IAM user and remove the GitHub Actions secrets. |
| Original Detection Date | 2026-05-06 |
| Scheduled Completion Date | 2026-08-31 |
| Status Date | 2026-05-08 |
| Vendor Dependency | No |
| Last Vendor Check-in Date | — |
| Vendor Dependent Product Name | — |
| Original Risk Rating | Moderate |
| Adjusted Risk Rating | — |
| Risk Adjustment | No |
| Status | Closed |

**Compensating controls.** Secrets live only in GitHub Actions encrypted secrets, scoped to the deploy job. The IAM user is permission-scoped to what Terraform needs; it is not a console-login user. GitHub secret scanning with push protection is enabled. The Sigstore signing chain in the same workflow already proves GitHub OIDC works end-to-end (cosign signs via `id-token: write` and the GitHub Actions OIDC provider).

**90-day key rotation (active compensating control).** While the OIDC migration remains deferred, the operator rotates the AWS access key every 90 days. The procedure is documented in [`docs/policies/secure-configuration-guide.md`](policies/secure-configuration-guide.md) and the rotation log is part of the [annual security review](security-review.md). This bounds the leakage window for a compromised key but does not eliminate the standing-privilege surface; OIDC migration remains the durable answer and this POA&M item remains open.

**Risk if not remediated.** A leaked access key gives an attacker persistent access until detection and manual rotation, with the leakage window bounded by the 90-day rotation cadence. Under OIDC, the equivalent compromise produces an STS session token valid for ~1 hour with no persistence — a ~2,160× shorter exposure window.


**Closed 2026-06-15.** Migrated to GitHub OIDC role assumption (`github-actions-deploy-oidc`); the workflow now uses `role-to-assume`. After a fully green OIDC deploy (compliance-check + Deploy Infrastructure jobs both assuming the role), the legacy `github-actions-deploy` IAM user and its access key were deleted and the `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` repo secrets removed. No long-lived AWS credential remains on the deploy path.

---

### POAM-002 — Runtime KSI signal not cryptographically signed

| Field | Value |
| --- | --- |
| POA&M ID | POAM-002 |
| Controls | AU-10, SI-7, SC-12, SC-13 |
| Weakness Name | Runtime KSI signal not cryptographically signed |
| Weakness Description | The runtime KSI signal at `/.well-known/ksi-signal-runtime.json` was published by the Lambda without a cryptographic signature; consumers trusted it implicitly via the well-known URL rather than a verifiable cryptographic root. |
| Weakness Detector Source | Internal review during initial implementation. |
| Weakness Source Identifier | internal-review-2026-05-06 |
| Asset Identifier | `aws-lambda::compliance-monitor`; `aws-s3-key::.well-known/ksi-signal-runtime.json` |
| Point of Contact | Sam Aydlette (operator) |
| Resources Required | Operator time (~half day); ~$1/month KMS cost. |
| Remediation Plan | AWS KMS asymmetric signing in the Lambda — ECC NIST P-256 `SIGN_VERIFY` key, Lambda role granted `kms:Sign` + `kms:GetPublicKey`, sign the canonical signal bytes, embed the signature in `provenance.attestation`, publish the public key at `/.well-known/runtime-signing-pubkey.pem`. |
| Original Detection Date | 2026-05-06 |
| Scheduled Completion Date | 2026-06-17 |
| Status Date | 2026-06-17 |
| Vendor Dependency | No |
| Last Vendor Check-in Date | — |
| Vendor Dependent Product Name | — |
| Original Risk Rating | Low |
| Adjusted Risk Rating | — |
| Risk Adjustment | No |
| Status | Closed |
| False Positive | No |

**Closed 2026-06-17 (Task 5).** The runtime emitter (`infrastructure/lambda/index.js`) now signs the runtime signal with an asymmetric KMS key (`aws_kms_key.runtime_signing`, ECC NIST P-256, `SIGN_VERIFY`). It canonicalizes the signal with `provenance.attestation` absent (sorted-keys JSON, no whitespace), signs the SHA-256 digest (`ECDSA_SHA_256`), and places the signature in `provenance.attestation`; the verifying public key is published at `/.well-known/runtime-signing-pubkey.pem`. A consumer verifies by stripping `provenance.attestation`, recomputing the canonical bytes, and checking the signature against the published key — no trust in the well-known URL required. **Residual (operational):** asymmetric KMS keys do not auto-rotate; key rotation is a manual new-key + re-publish-pubkey step, tracked in the [secure-configuration guide](policies/secure-configuration-guide.md).

---

The Closed POA&M Items section uses the same field structure as Open items, plus a `False Positive` field that distinguishes findings that were not real weaknesses. Closed entries are retained for assessment-history continuity per the FedRAMP template.

---

## False Positives

These scanner findings were investigated and dismissed as not representing a real
weakness at this system's Moderate categorization. Each names the suppressed
check, why it does not apply, and how the mapped control is actually met (in the
SSP). They are distinct from risk-accepted items (real weaknesses with documented
acceptance) and carry no `poam_ref` in the VDR.

| Was | Control | Suppressed check | Why it is a false positive | Control met via |
| --- | --- | --- | --- | --- |
| POAM-003 | CP-9 | CKV_AWS_144 (S3 cross-region replication) | Cross-region replication is not a CP-9 requirement at Moderate for this system; the data is public static content. | S3 versioning + full reproducibility of the site from the Git repository (SSP CP-9 narrative). |
| POAM-004 | AU-2 | CKV_AWS_23 (S3 event notifications) | S3 event notifications are an integration feature, not an audit control; AU-2 does not require them. | S3 server access logging (Task 7) + account-wide CloudTrail (SSP AU-2 narrative). |
| POAM-008 | SI-3 | CKV_AWS_174 (Log4j-specific WAF rule) | No Java/Log4j anywhere in the stack (Lambda is Node.js/Python; site is static), and WAF is intentionally declined (Decision 3), so the rule cannot apply. | Dependency scanning (Grype + Dependabot) over the controlled execution surface (SSP SI-3 narrative). |
| POAM-014 | AU-2 | CKV_AWS_50 (Lambda X-Ray tracing) | X-Ray is performance/latency observability, not a security audit control; AU-2 coverage does not depend on it. | CloudWatch Logs + CloudTrail (SSP AU-2 narrative). |
| POAM-012 | SC-5 | CKV_AWS_115 (Lambda reserved concurrency) | Reserved concurrency manages concurrency contention/DoS; the compliance monitor is a daily EventBridge-triggered internal function with no DoS exposure or contention. SC-5 does not depend on it here (and the account is hard-capped at 10 concurrency, so reservation is infeasible regardless). | SC-5 at the system boundary: CloudFront + API Gateway throttling + AWS Shield Standard (SSP SC-5 narrative). |
| POAM-015 | SI-7, SA-12 | CKV_AWS_272 (Lambda AWS Signer) | The check flags the absence of one specific signing tool (AWS Signer); no control mandates that tool. Software/supply-chain integrity is established by another mechanism. | Sigstore source-signing chain (deploy-time KSI signal Sigstore-signed, anchored in the public Rekor log; Wasm policy bytes verify against the canonical inventory hash) + the GitHub OIDC / GitOps chain of custody with no out-of-band code path (SSP SI-7/SA-12 narrative). |
| POAM-019 | SC-12, SC-28 | CKV2_AWS_57 (Secrets Manager automatic rotation) | The check flags the absence of *automatic* rotation; no control mandates that specific mechanism. The one remaining secret is a third-party Anthropic API key with no programmatic rotation source — AWS cannot mint a new upstream key — so a Secrets Manager rotation Lambda is infeasible by construction (the basic-auth secret it shared the finding with was removed under Task 3). SC-12 rotation is met by an equivalent procedure, and rotation currency is verified automatically, so this is not an accepted risk. | Documented annual manual rotation (operator regenerates the key at the provider and writes it via `put-secret-value`), **verified automatically** by the runtime KSI emitter: it reads the secret's `LastChangedDate` each day and fails an SC-12 validation if rotation lapses past the cadence (395-day grace), so a missed rotation surfaces as a runtime KSI failure rather than relying on a calendar reminder (SSP SC-12 narrative). |
| — (Prowler 2026-06-22) | n/a | `iam_role_access_not_stale_to_bedrock` (AWSServiceRoleForSupport) | The role is an **AWS-managed service-linked role**; its permission set is defined and controlled by AWS, is not operator-modifiable, and the Support SLR is benign. (The other hit, `CLI_admin`, was deleted, so it no longer reports.) | N/A — the operator cannot alter a service-linked role's permissions; AWS owns its lifecycle. |
| — (Prowler 2026-06-22) | SC-28 | `s3_bucket_default_encryption` *(deprecated check)* (samaydlette-com-logs) | A check Prowler itself marks deprecated; the log bucket uses **SSE-S3 (AES256)** by design (`infrastructure/logging.tf`), and the non-deprecated server-side-encryption check does not fire. | SSE-S3/AES256 at rest on the log bucket — a deliberate choice (a customer-managed key is not warranted for public-content-derived access logs; SSP SC-28 narrative). |
| — (Prowler 2026-06-22) | AU-2 | `s3_bucket_server_access_logging_enabled` (samaydlette-com-logs) | A log-target bucket cannot log to itself without creating a recursion loop; logging the log sink onto itself is a standard exception. | The website bucket's S3 server access logs land in this bucket, which is the terminal sink; it carries an inline scanner skip for self-logging, consistent with POAM-005's closure (SSP AU-2 narrative). |

False positives are tracked separately so an assessor can see which scanner findings were investigated and dismissed with rationale, distinct from risk-accepted items (which are real weaknesses with documented acceptance).

---

## PL-2 Findings (3PAO-Identified)

Not applicable. No 3PAO assessment is in scope for this PoC; no SSP or documentation deficiencies have been formally documented by an independent assessor.

The FedRAMP template carries a PL-2 Findings tab for 3PAO-identified deficiencies in the System Security Plan, the Authorization Boundary Diagram, or supporting documentation. Typical examples are SSP sections that disagree with the running system, an ABD that doesn't depict an in-scope external service, or boilerplate text that wasn't customized to the CSO. This section exists for parity with the template and would be populated if and when a 3PAO is engaged.

---

## Annual Review

Risk-accepted items are revisited annually as part of [`docs/security-review.md`](security-review.md). The review checks: do the rationales still hold? has the threat profile changed? are there new compensating controls that would let an item move to Closed? If any answer flips, the item is reopened.

---

## Field Notes

- **Risk rating values** follow the FedRAMP convention: `Low`, `Moderate`, `High`, `Critical`. PAIN (the FedRAMP 20x VDR rating, N1–N5) is a finer-grained scale; the column is included for cross-reference but Original Risk Rating uses the Rev 5 vocabulary so the POA&M reads as a Rev 5 artifact.
- **Risk Adjustment = Yes** on POAM-007 and POAM-015 reflects that the scanner-default risk rating (Moderate) has been adjusted to Low based on documented compensating controls. The adjustment rationale is in the corresponding inline `#checkov:skip=` annotation.
- **Asset Identifier** uses a `<type>::<name>` form so each entry is unambiguous. AWS resources resolve via Terraform; GitHub assets via owner/repo.