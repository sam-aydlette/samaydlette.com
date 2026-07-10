# Plan of Action and Milestones (POA&M)

**Cloud Service Provider:** Sam Aydlette
**Cloud Service Offering:** samaydlette.com
**Impact Level:** Moderate (FedRAMP Rev 5; equivalent to 20x Class C)
**POA&M Date:** 2026-05-08

This POA&M follows the field structure of the FedRAMP Rev 5 *Appendix O: Plan of Action and Milestones* template. Field names align with the official template; the format is condensed to Markdown for readability outside an Excel context. Per Rev 5 convention, this is the single register for all tracked weaknesses regardless of disposition; risk-accepted items are carried here with status `Risk-accepted`.

The authoritative machine-readable form is the OSCAL POA&M at [`/.well-known/oscal-poam.json`](/.well-known/oscal-poam.json), generated on every deploy by [`scripts/build-oscal-poam.py`](../scripts/build-oscal-poam.py). The OSCAL JSON and this Markdown document are kept in sync — both reflect the same set of items. When updating one, update the other in the same change. The Markdown is the human view; the OSCAL JSON is the machine view; both are required per FedRAMP NTC-0009 (machine-readable plus text-based equivalent).

The FedRAMP Excel template separates findings across tabs by lifecycle and source: Open POA&M Items (vulnerability-management items), Closed POA&M Items, Configuration Findings (software / IaC configuration scanner findings — Checkov, tfsec, etc.), PL-2 Findings (assessor-detected SSP/documentation deficiencies), and Record of Changes. This document mirrors that structure as separate sections.

The 20x VDR rules call risk-accepted entries "Accepted Vulnerabilities" (`VER-RPT-AVI`); the same items appear in machine-readable form at `/.well-known/vdr-report.json`, with `poam_ref` cross-references back to the entries below.

**POA&M-as-code for the OPA gate:** findings raised by the deploy/runtime policy gate itself are suppressed only through the machine-readable exceptions register at [`infrastructure/policy/exceptions/data.json`](../infrastructure/policy/exceptions/data.json). Each entry names the violation (`resource`, `rule_id`), a justification, an expiry date, and a `ticket` referencing its entry in this document (a False Positive or risk-accepted item). Suppression happens in the policy aggregator, suppressed findings remain visible in the gate report under `excepted`, an entry past its expiry stops suppressing at evaluation time, and CI fails on any expired entry (`scripts/check-exceptions.py`) so the register cannot rot. When adding or closing an exception, update the corresponding entry here in the same change.

Status values: **Open** · **In progress** · **Closed** · **Risk-accepted**.

---

## Open POA&M Items


*No items are currently open.* POAM-001 (deployer credentials) and POAM-002 (runtime-signal signing) are Closed below; the remaining assessment findings are tracked as Configuration Findings (risk-accepted), False Positives, or PL-2 Findings.

---

## Configuration Findings (POAM-003 through POAM-018)

Configuration Findings are findings about how software and infrastructure are configured, surfaced by IaC and configuration scanners (Checkov, tfsec) rather than by vulnerability scanners. They are tracked as POA&M items but live on a separate tab in the FedRAMP Excel template because the lifecycle is different from vulnerability findings. Each entry below is either a Checkov-reported configuration weakness or an explicit architectural decision; all are risk-accepted with documented rationale **except: POAM-011/POAM-018 (closed under Task 6); POAM-005/POAM-017/POAM-024 (closed under Task 7); POAM-006/POAM-013 (closed under Task 8b); POAM-012/POAM-015 (reclassified as false positives under Task 8b — see the False Positives register); POAM-021/POAM-022/POAM-023 (closed under Task 3 — Cognito); POAM-019 (reclassified as a false positive under Task 3 — SC-12 met via verified manual rotation); and POAM-025 (open operational requirement — root/operator hardware MFA, surfaced by the 2026-06-22 Prowler scan)** (closure notes below the table).

The source of truth for the rationale is the inline `#checkov:skip=ID:reason` annotation in `infrastructure/main.tf` (or, for POAM-016, the architectural decision record in [`docs/recovery-plan.md`](recovery-plan.md)). All entries have been evaluated per VDR-EVA-* (PAIN N1-N5, internet-reachability, likely-exploitability) and carry the corresponding `VER-RPT-AVI` fields in the published `/.well-known/vdr-report.json`. None is in CISA KEV.

| POA&M ID | Controls | Weakness Name | Detector Source | Source Identifier | Asset Identifier | PAIN | Original Risk | Adj. Risk | Risk Adj. | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| POAM-005 | AU-2, AU-3 | S3 access logging not enabled | Checkov | CKV_AWS_18 | aws-s3-bucket::website-prod | N1 | Low | — | No | Closed (Task 7) |
| POAM-006 | SI-12 | S3 lifecycle configuration not defined | Checkov | CKV_AWS_300 | aws-s3-bucket::website-prod | N1 | Low | — | No | Closed (Task 8b) |
| POAM-007 | SC-7, SI-4 | CloudFront WAF not attached | Checkov | CKV_AWS_68 | aws-cloudfront-distribution | N2 | Moderate | Low | Yes | Open (risk-accepted) |
| POAM-009 | CP-2, CP-7 | CloudFront origin failover not configured | Checkov | CKV_AWS_86, CKV_AWS_310 | aws-cloudfront-distribution | N1 | Low | — | No | Open (risk-accepted) |
| POAM-031 | SC-7, SC-8 | CloudFront response-headers policy not attached | Checkov | CKV2_AWS_32 | aws-cloudfront-distribution | N1 | Low | — | No | Closed (security headers attached 2026-06-29) |
| POAM-032 | AU-6, SI-4 | CloudTrail trail has no CloudWatch Logs integration or SNS delivery notifications | Checkov, tfsec | CKV2_AWS_10, CKV_AWS_252, AVD-AWS-0162 | aws-cloudtrail::management | N1 | Low | — | No | Open (risk-accepted) |
| POAM-010 | SC-7 | Lambda VPC configuration absent | Checkov | CKV_AWS_117 | aws-lambda::compliance-monitor | N1 | Low | — | No | Open (risk-accepted) |
| POAM-011 | SC-12, SC-28 | Lambda env vars not customer-key encrypted | Checkov | CKV_AWS_173 | aws-lambda::compliance-monitor | N1 | Low | — | No | Closed (Task 6) |
| POAM-013 | SI-4 | Lambda DLQ not configured | Checkov | CKV_AWS_116 | aws-lambda::compliance-monitor | N1 | Low | — | No | Closed (Task 8b) |
| POAM-017 | AU-11 | CloudWatch log retention < 1 year (7-day retention) | Checkov | CKV_AWS_338 | aws-cloudwatch-log-group | N1 | Low | — | No | Closed (Task 7) |
| POAM-018 | SC-28 | CloudWatch log group not customer-key encrypted | Checkov | CKV_AWS_158 | aws-cloudwatch-log-group | N1 | Low | — | No | Closed (Task 6) |
| POAM-020 | SA-9, CA-3 | Interconnection with Anthropic API (non-FedRAMP-authorized external service) | Architectural decision | silk-reeling-deploy.md | interconnection::anthropic-api | N2 | Moderate | Low | Yes | Open (risk-accepted) |
| POAM-025 | IA-2(1), IA-2(2), IA-2(8), CM-6 | Root + operator MFA is virtual TOTP, not hardware/phishing-resistant | Prowler | root-account-hardware-mfa-enabled; iam_user_hardware_mfa_enabled | aws-account::root; aws-iam-user::saydlette-dev | N2 | Moderate | Low | Yes | Open (operational requirement) |
| POAM-021 | IA-2(2), AC-7 | App access via single-factor shared-credential HTTP Basic Auth (no MFA, no lockout) | Architectural decision | silk-reeling-deploy.md | silk-reeling::access-control | N2 | Moderate | Low | Yes | Closed (Task 3) |
| POAM-022 | IA-2, AC-3 | API Gateway HTTP API route specifies no authorizer (app-layer Basic Auth is the access control) | Checkov | CKV_AWS_309 | aws-apigatewayv2::silk-reeling | N2 | Moderate | Low | Yes | Closed (Task 3) |
| POAM-023 | AC-7, SC-5 | No brute-force / rate-limit protection on the Basic Auth endpoint (no lockout, no WAF) | Security review | security-review.md | silk-reeling::access-control | N2 | Moderate | Low | Yes | Closed (Task 3) |
| POAM-024 | AU-2, AU-3 | API Gateway HTTP API access logging not enabled | Checkov | CKV_AWS_76 | aws-apigatewayv2::silk-reeling | N1 | Low | — | No | Closed (Task 7) |
| POAM-026 | AC-5, AC-6, AC-6(7) | Operator IAM group holds broad IAM administration privileges | Checkov | CKV2_AWS_56 | aws-iam-group::operators | N2 | Moderate | Low | Yes | Open (risk-accepted) |

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

**POAM-021 (closed 2026-06-22, Task 3 — historical record):** As shipped, access
to the gated app was authenticated by an operator-configured username/password
(HTTP Basic Auth) — single-factor, shared credential, no MFA (IA-2(2)), no
account lockout (AC-7). The weakness was risk-accepted on an interim,
sole-customer basis with compensating controls (credential in CMK-encrypted
Secrets Manager, TLS-only, constant-time comparison) while the remediation was
built. **Closure:** the Basic Auth gate was replaced by Amazon Cognito with
mandatory TOTP MFA, a 14-character password policy, and admin-only user
creation, fronted by an API Gateway JWT authorizer on the data routes. The
shared single-factor credential no longer exists. Phishing-resistant
authenticators (WebAuthn/FIDO2, IA-2(1)) remain the documented upgrade path and
are tracked in the same family as POAM-025's hardware-token direction.

**POAM-022 (closed 2026-06-22, Task 3 — historical record):** The app's API
Gateway HTTP API originally specified no authorizer on any route (Checkov
CKV_AWS_309) — deliberate at the time, because the Lambda's Basic Auth gate
consumed the `Authorization` header. **Closure:** the HTTP API now carries a
Cognito JWT authorizer on the `ANY /api/{proxy+}` data routes; an
unauthenticated request to the data API is rejected at the gateway (401) before
the Lambda runs. The `$default` route intentionally stays open so the SPA shell
and login page can load — that route serves static content only.

**POAM-023 (closed 2026-06-22, Task 3 — historical record):** The Basic Auth
endpoint originally had no account lockout (AC-7) and no rate limiting (SC-5),
so credential guessing was unthrottled. The interim acceptance carried an
explicit trigger: any credential-guessing evidence in the app's execution logs
would force the deferred WAF rate-rule immediately. **Closure:** API Gateway
stage throttling (20 req/s, burst 10) now fronts the app and Cognito provides
account lockout, so the trigger condition is structurally addressed at $0
rather than via WAF (~$120/yr, still pre-authorized under this item's original
terms if credential-guessing evidence ever appears in
`/aws/lambda/samaydlette-com-silk-reeling` or the API access logs).

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

These scanner findings were investigated and determined not to represent a real
weakness at this system's Moderate categorization. Each names the suppressed
check, why it does not apply, and how the mapped control is actually met (in the
SSP). They are distinct in *disposition* from risk-accepted items (real
weaknesses with documented acceptance), but they are **not** dropped from
tracking: each is a formal, **open** POA&M item and **carries a `poam_ref`** in
the VDR, so every suppressed scanner finding has a live, referenceable home and
none can be silently missed. The disposition (`false-positive`) is recorded on
the item; the lifecycle status stays `Open` until the underlying check no longer
fires (e.g. the resource is removed) or the finding is reclassified.

Rows whose POA&M ID is `—` are Prowler findings outside the published VDR's
scanner set (org-governance / service-linked-role checks on a single-account
boundary); they are documented here for assessor visibility but are not formal
machine-tracked items.

| POA&M ID | Control | Suppressed check | Why it is a false positive | Control met via |
| --- | --- | --- | --- | --- |
| POAM-003 | CP-9 | CKV_AWS_144 (S3 cross-region replication) | Cross-region replication is not a CP-9 requirement at Moderate for this system; the data is public static content. | S3 versioning + full reproducibility of the site from the Git repository (SSP CP-9 narrative). |
| POAM-004 | AU-2 | CKV_AWS_23 (website bucket) + CKV2_AWS_62 (log bucket) — S3 event notifications | S3 event notifications are an integration feature, not an audit control; AU-2 does not require them, on either bucket. | S3 server access logging (Task 7) + account-wide CloudTrail (SSP AU-2 narrative). |
| POAM-008 | SI-3 | CKV_AWS_174, CKV2_AWS_47 (Log4j-specific WAF rule) | No Java/Log4j anywhere in the stack (Lambda is Node.js/Python; site is static), and WAF is intentionally declined (Decision 3), so the rule cannot apply. | Dependency scanning (Grype + Dependabot) over the controlled execution surface (SSP SI-3 narrative). |
| POAM-032 | AU-6, SI-4 | `CKV2_AWS_10` / `AVD-AWS-0162` (CloudTrail not integrated with CloudWatch Logs), `CKV_AWS_252` (no SNS delivery notifications) | The management trail delivers to S3 only. CloudWatch Logs integration duplicates every management event into paid log-group storage to enable real-time metric filters that this single-operator system replaces with the quarterly audit-log review (KSI-MLA-RVL); SNS per-delivery notifications have no consumer. Residual: no real-time alerting on control-plane events — accepted at this scale, revisited if the operating model gains a second principal or an incident shows the review cadence was too slow. | Log-file validation on the trail; delivery bucket is TLS-only, versioned, public-access-blocked with AU-11 lifecycle tiering; quarterly review per `docs/architecture-decisions.md` (KSI-MLA-RVL). |
| POAM-030 | SC-7 | CKV_AWS_374 (CloudFront geo restriction not enabled) | A public personal website is intended to be reachable from every geography; no control requires geo-blocking, and enabling one would deny legitimate access for no security benefit. | SC-7 boundary protection via the managed CloudFront + API Gateway interfaces, AWS Shield Standard, and request throttling (SSP SC-7 narrative). |
| POAM-014 | AU-2 | CKV_AWS_50 (Lambda X-Ray tracing) | X-Ray is performance/latency observability, not a security audit control; AU-2 coverage does not depend on it. | CloudWatch Logs + CloudTrail (SSP AU-2 narrative). |
| POAM-012 | SC-5 | CKV_AWS_115 (Lambda reserved concurrency) | Reserved concurrency manages concurrency contention/DoS; the compliance monitor is a daily EventBridge-triggered internal function with no DoS exposure or contention. SC-5 does not depend on it here (and the account is hard-capped at 10 concurrency, so reservation is infeasible regardless). | SC-5 at the system boundary: CloudFront + API Gateway throttling + AWS Shield Standard (SSP SC-5 narrative). |
| POAM-015 | SI-7, SA-12 | CKV_AWS_272 (Lambda AWS Signer) | The check flags the absence of one specific signing tool (AWS Signer); no control mandates that tool. Software/supply-chain integrity is established by another mechanism. | Sigstore source-signing chain (deploy-time KSI signal Sigstore-signed, anchored in the public Rekor log; Wasm policy bytes verify against the canonical inventory hash) + the GitHub OIDC / GitOps chain of custody with no out-of-band code path (SSP SI-7/SA-12 narrative). |
| POAM-019 | SC-12, SC-28 | CKV2_AWS_57 (Secrets Manager automatic rotation) | The check flags the absence of *automatic* rotation; no control mandates that specific mechanism. The one remaining secret is a third-party Anthropic API key with no programmatic rotation source — AWS cannot mint a new upstream key — so a Secrets Manager rotation Lambda is infeasible by construction (the basic-auth secret it shared the finding with was removed under Task 3). SC-12 rotation is met by an equivalent procedure, and rotation currency is verified automatically, so this is not an accepted risk. | Documented annual manual rotation (operator regenerates the key at the provider and writes it via `put-secret-value`), **verified automatically** by the runtime KSI emitter: it reads the secret's `LastChangedDate` each day and fails an SC-12 validation if rotation lapses past the cadence (395-day grace), so a missed rotation surfaces as a runtime KSI failure rather than relying on a calendar reminder (SSP SC-12 narrative). |
| — (Prowler 2026-06-22) | n/a | `iam_role_access_not_stale_to_bedrock` (AWSServiceRoleForSupport) | The role is an **AWS-managed service-linked role**; its permission set is defined and controlled by AWS, is not operator-modifiable, and the Support SLR is benign. (The other hit, `CLI_admin`, was deleted, so it no longer reports.) | N/A — the operator cannot alter a service-linked role's permissions; AWS owns its lifecycle. |
| POAM-027 | AC-6 | `CKV_AWS_355`, `CKV_AWS_287`, `CKV_AWS_356` (bootstrap deploy/assessment role read-only IAM) | The flagged actions are account-level read-only IAM/enumeration (List*/Describe*/Get*, metadata-only Secrets reads) that AWS does not permit to be resource-scoped — they have no per-resource ARN form, so `Resource "*"` is required. No write, no admin, no credential retrieval. | Least privilege (AC-6) met by explicit enumerated read-only Action lists + ARN-scoped management statements; inline `#checkov:skip=` rationale in `infrastructure/bootstrap/main.tf`. |
| POAM-029 (Prowler 2026-06-22; extended 2026-07-09 to the CloudTrail trail) | SC-28 | `CKV_AWS_145` / `AVD-AWS-0132` / `s3_bucket_default_encryption` *(Prowler-deprecated)* (samaydlette-com-logs); `CKV_AWS_145` (samaydlette-com-tfstate); `CKV_AWS_119` (samaydlette-com-tflock); `CKV_AWS_35` / `AVD-AWS-0015` (CloudTrail log files) + `CKV_AWS_145` (samaydlette-com-cloudtrail) | Internal resources encrypt at rest with **AES256 (SSE-S3 / AWS-managed)** rather than a customer CMK. SC-28 is met by AES256 in each case; a CMK is declined deliberately: the log bucket holds low-sensitivity public-resource logs (a CMK adds no confidentiality benefit and complicates log delivery); the lock table holds only lock metadata; and the state bucket, though it can hold secrets, is private, TLS-only, versioned, and reachable only by the deploy role + operator, so a CMK is defense-in-depth, declined to limit key sprawl. | SSE-S3/AES256 at rest on all three (`infrastructure/logging.tf`, `infrastructure/bootstrap/tf-state-backend.tf`) — a deliberate choice (SSP SC-28 narrative). |
| POAM-028 (Prowler 2026-06-22) | AU-2, AU-3 | `CKV_AWS_18` / `AVD-AWS-0089` / `s3_bucket_server_access_logging_enabled` (samaydlette-com-logs) | A log-target bucket cannot log to itself without creating a recursion loop; logging the log sink onto itself is a standard exception. | The website bucket's S3 server access logs land in this bucket, the terminal sink; consistent with POAM-005's closure (SSP AU-2/AU-3 narrative). |
| — (Prowler 2026-06-23) | n/a (org governance) | `organizations_account_part_of_organizations` (account not in an AWS Organization) | AWS Organizations is a multi-account governance construct. This is a single-account, self-attested PoC with no member or child accounts to govern, so there is no organization for it to belong to. Org membership is not a Moderate control requirement and confers no security benefit on a one-account system. At multi-account scale this activates; here it has no subject. | N/A by architecture — single-account boundary by design; the cross-account guardrails an Organization provides have nothing to act on with no second account (authorization-boundary scope). |
| — (Prowler 2026-06-23) | n/a (org governance) | `organizations_scp_check_deny_regions` (no region-deny SCP) | Service Control Policies require an AWS Organization and — decisively — an SCP **never restricts the organization's management account**. In a single-account system the only account *is* the management account, so a region-deny SCP would constrain nothing (it would be cosmetic). The check presupposes member accounts this system does not have. | N/A by architecture — SCPs are structurally inapplicable to a lone management account; the regional footprint is bounded to us-east-1/us-east-2 by the Terraform configuration and IAM, not an SCP (authorization-boundary scope). |
| — (Prowler 2026-06-23) | n/a (org governance) | `organizations_opt_out_ai_services_policy` (no AI-services opt-out policy) | The AI-services opt-out is an Organizations policy that opts *member accounts* out of AWS using their content to improve AI/ML services. It requires an organization and governs child accounts; with neither, there is nothing for it to apply to. | N/A by architecture — no organization and no member accounts whose content-use to govern; the workload holds only public static content and one operator's app data (authorization-boundary scope). |
| — (Prowler 2026-06-23) | n/a (org governance) | `organizations_tags_policies_enabled_and_attached` (no org tag policy) | Tag policies are an Organizations feature that standardizes tagging *across member accounts*. With no organization and a single account, there are no member accounts to enforce a tag standard against. | N/A by architecture — single-account tagging is enforced directly in the Terraform configuration; CM-8 inventory is met by the canonical inventory + IaC, not an org tag policy (SSP CM-8 narrative). |

False positives are carried as formal, open POA&M items (disposition `false-positive`) — not dismissed into a separate untracked list — so an assessor can see which scanner findings were investigated and why, and so every suppressed finding keeps a `poam_ref` in the VDR. This is what distinguishes them from risk-accepted items: the *disposition* differs (the scanner is wrong vs. a real weakness accepted), but both stay open and tracked.

---

## PL-2 Findings (Assessor-Identified)

Not applicable. No FedRAMP Recognized independent assessment is in scope for this PoC; no SSP or documentation deficiencies have been formally documented by an independent assessor.

The FedRAMP template carries a PL-2 Findings tab for FedRAMP Recognized assessor-identified deficiencies in the System Security Plan, the Authorization Boundary Diagram, or supporting documentation. Typical examples are SSP sections that disagree with the running system, an ABD that doesn't depict an in-scope external service, or boilerplate text that wasn't customized to the CSO. This section exists for parity with the template and would be populated if and when a FedRAMP Recognized assessor is engaged.

---

## Annual Review

Risk-accepted items are revisited annually as part of [`docs/security-review.md`](security-review.md). The review checks: do the rationales still hold? has the threat profile changed? are there new compensating controls that would let an item move to Closed? If any answer flips, the item is reopened.

---

## Field Notes

- **Risk rating values** follow the FedRAMP convention: `Low`, `Moderate`, `High`, `Critical`. PAIN (the FedRAMP 20x VDR rating, N1–N5) is a finer-grained scale; the column is included for cross-reference but Original Risk Rating uses the Rev 5 vocabulary so the POA&M reads as a Rev 5 artifact.
- **Risk Adjustment = Yes** on POAM-007 and POAM-015 reflects that the scanner-default risk rating (Moderate) has been adjusted to Low based on documented compensating controls. The adjustment rationale is in the corresponding inline `#checkov:skip=` annotation.
- **Asset Identifier** uses a `<type>::<name>` form so each entry is unambiguous. AWS resources resolve via Terraform; GitHub assets via owner/repo.