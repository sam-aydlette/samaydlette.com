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


### POAM-002 — Runtime KSI signal not cryptographically signed

| Field | Value |
| --- | --- |
| POA&M ID | POAM-002 |
| Controls | AU-10, SI-7, SC-12, SC-13 |
| Weakness Name | Runtime KSI signal not cryptographically signed |
| Weakness Description | The runtime KSI signal at `/.well-known/ksi-signal-runtime.json` is published by the Lambda without a cryptographic signature. Consumers trust it implicitly via "AWS has not lied about what is at the well-known URL." That is the standard static-site CDN trust model, but it does not reduce to the public Sigstore transparency log the deploy-time signal does. |
| Weakness Detector Source | Internal review during initial implementation. |
| Weakness Source Identifier | internal-review-2026-05-06 |
| Asset Identifier | `aws-lambda::compliance-monitor`; `aws-s3-key::.well-known/ksi-signal-runtime.json` |
| Point of Contact | Sam Aydlette (operator) |
| Resources Required | Operator time (~half day); ~$1/month KMS cost. |
| Remediation Plan | AWS KMS asymmetric signing in the Lambda — provision an ECC NIST P-256 key with `key_usage = "SIGN_VERIFY"`, grant the Lambda role `kms:Sign` and `kms:GetPublicKey`, sign the canonical-form bytes, and embed the signature in `provenance.attestation`. Publish the public key at `/.well-known/runtime-signing-pubkey.pem`. An alternative path is federating an OIDC identity into the Lambda for Sigstore-keyless signing, but that requires more new infrastructure for the same end state. |
| Original Detection Date | 2026-05-06 |
| Scheduled Completion Date | When an external consumer asks to verify the runtime signal end-to-end. Low priority for the PoC. |
| Status Date | 2026-05-08 |
| Vendor Dependency | No |
| Last Vendor Check-in Date | — |
| Vendor Dependent Product Name | — |
| Original Risk Rating | Low |
| Adjusted Risk Rating | — |
| Risk Adjustment | No |
| Status | Open |

**Compensating controls.** The Lambda's IAM role can write only to the single S3 key for the runtime signal — a compromised Lambda cannot tamper with other site content. The runtime signal carries `provenance.builder.id` identifying its execution context. Drift between the (signed) deploy-time signal and the (unsigned) runtime signal is detectable from outside; mismatched components or validations are high-confidence signal of either real drift or a tampered runtime signal. All other published artifacts (OSCAL SSP, OSCAL POA&M, VDR report, IIW CSV) are now Sigstore-signed in CI; this POA&M item applies only to the runtime KSI signal.

**Risk if not remediated.** A consumer pulling the runtime signal cannot independently verify it has not been tampered with. For a fully public site with no consuming agency, the risk is reputational. In any portfolio context where multiple agencies consume signals across CSPs, runtime signal forgery becomes a credible attack and signing closes it.

---

## Configuration Findings (POAM-003 through POAM-018)

Configuration Findings are findings about how software and infrastructure are configured, surfaced by IaC and configuration scanners (Checkov, tfsec) rather than by vulnerability scanners. They are tracked as POA&M items but live on a separate tab in the FedRAMP Excel template because the lifecycle is different from vulnerability findings. Each entry below is either a Checkov-reported configuration weakness or an explicit architectural decision; all are currently risk-accepted with documented rationale.

The source of truth for the rationale is the inline `#checkov:skip=ID:reason` annotation in `infrastructure/main.tf` (or, for POAM-016, the architectural decision record in [`docs/recovery-plan.md`](recovery-plan.md)). All entries have been evaluated per VDR-EVA-* (PAIN N1-N5, internet-reachability, likely-exploitability) and carry the corresponding `VDR-RPT-AVI` fields in the published `/.well-known/vdr-report.json`. None is in CISA KEV.

| POA&M ID | Controls | Weakness Name | Detector Source | Source Identifier | Asset Identifier | PAIN | Original Risk | Adj. Risk | Risk Adj. | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| POAM-005 | AU-2, AU-3 | S3 access logging not enabled | Checkov | CKV_AWS_18 | aws-s3-bucket::website-prod | N1 | Low | — | No | Risk-accepted |
| POAM-006 | SI-12 | S3 lifecycle configuration not defined | Checkov | CKV_AWS_300 | aws-s3-bucket::website-prod | N1 | Low | — | No | Risk-accepted |
| POAM-007 | SC-7, SI-4 | CloudFront WAF not attached | Checkov | CKV_AWS_68 | aws-cloudfront-distribution | N2 | Moderate | Low | Yes | Risk-accepted |
| POAM-009 | CP-2, CP-7 | CloudFront origin failover not configured | Checkov | CKV_AWS_86 | aws-cloudfront-distribution | N1 | Low | — | No | Risk-accepted |
| POAM-010 | SC-7 | Lambda VPC configuration absent | Checkov | CKV_AWS_117 | aws-lambda::compliance-monitor | N1 | Low | — | No | Risk-accepted |
| POAM-011 | SC-12, SC-28 | Lambda env vars not customer-key encrypted | Checkov | CKV_AWS_173 | aws-lambda::compliance-monitor | N1 | Low | — | No | Risk-accepted |
| POAM-012 | SC-5 | Lambda concurrent execution limit not set | Checkov | CKV_AWS_115 | aws-lambda::compliance-monitor | N1 | Low | — | No | Risk-accepted |
| POAM-013 | SI-4 | Lambda DLQ not configured | Checkov | CKV_AWS_116 | aws-lambda::compliance-monitor | N1 | Low | — | No | Risk-accepted |
| POAM-015 | SI-7, SA-12 | Lambda zip not signed via AWS Signer | Checkov | CKV_AWS_272 | aws-lambda::compliance-monitor | N2 | Moderate | Low | Yes | Risk-accepted |
| POAM-017 | AU-11 | CloudWatch log retention < 1 year (7-day retention) | Checkov | CKV_AWS_338 | aws-cloudwatch-log-group | N1 | Low | — | No | Risk-accepted |
| POAM-018 | SC-28 | CloudWatch log group not customer-key encrypted | Checkov | CKV_AWS_158 | aws-cloudwatch-log-group | N1 | Low | — | No | Risk-accepted |
| POAM-019 | SC-12, SC-28 | Secrets Manager automatic rotation not enabled | Checkov | CKV2_AWS_57 | aws-secretsmanager::silk-reeling | N2 | Moderate | Low | Yes | Risk-accepted |
| POAM-020 | SA-9, CA-3 | Interconnection with Anthropic API (non-FedRAMP-authorized external service) | Architectural decision | silk-reeling-deploy.md | interconnection::anthropic-api | N2 | Moderate | Low | Yes | Risk-accepted |
| POAM-021 | IA-2(2), AC-7 | App access via single-factor shared-credential HTTP Basic Auth (no MFA, no lockout) | Architectural decision | silk-reeling-deploy.md | silk-reeling::access-control | N2 | Moderate | Low | Yes | Risk-accepted |
| POAM-022 | IA-2, AC-3 | API Gateway HTTP API route specifies no authorizer (app-layer Basic Auth is the access control) | Checkov | CKV_AWS_309 | aws-apigatewayv2::silk-reeling | N2 | Moderate | Low | Yes | Risk-accepted |
| POAM-023 | AC-7, SC-5 | No brute-force / rate-limit protection on the Basic Auth endpoint (no lockout, no WAF) | Security review | security-review.md | silk-reeling::access-control | N2 | Moderate | Low | Yes | Risk-accepted |
| POAM-024 | AU-2, AU-3 | API Gateway HTTP API access logging not enabled | Checkov | CKV_AWS_76 | aws-apigatewayv2::silk-reeling | N1 | Low | — | No | Risk-accepted |

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
app is deployed. POAM-019
(Secrets Manager automatic rotation, Checkov CKV2_AWS_57) was confirmed by the
checkov scan and is now finalized: the two app secrets are a third-party API key
and an operator-set basic-auth credential with no programmatic rotation source;
rotated manually, revisited annually.

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

**POAM-024 (API Gateway access logging not enabled):** The HTTP API stage does not
emit access logs (Checkov CKV_AWS_76). HTTP API access logging requires a CloudWatch
Logs delivery resource-policy that this deployment does not yet provision; the
Lambda's own execution log group (`/aws/lambda/samaydlette-com-silk-reeling`) and
CloudFront access logs provide request-level coverage in the interim. Risk-adjusted
Low (operational observability, not an access-control gap). **Remediation:** add the
delivery resource-policy and a stage `access_log_settings` block. Applies only while
the app is deployed.

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