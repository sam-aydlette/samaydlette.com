# Secure Configuration Guide (FedRAMP 20x SCG)

This guide describes the secure access, configuration, operation, and decommissioning of the **top-level administrative accounts** for the system, per `SCG-CSO-RSC`. It is published publicly (`SCG-CSO-PUB`) and lives in the repository so it is versioned alongside the code (`SCG-ENH-VRH`).

For this system, "top-level administrative accounts" map to two real-world accounts: the AWS root account, and the GitHub repository owner.

## 1. AWS root account

**Naming.** The root account is the operator's email address registered against the AWS account holding all production resources.

**Secure access.** MFA enforced via Duo. Access is interactive only — there are no API keys generated for root. Sessions are minimal: root is used only for billing, service quotas, and IAM-policy-of-last-resort actions. Day-to-day deploys use the IAM deployer principal, not root.

**Secure configuration.** AWS-default secure settings are kept. CloudTrail is account-wide and management-event logging is enabled. The S3 bucket public-access block is on at the account level.

**Secure operation.** Sessions are short. Any root-level action is recorded in CloudTrail. Routine operations do not use root.

**Decommissioning.** If the operator transfers stewardship of the site, the AWS root account is closed and the domain is transferred per AWS's account-closure procedures. All API keys for the deployer principal are rotated and deleted before account closure.

## 2. GitHub repository owner

**Naming.** The operator's GitHub account, which is the owner of the `samaydlette.com` repository.

**Secure access.** MFA enforced via Duo. All pushes to `main` require an authenticated session; `main` has branch protection requiring PR review and OPA-gate passage.

**Secure configuration.** Repository settings: branch protection on `main`; required status checks (OPA gate, build); secret scanning with push protection; Dependabot enabled. GitHub Actions settings: workflow permissions are read-only by default; mutation is granted per-job. Encrypted secrets used for AWS credentials are scoped per-environment.

**Secure operation.** No long-lived PATs are issued; the workflow's ephemeral `GITHUB_TOKEN` and the OIDC token for cosign are the only GitHub-issued tokens used.

**AWS access key rotation (90-day cadence).** While the OIDC migration in [POAM-001](../poam.md) remains deferred, the AWS access key used by the deployer IAM user is rotated every 90 days. The rotation procedure:

1. **Calendar trigger.** A recurring 90-day calendar event on the operator's calendar is the rotation trigger.
2. **Generate the new key.** In the AWS console (IAM → Users → `<deployer-user>` → Security credentials → Create access key) or via CLI: `aws iam create-access-key --user-name <deployer-user>`.
3. **Update the GitHub Actions secrets.** Repository Settings → Secrets and variables → Actions → update `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` with the new values.
4. **Verify a deploy.** Push a small no-op PR (or open and close one) to trigger the workflow. Confirm the compliance-check and deploy jobs both pass with the new key.
5. **Delete the old key.** In AWS console (IAM → Users → `<deployer-user>` → Security credentials → Delete previous access key) or via CLI: `aws iam delete-access-key --user-name <deployer-user> --access-key-id <old-key-id>`.
6. **Log the rotation.** Append a one-line entry to [`docs/security-review.md`](../security-review.md) under the rotation log: date, action, outcome.

**Emergency rotation.** If a key is suspected compromised at any time, rotation happens immediately, not on the 90-day cadence. Same procedure as above, plus the IR runbook ([`docs/incident-response.md`](../incident-response.md)) is followed.

**Decommissioning.** If the operator transfers stewardship, repository ownership is transferred per GitHub's transfer flow. Encrypted secrets are rotated before transfer; AWS access keys held in those secrets are deleted on the AWS side immediately after.

## 3. Silk Reeling Mirror app (operator-configured security settings)

Active in production (`create_silk_reeling = true` in the main deploy pipeline; live
since 2026-06-03). The app adds one operator-configured security setting and a fixed
secure-by-default resource baseline. Introduced under
[SCN-2026-001](../scn/SCN-2026-001-silk-reeling.md).

**Operator-set Basic Auth credential (the one configurable security setting).** Access
to the app is gated by a single HTTP Basic Auth credential the operator sets, stored in
Secrets Manager and CMK-encrypted. It is the access-control setting for the app
(POAM-021; single-factor, shared, no MFA, no lockout — risk-accepted operational item).

- **Set / rotate securely.** The secret *value* is injected out of band — never via Terraform (Terraform manages only the secret container, so plaintext never enters state). Set or rotate it with `aws secretsmanager put-secret-value` from the CI-held GitHub secret; use a long, random password. Rotate on the same 90-day cadence as the deployer key (and immediately on suspected compromise), logging the rotation in [`docs/security-review.md`](../security-review.md). Automatic rotation is not configured (POAM-019).
- **Recommended upgrade.** SAML/OIDC federation to an identity provider is the stronger control (POAM-021); not implemented (no IdP).

**Fixed secure-by-default baseline (not operator-tunable, recorded here for the SCG inventory).**

- **KMS CMK** with key rotation enabled; an explicit least-privilege key policy (account root-enable + Secrets-Manager-via-service condition only).
- **Secrets Manager** secrets (basic-auth credential, Anthropic API key) CMK-encrypted; read at runtime via least-privilege IAM (`GetSecretValue` on exactly the two ARNs, `kms:Decrypt` on the one key).
- **Lambda** runs with that least-privilege role; non-sensitive config only in environment variables (secret ARNs, never values); CORS locked to the site origin; constant-time credential compare.
- **API Gateway HTTP API** has no authorizer by design (app-layer Basic Auth is the gate, POAM-022); TLS-only; access logging deferred (POAM-024).
- **Egress** is a single documented path: TLS to the Anthropic API (SA-9/CA-3, POAM-020).
- **Logs** go to an explicit CloudWatch log group with managed retention.

## What this guide does NOT cover

Apart from the operator-set app credential in section 3, this system has no
customer-configurable surface. There are no agency-customer accounts, no per-tenant
settings, no provisioning APIs. The "customer" experience is the public read of the
static site plus the single-credential gated app — there is otherwise nothing to
configure. The standard SCG content about agency-customer security settings
(`SCG-CSO-RSC` items 2 and 3 — settings operated by top-level administrative accounts on
behalf of customers, and settings operated by privileged accounts) is not-applicable as
scoped.

## Enhanced capabilities (`SCG-ENH-*`)

- **Comparison capability (`SCG-ENH-CMP`):** the runtime KSI emitter is the comparison capability — it reads the live cloud configuration and compares against the deploy-time signal. The drift detection is the SCG comparison.
- **Export capability (`SCG-ENH-EXP`):** all configuration is in Terraform code, fully exportable.
- **Machine-readable guidance (`SCG-ENH-MRG`):** this guide is in markdown; the configuration the guide describes is in `infrastructure/main.tf` (machine-readable Terraform).
- **API capability (`SCG-ENH-API`):** AWS APIs and GitHub APIs are the upstream APIs that govern these accounts; both are fully API-driven.
- **Versioning (`SCG-ENH-VRH`):** maintained in git with full history.

## Public availability

Published at this path within the repository and rendered as part of the public site. Linked from [`docs/policies/README.md`](README.md) and from the OSCAL SSP for the AC and SC families.
