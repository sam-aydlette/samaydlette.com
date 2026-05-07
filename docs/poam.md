# Plan of Action and Milestones (POA&M)

This document records known security gaps that are tracked for remediation but not addressed in the current implementation. The format follows the conceptual structure of a NIST/FedRAMP POA&M without claiming alignment with any specific authorization process.

POA&M items are different from "consciously skipped" items recorded in the README's *Conscious Trade-offs for Budget Reality* table. Skipped items are decisions made not to remediate (risk-accepted, with rationale). POA&M items are decisions that remediation is appropriate but not yet completed.

Status legend: **Open** (not started) · **In progress** · **Closed** (remediation complete) · **Risk-accepted** (closed without remediation, with documented rationale)

---

## POAM-001: Long-lived AWS access keys for the deployer

**Status:** Open
**Opened:** 2026-05-06
**Target close:** 2026-08-31
**Severity:** Medium
**Source:** CodeGuard `codeguard-0-iac-security` ("NEVER use service API Keys and client secrets and instead use workload identity with role-based access control to eliminate the need for long-lived credentials").

### Gap

The CI deployer authenticates to AWS using a long-lived IAM user's access key + secret access key, stored in GitHub Actions encrypted secrets. The `aws-actions/configure-aws-credentials` step reads them via `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`. If either secret leaks, the credentials retain validity until manually rotated.

### Compensating controls in place

- The credentials live only in GitHub Actions encrypted secrets (not in the repo).
- The IAM user the credentials belong to is scoped to the actions Terraform needs to perform; it is not a console-login user with broad privileges.
- GitHub secret scanning with push protection is enabled, which would block accidental commits of the values.
- The OPA gate in CI does not have access to the secrets directly — they are injected only into the AWS step.
- The Sigstore signing chain already proves the OIDC pattern works in this workflow (cosign signs using the `id-token: write` permission and the GitHub OIDC provider).

### Remediation plan

The migration is mechanically straightforward; it is deferred only because of the Terraform/IAM trust-policy work.

1. **Create a deployer IAM role in the AWS account** (`github-actions-deployer`) with:
   - A trust policy whose `Principal` is `arn:aws:iam::<account>:oidc-provider/token.actions.githubusercontent.com`.
   - A `Condition` block restricting `token.actions.githubusercontent.com:sub` to `repo:sam-aydlette/samaydlette.com:*` (or a tighter pattern bound to the workflow).
   - Permissions equivalent to what the current IAM user has (Terraform plan/apply on the resources this repo manages, S3 read/write on the website bucket and `.well-known/`, CloudFront invalidation, Lambda update, IAM role/policy management on the Lambda role only).
2. **Provision the GitHub OIDC provider in AWS** if not already present:
   ```hcl
   resource "aws_iam_openid_connect_provider" "github" {
     url             = "https://token.actions.githubusercontent.com"
     client_id_list  = ["sts.amazonaws.com"]
     thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
   }
   ```
3. **Update the workflow** to drop `aws-access-key-id` / `aws-secret-access-key` and add `role-to-assume` + `aws-region`:
   ```yaml
   - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502 # v4.0.2
     with:
       role-to-assume: arn:aws:iam::<account>:role/github-actions-deployer
       aws-region: ${{ env.AWS_REGION }}
   ```
   The job already declares `id-token: write` (added for Sigstore), so no additional permission is needed.
4. **Verify** by running the workflow against a non-production resource, confirming AWS calls succeed under the assumed role.
5. **Remove** `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` from GitHub Actions secrets.
6. **Delete** the underlying IAM user and its access keys in AWS.

### Risk if not remediated

A leaked access key (via a future supply-chain compromise of a GitHub Action, an accidental log of the secret, or a GitHub account compromise) would give an attacker persistent access until detection + manual rotation. With OIDC role assumption, the equivalent compromise produces a session token valid for ~1 hour with no persistence.

---

## POAM-002: Runtime KSI signal is not cryptographically signed

**Status:** Open
**Opened:** 2026-05-06
**Target close:** When a real consumer asks to verify the runtime signal end-to-end. Until then this is a low-priority POA&M; the implicit trust model is acceptable for a PoC.
**Severity:** Low (PoC) / Medium (in any portfolio context with external consumers)
**Source:** Internal review during initial implementation; documented in [`docs/architecture-decisions.md`](architecture-decisions.md) and [`docs/ksi-signal.md`](ksi-signal.md).

### Gap

The runtime KSI signal at `/.well-known/ksi-signal-runtime.json` is published by the Lambda but is not cryptographically signed. Consumers trust it implicitly: the chain is "AWS hasn't lied about what's at the well-known URL." That is the same trust model every static-site CDN relies on, but it does not reduce to the public Sigstore transparency log the deploy-time signal does.

### Compensating controls in place

- The Lambda's IAM role can write only to one specific S3 key (`.well-known/ksi-signal-runtime.json`), so a compromised Lambda cannot overwrite arbitrary site content.
- The runtime signal carries `provenance.builder.id` identifying the Lambda function and execution context.
- Drift between the deploy-time signal (signed) and runtime signal is detectable from outside: the deploy-time signal's `components[]` and `validations[]` should reconcile with the runtime signal's, and any mismatch is high-confidence signal of either a real drift or a tampered runtime signal.

### Remediation plan

Two viable approaches:

**Option A (recommended for a small system): AWS KMS asymmetric signing.**

1. Provision an asymmetric KMS key in Terraform with `key_usage = "SIGN_VERIFY"` and an ECC NIST P-256 spec.
2. Grant the Lambda role `kms:Sign` and `kms:GetPublicKey` on that key.
3. In the Lambda, hash the runtime signal's bytes (excluding the signature field), call `KMS Sign` with `SigningAlgorithm = ECDSA_SHA_256`, and embed the resulting signature in the signal's `provenance.attestation` block.
4. Publish the public key at `/.well-known/runtime-signing-pubkey.pem` as part of the deploy.
5. Document verification: any consumer fetches the public key and verifies the signature using `openssl dgst -sha256 -verify`.

Cost: ~$1/month for the KMS key plus per-request charges. Effort: ~half a day.

**Option B (more elaborate): federate an OIDC-style identity into the Lambda.**

Use AWS IAM Roles Anywhere or an external workload-identity broker to obtain a Sigstore-compatible token. Same chain of trust as the deploy-time signal, but multiple new pieces of infrastructure.

### Risk if not remediated

A consumer pulling the runtime signal cannot independently verify it has not been tampered with. For an entirely public site with no agency relying on this evidence, the risk is mostly reputational. In any portfolio context where multiple agencies consume signals across CSPs, runtime signal forgery becomes a credible attack and signing closes the gap.

---

## Items deliberately not on this POA&M

These are tracked in the README's *Conscious Trade-offs for Budget Reality* table, not here, because they are risk-accepted decisions rather than gaps awaiting remediation:

- **CloudFront WAF** — accepted on cost grounds. Threat model for a static personal site does not justify ~$120/year.
- **S3 access logging** — accepted; CloudTrail covers the audit need.
- **Multi-region active-passive** — accepted; the declared 21-day RTO accommodates regional failure.
- **Lambda VPC isolation** — accepted; the Lambda processes no sensitive data and has no internet egress.

These are revisited annually in [`docs/security-review.md`](security-review.md). If the threat profile or scope changes, any of them can be promoted to a POA&M.
