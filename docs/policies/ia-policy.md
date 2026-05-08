# IA — Identification and Authentication

Three authentication chains exist:

1. **Operator → GitHub:** username + password + MFA via Duo. All pushes to `main` require this chain plus passing branch protection checks.
2. **GitHub Actions → AWS:** long-lived AWS access keys stored as GitHub Actions encrypted secrets. Migration to GitHub OIDC role assumption is tracked as POAM-001 in [`poam.md`](../poam.md). Until that migration completes, the deployer principal is the largest standing-privilege surface in the system. As an active compensating control while POAM-001 remains open, the AWS access key is rotated every 90 days per the procedure in the [Secure Configuration Guide](secure-configuration-guide.md); rotation events are logged in [`security-review.md`](../security-review.md).
3. **Lambda → AWS:** AWS IAM execution role with no human-assumable trust policy. The role's only invoker is the EventBridge scheduled rule.

Sigstore keyless signing uses GitHub Actions OIDC for ephemeral identity proof; no signing keys are stored anywhere. Fulcio issues a short-lived X.509 certificate per workflow run, the signature is recorded in Rekor, and verification is anchored in the public transparency log.

Several IA enhancements (network access for non-privileged accounts in AWS infrastructure, identifier management for AWS-side identities) are inherited from AWS East/West Moderate FedRAMP authorization (Package ID: AGENCYAMAZONEW).

**20x rule integration.** Operator-side complement to KSI-IAM. Cryptographic primitives used in authentication are governed under SC and the Using Cryptographic Modules (UCM) rule.

**Review cadence.** Annually.
