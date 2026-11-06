# IA — Identification and Authentication

Three authentication chains exist:

1. **Operator → GitHub:** username + password + two-factor authentication (virtual TOTP from an authenticator app), which GitHub enforces on the owner account (DEC-151). All pushes to `main` require this chain plus passing branch protection checks.
2. **GitHub Actions → AWS:** GitHub OIDC role assumption. Each workflow assumes its own role (deploy, plan, nightly, package maintenance, incident reports) with short-lived credentials; no AWS access key exists for CI. The deployer access key this replaced was deleted (DEC-001, remediated, in [`data/decisions.json`](../../data/decisions.json)).
3. **Lambda → AWS:** AWS IAM execution role with no human-assumable trust policy. The role's only invoker is the EventBridge scheduled rule.

Sigstore keyless signing uses GitHub Actions OIDC for ephemeral identity proof; no signing keys are stored anywhere. Fulcio issues a short-lived X.509 certificate per workflow run, the signature is recorded in Rekor, and verification is anchored in the public transparency log.

Several IA enhancements (network access for non-privileged accounts in AWS infrastructure, identifier management for AWS-side identities) are inherited from AWS East/West Moderate FedRAMP authorization (Package ID: AGENCYAMAZONEW).

**20x rule integration.** Operator-side complement to KSI-IAM. Cryptographic primitives used in authentication are governed under SC and the Using Cryptographic Modules (UCM) rule.

**Review cadence.** Annually.
