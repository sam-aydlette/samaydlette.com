# AC — Access Control

Two access surfaces exist: operator control of the source-of-truth (GitHub repository, AWS root, AWS IAM roles, ACM, Route 53) and public read of the published static site via CloudFront. There are no customer accounts, no end-user authentication, and no shared user pools.

Operator access uses GitHub branch protection on `main` plus AWS IAM with fixed-scope principals — no human trust policy on the Lambda role; the deployer role is the only credential with mutating cloud authority. MFA is enforced on both AWS root and the GitHub account. Top-level administrative accounts (AWS root, GitHub repository owner) are operated per the [Secure Configuration Guide](secure-configuration-guide.md).

**20x rule integration.** SCG-CSO-RSC and SCG-CSO-AUP are satisfied by the [Secure Configuration Guide](secure-configuration-guide.md). This family is the operator-side complement to KSI-IAM (Identity and Access Management).

Operator behavior (PL-4 Rules of Behavior) is documented in [`docs/rules-of-behavior.md`](../rules-of-behavior.md), which the operator acknowledges annually as part of the security review.

**Review cadence.** Annually with the [security review](../security-review.md).
