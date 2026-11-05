# AC — Access Control

Three access surfaces exist: operator control of the source-of-truth (GitHub repository, AWS root, AWS IAM roles, ACM, Route 53); public, unauthenticated read of the published static site via CloudFront; and authenticated use of the Silk Reeling app through one Amazon Cognito user pool. There are no customer tenants and no other user pools.

**Silk Reeling users** (`infrastructure/cognito.tf`). Accounts are created by the operator only; self-registration is disabled. Every user must use authenticator-app (TOTP) MFA, and passwords are at least 14 characters with all four character classes. Users sign in through the Cognito Hosted UI with the OAuth 2.0 authorization-code flow and PKCE, from a public client that holds no secret. Access and ID tokens expire after 60 minutes, refresh tokens after 30 days, and tokens can be revoked. The API Gateway route to the app's API carries a Cognito JWT authorizer, and the app validates the token again. The page that serves the app and receives the login callback has no authorizer; it holds no data. Account recovery goes to the verified email address, and login errors do not reveal whether an account exists.

Operator access uses GitHub branch protection on `main` plus AWS IAM with fixed-scope principals — no human trust policy on the Lambda role; the deployer role is the only credential with mutating cloud authority. MFA is enforced on both AWS root and the GitHub account. Top-level administrative accounts (AWS root, GitHub repository owner) are operated per the [Secure Configuration Guide](secure-configuration-guide.md).

**20x rule integration.** SCG-CSO-RSC and SCG-CSO-AUP are satisfied by the [Secure Configuration Guide](secure-configuration-guide.md). This family is the operator-side complement to KSI-IAM (Identity and Access Management).

Operator behavior (PL-4 Rules of Behavior) is documented in [`docs/rules-of-behavior.md`](../rules-of-behavior.md), which the operator acknowledges annually as part of the security review.

**Review cadence.** Annually with the [security review](../security-review.md).
