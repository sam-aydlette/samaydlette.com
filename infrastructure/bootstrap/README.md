# Bootstrap: GitHub OIDC deploy role

This module is **applied by an operator, not by CI** — it creates the IAM role the
CI pipeline assumes, so it cannot be created by the pipeline it enables
(chicken-and-egg). It has its own local state, separate from the main
`infrastructure/` stack.

What it creates (assessment POAM-001, Task 2):

- An IAM OIDC identity provider for `token.actions.githubusercontent.com`.
- An IAM role (`github-actions-deploy-oidc`) the workflow assumes via
  `aws-actions/configure-aws-credentials` with `role-to-assume` — **no
  long-lived access key**. Its trust policy restricts `sub` to **this repo's
  `main` pushes and pull requests only** (not `:*`).
- The same permission scope the legacy `github-actions-deploy` IAM user had
  (its managed policies, reattached to the role) plus the reconciliation-gate
  read permissions, so the deploy keeps working unchanged.

After a green OIDC deploy proves the role works, the legacy IAM user and its
access key are deleted and the `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
repo secrets are removed (the POAM-001 closure). Until then both paths coexist.

## Apply

```
cd infrastructure/bootstrap
terraform init
terraform plan
terraform apply
terraform output github_actions_role_arn   # set as the workflow's role-to-assume
```

Consolidating the legacy `github_*` managed policies into one least-privilege
deploy policy is a tracked follow-up; this module preserves the existing scope
verbatim to avoid a deploy regression at cutover.
