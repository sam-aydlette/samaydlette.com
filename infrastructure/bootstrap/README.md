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

## CloudFront (cloudfront.tf)

This module also manages the **CloudFront distribution** that serves the site
(and proxies the Silk Reeling app) plus its Origin Access Control. CloudFront is
foundational, rarely-changing infrastructure, so — like the IAM trust layer — it
is managed here and applied deliberately, **not** re-applied on every website
deploy. The per-deploy `infrastructure/` stack keeps reading it through a
`data "aws_cloudfront_distribution"`; a routine deploy never plans or mutates it.
The config (origins, behaviors, the 403/404 → `/404.html` error responses, TLS,
OAC) was reconciled byte-for-byte against the live distribution before commit.

Two inputs are not committed (kept in a local, git-ignored `terraform.tfvars`):

- `silk_reeling_api_origin_domain` — the API Gateway origin host for the
  `/silk-reeling/*` behavior (`<api-id>.execute-api.<region>.amazonaws.com`).
- `owner_email` — the value of the distribution's `Owner` tag (kept out of the
  public repo).

On a fresh state, import the two resources before the first plan:

```
terraform import aws_cloudfront_origin_access_control.website <oac-id>
terraform import aws_cloudfront_distribution.website          <distribution-id>
terraform plan   # expect: No changes
```

`prevent_destroy` is set on the distribution so a plan can never replace or
destroy it; changes are made in place and reviewed.

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
