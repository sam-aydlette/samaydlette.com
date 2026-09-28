# SCN-2026-005 — Significant Change Notification & Security Impact Analysis
## CI identity split: deploy credentials only inside the approved deploy

| | |
| --- | --- |
| **SCN ID** | SCN-2026-005 |
| **System** | samaydlette.com (FedRAMP 20x KSI Certification + OSCAL Rev 5 Moderate SSP) |
| **SCN type** | **Adaptive** (`SCN-ADP`) |
| **Status** | Steps 1 and 2 implemented 2026-09-28 (#374 applied; #375 merged, its plan-role run verified). Step 3 (this record's PR) pending merge and operator apply; verification plan below. |
| **Date initiated** | 2026-09-28 |
| **Approver** | Sam Aydlette — System Owner / Authorizing Operator |
| **Authoritative source** | CR26 corpus (`final_consolidated_rules_2026/2026-markdown`) |

## 1. Categorization (SCN-CSO-EVA)

Changes the privileged-identity model of the CI/CD path. It is the same kind of change as SCN-2026-002's authentication replacement: an access-model change is not routine-recurring maintenance.

- **One new IAM identity.** `github-actions-plan-oidc` is a read-only plan role.
- **The deploy role's trust narrows.**

It is not Transformative:
- no new external service, data flow or component beyond one IAM role;
- no federal data;
- no customer-responsibility or class change.

## 2. Required information (SCN-CSO-INF)

- **Short description:** the `compliance-check` job (`terraform plan` plus the OPA gate), which runs on every pull request and on pushes to `main`, moves from the deploy role to a new read-only plan role. The deploy role's trust then narrows to the reviewer-gated `prod` GitHub Environment only.
- **Reason:** the deploy role's trust included `repo:…:pull_request` and `repo:…:ref:refs/heads/main`, because `compliance-check` planned with it. So every PR run received the full deploy permission set without passing the `prod` environment approval that gates the deploy job. That set includes `iam:PutRolePolicy` and `iam:PassRole` on a Lambda execution role plus Lambda code updates, which together allow effectively unbounded reach in the account.

  Reachability was narrow: fork PRs cannot mint GitHub OIDC tokens on a public repository, Dependabot PRs run like forks, and the repository has one collaborator. But the approval gate only means something if nothing reaches deploy credentials around it.
- **Customer impact:** none. There are no agency customers.
- **Changes, in three steps:**
  1. **#374** adds `github-actions-plan-oidc` (`infrastructure/bootstrap/plan-role.tf`):
     - **Trust:** `pull_request` and `ref:refs/heads/main` only.
     - **Base access:** AWS managed `ReadOnlyAccess`.
     - **Explicit denies** on data-plane reads (object contents outside the state file, DynamoDB rows outside the lock, log events, secret values, SSM parameters, `kms:Decrypt`, SQS receive).
     - **State access:** read on the state object, plus item writes on the lock table, which is its only write.
  2. **#375** switches `compliance-check` to `AWS_PLAN_ROLE_ARN`.
  3. **This change** narrows `aws_iam_role.deploy`'s trust to `repo:sam-aydlette/samaydlette.com:environment:prod`.
- **Related:** the `evidence-nightly` GitHub Environment gained a `main`-only deployment branch policy on 2026-09-28, so a workflow on another branch cannot name it to obtain the nightly role.

## 3. Security impact analysis

- **Net reduction in exposure.** After step 3, deploy credentials exist only inside a deploy job that a human approved. Every other CI context holds, at most, read-only access with data-plane reads denied.
- **The new role cannot write** anything except the state-lock item, cannot read object or table contents (other than the state and the lock), and cannot read secrets or decrypt.
- **Residual exposure: state contents.** The plan role reads the Terraform state object, which contains resource attributes, some sensitive. The deploy role could already do so on the same PRs, so this is not new exposure. It is now the *only* sensitive read available to PR context.
- **Failure mode:** if the plan role lacked a permission `terraform plan` needs, `compliance-check` would fail closed; it cannot fall back to the deploy role, which no longer trusts PR context. The verification below exercises this.
- **Cost:** none (IAM).

### Verification plan (post-implementation)

1. **Step 2 (done 2026-09-28).** `compliance-check` on #375 (run 36418382358, re-run after the role existed) assumed `github-actions-plan-oidc`. `terraform init`, `validate` and `plan` succeeded, with no access-denied errors.
2. **After the step-3 apply:**
   - The live trust policy of `github-actions-deploy-oidc` reads back with the single `environment:prod` subject.
   - The next approved deploy on `main` assumes the deploy role and completes, including the reconciliation gate.
   - A pull request's `compliance-check` still assumes the plan role and passes.
   - A push to `main` runs `compliance-check` under the plan role (the `ref:refs/heads/main` subject).
