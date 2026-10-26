# SCN-2026-006 — Significant Change Notification & Security Impact Analysis
## Remove the Anthropic API interconnection from the Silk Reeling app

| | |
| --- | --- |
| **SCN ID** | SCN-2026-006 |
| **System** | samaydlette.com (FedRAMP 20x KSI Certification + OSCAL Rev 5 Moderate SSP) |
| **SCN type** | **Adaptive** (`SCN-ADP`) |
| **Status** | **Planned.** Becomes implemented once the deploy applies and the post-implementation verification below passes. |
| **Date initiated** | 2026-10-26 |
| **Approver** | Sam Aydlette — System Owner / Authorizing Operator |
| **Authoritative source** | CR26 corpus (`final_consolidated_rules_2026/2026-markdown`) |

## 1. Categorization (SCN-CSO-EVA)

Removes an external interconnection, a boundary-crossing data flow and a secret.
It changes the authorization boundary and the SSP's interconnections, which is
more than routine-recurring maintenance, so it is Adaptive. It reduces risk.

It is not Transformative:
- no new external service, data flow or component;
- no federal data;
- no customer-responsibility or class change.

## 2. Required information (SCN-CSO-INF)

- **Short description:** the Silk Reeling app Lambda stops calling the Anthropic
  API. It writes feedback text from the scores itself. The Anthropic API-key
  secret, the app role's read grant on it, the runtime emitter's metadata grant
  on it, and the key's environment variable are removed. The app's LLM-written
  feedback becomes a customer-configurable option (`SRM_ENABLE_LLM_FEEDBACK`,
  off by default since the app's ADR-0009) that is disabled in this deployment.
- **Reason:** the interconnection was a risk-accepted SA-9/CA-3 item (POAM-020)
  to a service without a FedRAMP authorization, and its key had expired. The app
  now produces useful feedback without it, so the interconnection no longer
  earns its risk.
- **Customer impact:** none. There are no agency customers. App users get
  feedback written from their scores instead of by an LLM.
- **Changes:**
  - `infrastructure/silk-reeling.tf`, `main.tf`, `outputs.tf`: delete
    `aws_secretsmanager_secret.silk_anthropic` (Secrets Manager's 30-day recovery
    window applies), its `GetSecretValue` and `DescribeSecret` grants, the
    `SRM_ANTHROPIC_SECRET_ARN` variable, and the secret-ARN output.
  - `deploy-with-opa.yml`: drop the secret's import and the step that seeded
    its value from a GitHub secret.
  - Generators: the inventory drops `ext::anthropic-api`; the SSP stops emitting
    the interconnection component and the boundary-crossing data flow.
  - Boundary classification: the AI-provider group goes, and flow H ends at the
    app Lambda.
  - `.checkov.yaml`: the `CKV2_AWS_57` skip goes, since no secret remains.
- **Turning LLM feedback back on** in this deployment would be a new Adaptive
  change: its own SCN, an SSP interconnection and data flow, an inventoried
  external component, a secret with a least-privilege read grant, and an
  SA-9/CA-3 decision.

## 3. Security impact analysis

- **Net reduction in exposure.** No data leaves the boundary on the app path,
  no third-party credential is stored, and two IAM grants on a secret are gone.
- **Data flow:** browser → API Gateway → app Lambda only. Pose landmarks are
  processed transiently and not persisted, as before.
- **Monitoring:** the runtime emitter's SC-12 rotation check iterates the
  inventory's Secrets Manager components. With none left, it emits no rotation
  validation; that is expected, not a gap.
- **Failure mode:** if the app still expected a key, it degrades to numeric
  feedback and never fails the request (the app's `generate_feedback` never
  raises).
- **Cost:** a small reduction (one secret).

### Verification plan (post-implementation)

1. `terraform plan` shows only: the secret destroyed, the two IAM policies
   updated, the app Lambda's environment updated, the output removed.
2. After the gated deploy, read back from AWS: the secret is scheduled for
   deletion; the app Lambda's environment has no secret ARN; neither role
   policy references the secret.
3. The published SSP and KSI signal carry no Anthropic component or
   interconnection, and the signal is fresh (`make verify-published`).
4. Then close POAM-020 and retire POAM-019 in `data/poam-items.json` and
   `docs/poam.md`, and mark this SCN implemented.
