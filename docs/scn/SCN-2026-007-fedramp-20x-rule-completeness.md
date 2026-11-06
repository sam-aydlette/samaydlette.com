# SCN-2026-007 — Significant Change Notification & Security Impact Analysis
## FedRAMP 20x rule completeness: every applicable rule Implemented or Not Applicable

<!-- AI-drafted for the operator's review. -->

| | |
| --- | --- |
| **SCN ID** | SCN-2026-007 |
| **System** | samaydlette.com (FedRAMP 20x Class C proof of concept; not FedRAMP-certified) |
| **SCN type** | **Adaptive** (`SCN-ADP`) |
| **Status** | Planned. Merges to `main` with the rule-records change; implemented when its deploy succeeds. |
| **Date initiated** | 2026-11-05 |
| **Approver** | Sam Aydlette — System Owner / Authorizing Operator |

## 1. Categorization (SCN-CSO-EVA)

The change adds privileged identities and unattended publishing paths, and a new store of access logs. That is more than routine-recurring maintenance.

- **Two new IAM roles**, each assumable only from a GitHub Environment restricted to `main`: package maintenance and incident-report publishing.
- **Runtime emitter:** additional read-only grants (IAM, Lambda, API Gateway, Cognito, KMS) and one PutObject grant on `deploy-staging/*/ksi-signal-runtime.json`.
- **CloudFront access logging** for `/.well-known/` and `/trust/`, into the existing encrypted log bucket with a 90-day expiry. Only aggregate counts are published.
- **Scheduled publishing workflows** on GitHub Actions (package maintenance, incident publisher, availability probe, SCN deadlines).
- **A DAST scanner user** in the existing Cognito user pool.

It is not Transformative:
- no new external service: GitHub and AWS are already in the boundary;
- no new data flow carrying federal data; there is no federal data;
- no customer-responsibility or certification-class change.

## 2. Required information (SCN-CSO-INF)

- **Short description:** the rule register, its completeness gate and the work that brings every applicable FedRAMP 20x Class C rule to Implemented or Not Applicable. Outside parties (assessor, FedRAMP, agencies, incident recipients, mail, SAM.gov) are simulated and flagged; nothing is sent to anyone.
- **Reason for change:** show FedRAMP 20x adherence as evidence built from code, with the deploy refusing to publish any gap.
- **Customer impact:** none. There are no agency customers.
- **Plan and timeline:** bootstrap applies by the operator, then repository variables, environments, secrets and labels, then the merge to `main` and one gated deploy, then post-deploy verification (`verify-published.sh`, storycheck on the live site).

## 3. Security impact

- **New risks:** the two unattended roles can write published artifacts without a reviewer. Each is limited to its own key prefixes and to runs on `main`. The access logs hold IP addresses for 90 days, readable only by the operator role. The DAST user is a real account in the app's user pool, with TOTP MFA.
- **Reductions:** IAM user names, GitHub run IDs and the personal email address leave published output, each with a gate. The deploy fails when any rule record is open or any KSI is short of two automated methods (except KSI-CED-RAT, accepted in DEC-191).
