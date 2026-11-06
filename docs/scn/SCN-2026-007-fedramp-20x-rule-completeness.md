# SCN-2026-007 — Significant Change Notification & Security Impact Analysis
## FedRAMP 20x rule completeness: every applicable rule Implemented or Not Applicable

<!-- AI-drafted for the operator's review. -->

| | |
| --- | --- |
| **SCN ID** | SCN-2026-007 |
| **System** | samaydlette.com (FedRAMP 20x Class C proof of concept; not FedRAMP-certified) |
| **SCN type** | **Adaptive** (`SCN-ADP`) |
| **Status** | Implemented on the first deploy that publishes this record: the register row says `on-deploy`, and the deploy's SCN build records the finish date (`scripts/_scn.py` `resolve_on_deploy`). |
| **Date initiated** | 2026-11-05 |
| **Approver** | Sam Aydlette — System Owner / Authorizing Operator |

## 1. Categorization (SCN-CSO-EVA)

The change adds privileged identities, unattended publishing paths, broader read-only grants, a new trusted signer and a new store of access logs. That is more than routine-recurring maintenance.

- **Two new IAM roles**, each assumable only from a GitHub Environment restricted to `main`: package maintenance and incident-report publishing.
- **Runtime emitter:** additional read-only grants (IAM, Lambda, API Gateway, Cognito, KMS) and one PutObject grant on `deploy-staging/*/ksi-signal-runtime.json`.
- **CloudFront access logging** (`infrastructure/bootstrap/trust-access-logs.tf`), into the existing encrypted log bucket with a 90-day expiry. CloudFront cannot log by path, so every request is logged, with a field allowlist that drops the client IP, forwarded-for, port, user agent, referrer, cookies and query string at the edge. The deploy role reads the records and counts only `/.well-known/` and `/trust/`; only aggregate counts are published.
- **Account-wide read-only reads on the deploy role** (`infrastructure/bootstrap/deploy-config-reads.tf`): IAM account summary, password policy, users, virtual MFA devices and the account-level S3 Block Public Access setting, plus user and group policy reads, so the deploy can compare the privileged accounts' settings with the Secure Configuration Guide. Metadata only; no secret value is readable.
- **Read-only CORS on `/.well-known/`** (`infrastructure/bootstrap/cloudfront.tf`): `Access-Control-Allow-Origin: *` with GET, HEAD and OPTIONS and no credentials, so a program on any origin can read the certification data.
- **A new trusted signing identity:** the simulated assessor workflow (`.github/workflows/simulated-assessor.yml`) signs its assessment results keylessly under its own identity, and the SDR and CPO builders accept assessment results only from that identity.
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

- **New risks:** the two unattended roles can write published artifacts without a reviewer. Each is limited to its own key prefixes and to runs on `main`. The access logs hold no client IP address or other client identifier (they are dropped at the edge); the raw records expire after 90 days and are read by the deploy role to build the monthly counts (the operator's administrative access also reaches the bucket). The deploy role can read IAM and S3 account-setting metadata account-wide, but no secret value. Any origin can read `/.well-known/` without credentials, which publishes nothing that is not already public. The builders accept assessment results signed by one more identity, the simulated assessor's, and nothing else from it. The DAST user is a real account in the app's user pool, with TOTP MFA.
- **Reductions:** IAM user names, GitHub run IDs and the personal email address leave published output, each with a gate. The deploy fails when any rule record is open or any KSI is short of two automated methods without an in-force accepted decision record for the shortfall.
