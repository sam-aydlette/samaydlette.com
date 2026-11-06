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
- **Changes to the compliance engine** (pull request #518). Each changes how the security posture is verified, so each is adaptive:
  - **Assessor binding:** each simulated assessment set names the commit and published KSI signal it covered. The SDR and CPO builders refuse a set covering any other. The deploy reads the live signal itself before the SDR is built, and the SDR states what was covered (`providerExtensions.assessmentCoverage`).
  - **Post-deploy assessment:** after every deploy, the same simulated assessor assesses the just-published state, which must carry the deployed commit. Its set must cover this commit and the signal this deploy published. A failure fails the run and raises the deployment-failure issue.
  - **History fetches:** the access summary, the certification-report index and the package submission log are fetched fail-closed. Only a 404 starts a history; any other failure stops the deploy.
  - **Certification reports:** the simulated FedRAMP issues a stand-in certification report only in response to a simulated package submission: the first, after an adaptive or transformative SCN, and once a year. The report is logged with the date it was received. A report first published more than 14 days after receipt fails the deploy. Every report says it is not issued by FedRAMP and that the system is not certified.
  - **Inbox change notices (AFC-CSO-NOC):** each FedRAMP Security Inbox contact change is filed with the simulated FedRAMP as a log entry; nothing is sent. The change takes effect when a deploy first publishes it: that deploy files the notice and is recorded in the submission log, and the deploy fails when a notice was filed more than one business day after it. A change merged but not yet deployed cannot go stale.
  - **Exploitation assessment (DEC-181):** rests on automated sources only; a screen fails any in-force decision or rule record that commits the operator to a manual review.
  - **Package history:** the SDR, CPO and OCR previous copies are fetched fail-closed, like the other histories.
  - **Failure alerts:** the deployment-failure notification also covers the unit tests (which hold the rule-completeness gate) and the security scan on `main`.
  - **Human-readable views:** every publishing workflow (deploy, evidence nightly, package maintainer, incident publisher) puts a complete `.view.md` beside every JSON or CSV it puts, including incident reports, certification reports, issued Ongoing Certification Reports, snapshots and Quarterly Reviews. The trust manifest lists views from the publisher table (`scripts/_signers.py`) and fails if a JSON was built without one.
  - **Email addresses:** the publication redaction gate fails any published file carrying an email address outside the site's domain.
  - **No-engagement statement (DEC-194):** every simulated output (package submission log, certification-report index, inbox simulation, incident log, delivery log and reports, SCN index) carries the statement.
  - **Corroboration:** the operator-run corroboration checks each signature against the workflows that write the file, not against its refresh cadence.
  - **Not-certified status:** the CPO, the SDR and the trust center data state `certification.status` "not certified (proof of concept)", from one source. A package without it is never submitted.

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
- **Reductions:** IAM user names, GitHub run IDs and the personal email address leave published output, each with a gate; any email address outside the site's domain fails the publication gate. An assessment of any commit or signal other than the one stated is refused. A failed post-deploy assessment fails the run; what was published stays until the next deploy. A failed history fetch stops the deploy instead of restarting the history. The CPO and SDR state in their JSON that the system is not certified. The deploy fails when any rule record is open or any KSI is short of two automated methods without an in-force accepted decision record for the shortfall.
