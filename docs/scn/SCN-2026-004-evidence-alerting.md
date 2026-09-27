# SCN-2026-004 — Significant Change Notification & Security Impact Analysis
## Evidence SLA watchdog and operator alerting (backfilled record)

| | |
| --- | --- |
| **SCN ID** | SCN-2026-004 |
| **System** | samaydlette.com (FedRAMP 20x KSI Certification + OSCAL Rev 5 Moderate SSP) |
| **SCN type** | **Adaptive** (`SCN-ADP`) |
| **Status** | Implemented 2026-09-25; post-implementation verification complete 2026-09-25 (end-to-end alarm delivery). Inventory, SSP and boundary documentation brought into line with the change 2026-09-27. |
| **Date initiated** | 2026-09-25 |
| **Approver** | Sam Aydlette — System Owner / Authorizing Operator |
| **Authoritative source** | CR26 corpus (`final_consolidated_rules_2026/2026-markdown`) |

**Why this record is backfilled.** The change shipped in PRs #357, #359 and #361 on 2026-09-25. None carried an `SCN-Type:` line, so each defaulted to routine-recurring. That under-categorized a change that adds components and an outbound data flow. This record sets the categorization to Adaptive and supplies the security impact analysis.

## 1. Categorization (SCN-CSO-EVA)

Adds net-new service components inside the boundary: an hourly watchdog Lambda, three CloudWatch alarms, and a CMK-encrypted SNS topic. It also adds **one new outbound flow**: alarm notifications by email to the operator's personal email, which is outside the boundary per Rule of Thumb #3 (flow I on the authorization-boundary page). A new egress flow is not routine-recurring maintenance, and it is why this change sits above the lower edge of Adaptive, where SCN-2026-003 sat.

It is not Transformative. The `SCN-TRF-TPR` examples involve a critical third party handling a significant portion of information, or a change touching federal customer data. The new flow carries alarm metadata only, to the operator's own email, and the system holds no federal data. There is no authentication change, no customer-responsibility change, and no class change. The same reasoning applies as in SCN-2026-001, which records what would flip a change like this to Transformative.

## 2. Required information (SCN-CSO-INF)

- **Short description:** an evidence SLA watchdog pages the operator by email when published compliance evidence goes stale or the evidence nightly fails. The nightly moves to twice a day and writes a status beacon. Its live drift check runs independently of its vulnerability gate.
- **Reason:** from 2026-09-09 to 2026-09-24 the evidence nightly failed every night on two undispositioned advisories. The published VDR went twelve days stale, beyond the 24-hour reporting policy, and the only signal was a GitHub issue. For those sixteen nights the vulnerability gate also short-circuited the live reconciliation, so drift went unchecked and nothing said so.
- **Customer impact:** none. There are no agency customers, and the change is detective and internal.
- **New components:**
  - `aws_lambda_function.evidence_watchdog`, with its IAM role and policy, log group and hourly EventBridge rule;
  - `aws_cloudwatch_metric_alarm.evidence` (three alarms: VDR age, runtime-signal age, nightly result);
  - `aws_sns_topic.evidence_alerts` with a topic policy scoped by `aws:SourceArn` / `aws:SourceAccount`;
  - an at-rest KMS key-policy grant to `cloudwatch.amazonaws.com`, scoped the same way;
  - in the bootstrap layer: the deploy role's `evidence-watchdog-management` grant and the operators group's `evidence-alerts-operator` grant, both name-scoped.
- **No new in-boundary external service.** The notification destination is the operator's personal email, which stays out of scope under Rule of Thumb #3: it receives alarm metadata only, while the alerting controls themselves (the alarms and the encrypted topic) are inside the boundary. The email subscription is created out of band, and no address is recorded in the repository, Terraform state or the published inventory.

## 3. Security impact analysis

- **Additive and detective.** The watchdog reads three named objects from the site bucket over the AWS API. It has no internet egress, so the "Lambda egress is to AWS APIs only" statements and the POAM-010 rationale stay true. It writes metrics to one namespace. Its role cannot write evidence, change infrastructure, or publish to the topic.
- **The new outbound flow** carries alarm metadata: alarm name, state, reason, threshold, and account and alarm identifiers. It carries no evidence content, vulnerability findings or credentials. SNS email is not end-to-end encrypted. That is acceptable for this content and is recorded, not hidden.
- **Integrity of the page.** Only this account's evidence alarms can publish to the topic (topic policy plus key-policy conditions). The operator can subscribe, test and silence, but cannot publish (`evidence-alerts-operator` omits `sns:Publish`).
- **Failure modes.**
  - A watchdog that stops publishing pages the operator, because missing data is a breach.
  - A disabled GitHub cron pages through the beacon's age.
  - A mis-scoped KMS condition would fail delivery silently. The post-implementation test was designed to catch exactly that.
- **The unattended path is unchanged in scope.** The nightly's beacon is written within its existing `.well-known/vdr-*` permission. No role on the unattended path gained a permission.
- **Cost:** about $0.80/month (three alarms, three custom metrics).

### Verification plan (post-implementation)

- The deploy creates the watchdog, topic and alarms, and the reconciliation gate passes.
- A manual invocation publishes real metrics.
- A nightly run writes the beacon.
- The operator subscription is confirmed.
- A forced `set-alarm-state` produces delivered email.
- All alarms settle to OK.

### Verification result — COMPLETE (2026-09-25)

- The deploy for #359 succeeded, including the reconciliation gate against the new resources.
- A manual invocation published VDR age 0.06h, runtime-signal age 0.03h and `NightlyFailed` 1 (no beacon yet).
- A dispatched nightly passed and wrote a beacon (`result: success`, all gates `success`), after which the watchdog read `NightlyFailed` 0.
- The operator subscription was confirmed.
- `set-alarm-state` OK then ALARM on `nightly-failed`: SNS reported 2 notifications delivered and 0 failed. The KMS grant works end to end.
- All three alarms settled to OK.

### Follow-up (2026-09-27)

- The topic, the alarms and the compliance DLQ were not in the canonical inventory, because the builder had no mapping for their Terraform types. They are now inventoried, and each derived classification equals its live tags (reconciliation invariant i).
- The alarm email destination is recorded as out of boundary (Rule of Thumb #3), with no address published.
- The authorization-boundary page gains flow I.
- The SSP's CA-7 and IR-6 narratives describe the alerting.
