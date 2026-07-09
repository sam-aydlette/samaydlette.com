# SCN-2026-003 — Significant Change Notification & Security Impact Analysis
## CloudTrail management-events trail (account-level API audit)

| | |
| --- | --- |
| **SCN ID** | SCN-2026-003 |
| **System** | samaydlette.com (FedRAMP 20x KSI Certification + OSCAL Rev 5 Moderate SSP) |
| **SCN type** | **Adaptive** (`SCN-ADP`) |
| **Status** | Proposed — implemented when the `infra/cloudtrail-management-trail` change merges and the bootstrap grant is applied |
| **Date initiated** | 2026-07-08 |
| **Approver** | Sam Aydlette — System Owner / Authorizing Operator |
| **Authoritative source** | CR26 corpus (`final_consolidated_rules_2026/2026-markdown`) |

## 1. Categorization (SCN-CSO-EVA)

Adds a net-new service component (CloudTrail trail + delivery bucket) inside the
boundary. No new ingress or egress, no authentication change, no customer
impact, no class change — so not Transformative. A net-new component is not
routine-recurring maintenance; conservatively categorized **Adaptive** (the
lower edge of Adaptive: purely internal detective tooling).

## 2. Required information (SCN-CSO-INF)

- **Short description:** multi-region CloudTrail management-events trail with
  log-file validation, delivering to a dedicated locked-down S3 bucket with
  AU-11 retention tiering (12 months active, Deep Archive to 30 months).
- **Reason:** the account had no durable control-plane audit record (90-day
  Event History only) while SSP AU-family statements assumed CloudTrail
  coverage; this closes that gap (AU-2/AU-11/AU-12, KSI-MLA-OSM).
- **Customer impact:** none (internal detective control).
- **New components:** `aws_cloudtrail.management`, `aws_s3_bucket.cloudtrail`
  (+ policy/PAB/ownership/SSE/versioning/lifecycle), deploy-role
  `cloudtrail-management` grant in the bootstrap layer (ARN-scoped, no
  delete/stop).

## 3. Security impact analysis

Strictly additive detective coverage. Tamper resistance: log-file validation;
the deploy role cannot stop or delete the trail. Residuals (documented as
inline checkov-skip rationales): SSE-S3 rather than a CMK (POAM-029-consistent),
no CloudWatch Logs integration or SNS notifications (quarterly review reads the
bucket; KSI-MLA-RVL).

### Verification plan (post-implementation)

After the bootstrap apply + merge + deploy: `describe-trails` shows the trail
(multi-region, validation on), `get-trail-status` shows `IsLogging: true`, the
bucket receives `AWSLogs/<account>/CloudTrail/...` objects, and the canonical
inventory carries the new `audit_log_trail` component in the next signal.
