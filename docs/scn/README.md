# Significant Change Notification (SCN) records

This directory holds the system's FedRAMP 20x Significant Change Notification records,
per the SCN rules in the CR26 corpus (`providers/20x/rules/significant-change-notification.md`).

## Contents

- **[`scn-register.csv`](scn-register.csv)** — the machine-readable **and** human-readable
  SCN register (`SCN-CSO-HRM`). One row per significant change, carrying the
  `SCN-CSO-INF` required fields. CSV is the format the FedRAMP SCN beta used to satisfy
  both readability requirements simultaneously.
- **`SCN-<year>-<n>-<slug>.md`** — the human-readable SCN record + copy of the security
  impact analysis for each change (`SCN-CSO-INF`, including item 9, the SIA).

## How this relates to the rest of the system

- **Evaluation (`SCN-CSO-EVA`):** every pull request into `main` carries a security
  impact analysis, answers to [`data/sia-questions.json`](../../data/sia-questions.json),
  and [`scripts/sia.py`](../../scripts/sia.py) derives the SCN type from it in the
  rule's order. The `scn-tag` check fails when a question the diff touches is
  unanswered or the declared `SCN-Type:` disagrees. See
  [`docs/policies/cm-policy.md`](../policies/cm-policy.md).
- **Audit records (`SCN-CSO-MAR`):** the pull requests, with their analyses and the
  `scn-tag` check runs, are the audit record of SCN evaluation activity.
  The register and the per-change records here are the durable, structured complement to
  that history for Adaptive and Transformative changes (which produce a SIA).
- **Historical notifications (`SCN-CSO-HIS`):** at least **12 months** of SCNs are kept
  here with the FedRAMP Certification data. Rows are never deleted; superseded records
  are retained.
- **Notification mechanism (`SCN-CSO-NOM`):** the system has no agency customers today,
  so notification is met by publishing the updated certification data — the KSI signal,
  SDR, CPO and VDR report at `/.well-known/` — alongside these records.
- **Emergency changes (`SCN-CSO-EMG`):** handled per the IR runbook
  ([`docs/incident-response.md`](../incident-response.md)); retroactive SCN materials are
  added here within the required window.

## Index

| SCN ID | Type | Change | Status |
| --- | --- | --- | --- |
| [SCN-2026-001](SCN-2026-001-silk-reeling.md) | Adaptive | "Silk Reeling Mirror" gated app | Implemented + post-impl. verified 2026-06-08 (live since 2026-06-03) |
| [SCN-2026-002](SCN-2026-002-cognito-auth.md) | Adaptive | Silk Reeling auth: Basic Auth → Cognito MFA + JWT authorizer (backfilled record) | Implemented 2026-06-22 (POAM-021/022/023 closed) + post-impl. verified 2026-07-06 |
| [SCN-2026-003](SCN-2026-003-cloudtrail.md) | Adaptive | CloudTrail management-events trail | Implemented + post-impl. verified 2026-07-09 |
| [SCN-2026-004](SCN-2026-004-evidence-alerting.md) | Adaptive | Evidence SLA watchdog and operator email alerting (backfilled record) | Implemented + post-impl. verified 2026-09-25 |
| [SCN-2026-005](SCN-2026-005-ci-identity-split.md) | Adaptive | CI identity split: read-only plan role; deploy role trusts only the prod environment | Implemented and verified 2026-09-28 |
| [SCN-2026-006](SCN-2026-006-remove-anthropic-interconnection.md) | Adaptive | Remove the Anthropic API interconnection; LLM feedback customer-configurable, off | Implemented (2026-10-27) |
