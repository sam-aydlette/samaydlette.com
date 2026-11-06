# Significant Change Notification (SCN) records

This directory holds the system's FedRAMP 20x Significant Change Notification records,
per the SCN rules in the CR26 corpus (`providers/20x/rules/significant-change-notification.md`).

## Contents

- **[`scn-register.csv`](scn-register.csv)** — the register, and the source every published
  notification is built from. One row per adaptive or transformative change, carrying the
  `SCN-CSO-INF` fields, the dates the notice deadlines count from (`date_started`,
  `date_finished`, `verified_on`), and for transformative changes the plan, third-party-review and
  documentation-update fields. `scripts/_scn.py` validates it (`tests/test_scn.py`); a
  routine-recurring row is refused (`SCN-RTR-NNR`). A change that ships with the deploy that publishes
  its record has `status` `on-deploy` and no `date_finished`: the deploy's SCN build records it as
  implemented on the date of the first deploy that publishes it (`resolve_on_deploy`).
- **`SCN-<year>-<n>-<slug>.md`** — the human-readable record and copy of the security impact
  analysis for each change (`SCN-CSO-INF` item 9).
- **[`evaluation-examples.md`](evaluation-examples.md)** — the evaluation format and one example
  per type (`SCN-CSO-EVA`).
- **[`TEMPLATE-transformative.md`](TEMPLATE-transformative.md)** — the transformative record
  template: notice windows, third-party review, verification and documentation update.

## How the process runs

- **Evaluation (`SCN-CSO-EVA`).** Every pull request carries `SCN-Type:`, `SCN-Rationale:` and,
  for adaptive, transformative and emergency changes, `SCN-Record:`. The required `scn-tag`
  check ([`.github/workflows/scn-tag.yml`](../../.github/workflows/scn-tag.yml)) fails without
  them; there is no default. `class-change` always fails. A transformative change fails until its
  initial plan has been published 30 business days and its final plan 10.
- **Audit records (`SCN-CSO-MAR`).** Each deploy appends the evaluation of every change merged
  since the last one (commit, type, rationale, record, who merged it, when) to the signed,
  append-only log at `/.well-known/scn-evaluations.json` (and `.md`). A deploy that would drop or
  rewrite an entry fails.
- **Notification (`SCN-CSO-NOM`).** FedRAMP's rules name the notification method as an update to
  the Certification Data. Each deploy publishes every register row in FedRAMP's SCN schema at
  `/.well-known/significant-change-notifications.json` (signed), its human-readable view (`.md`)
  and an Atom feed (`significant-change-notifications.atom`) anyone can subscribe to; the
  Certification Package Overview lists them. A notice is given when it is first published, and
  the index records that date beside its deadline. **Nothing is sent by email or to FedRAMP.**
- **Deadlines.** Business days exclude weekends and US federal holidays (`scripts/_bizdays.py`).
  Adaptive: 10 after finishing (`SCN-ADP-NTF`). Transformative: initial plan 30 before starting,
  final plan 10 before, 5 after finishing, 5 after verification, documentation within 30
  (`SCN-TRF-*`). Emergency: the retroactive record within 5 (`SCN-CSO-EMG`). The scheduled
  [`scn-deadlines`](../../.github/workflows/scn-deadlines.yml) workflow fails and raises an issue
  on anything overdue.
- **History (`SCN-CSO-HIS`).** Notifications are never pruned; a deploy that would drop one or
  re-date a notice fails. Rows here are never deleted.

The six records below predate the published index: their notices were first published by the
deploy that introduced it, after their deadlines, and the index says so.

## Index

| SCN ID | Type | Change | Status |
| --- | --- | --- | --- |
| [SCN-2026-001](SCN-2026-001-silk-reeling.md) | Adaptive | "Silk Reeling Mirror" gated app | Implemented + post-impl. verified 2026-06-08 (live since 2026-06-03) |
| [SCN-2026-002](SCN-2026-002-cognito-auth.md) | Adaptive | Silk Reeling auth: Basic Auth → Cognito MFA + JWT authorizer (backfilled record) | Implemented 2026-06-22 (POAM-021/022/023 closed) + post-impl. verified 2026-07-06 |
| [SCN-2026-003](SCN-2026-003-cloudtrail.md) | Adaptive | CloudTrail management-events trail | Implemented + post-impl. verified 2026-07-09 |
| [SCN-2026-004](SCN-2026-004-evidence-alerting.md) | Adaptive | Evidence SLA watchdog and operator email alerting (backfilled record) | Implemented + post-impl. verified 2026-09-25 |
| [SCN-2026-005](SCN-2026-005-ci-identity-split.md) | Adaptive | CI identity split: read-only plan role; deploy role trusts only the prod environment | Implemented and verified 2026-09-28 |
| [SCN-2026-006](SCN-2026-006-remove-anthropic-interconnection.md) | Adaptive | Remove the Anthropic API interconnection; LLM feedback customer-configurable, off | Implemented (2026-10-27) |
| [SCN-2026-007](SCN-2026-007-fedramp-20x-rule-completeness.md) | Adaptive | FedRAMP 20x rule records and completeness gate; unattended publisher roles, edge access logging, DAST scanner user | Implemented on the first deploy that publishes it (`on-deploy`) |
