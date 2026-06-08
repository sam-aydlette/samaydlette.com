# Significant Change Notification (SCN) records

This directory holds the system's FedRAMP 20x Significant Change Notification records,
per the SCN rules in the CR26 corpus (`providers/20x/rules/significant-change-notifications.md`).

## Contents

- **[`scn-register.csv`](scn-register.csv)** — the machine-readable **and** human-readable
  SCN register (`SCN-CSO-HRM`). One row per significant change, carrying the
  `SCN-CSO-INF` required fields. CSV is the format the FedRAMP SCN beta used to satisfy
  both readability requirements simultaneously.
- **`SCN-<year>-<n>-<slug>.md`** — the human-readable SCN record + copy of the security
  impact analysis for each change (`SCN-CSO-INF`, including item 9, the SIA).

## How this relates to the rest of the system

- **Audit records (`SCN-CSO-MAR`):** the git history is the audit record of SCN
  evaluation activity. Every commit to `main` carries an `SCN-Type:` categorization
  validated by [`.github/workflows/scn-tag.yml`](../../.github/workflows/scn-tag.yml);
  the default is `routine-recurring` per [`docs/policies/cm-policy.md`](../policies/cm-policy.md),
  and the operator upgrades to `adaptive` / `transformative` / `emergency` explicitly.
  The register and the per-change records here are the durable, structured complement to
  that history for Adaptive and Transformative changes (which produce a SIA).
- **Historical notifications (`SCN-CSO-HIS`):** at least **12 months** of SCNs are kept
  here with the FedRAMP Certification data. Rows are never deleted; superseded records
  are retained.
- **Notification mechanism (`SCN-CSO-NOM`):** the system has no agency customers today,
  so notification is met by publishing the updated certification data — the KSI signal,
  OSCAL SSP, and VDR report at `/.well-known/` — alongside these records.
- **Emergency changes (`SCN-CSO-EMG`):** handled per the IR runbook
  ([`docs/incident-response.md`](../incident-response.md)); retroactive SCN materials are
  added here within the required window.

## Index

| SCN ID | Type | Change | Status |
| --- | --- | --- | --- |
| [SCN-2026-001](SCN-2026-001-silk-reeling.md) | Adaptive | "Silk Reeling Mirror" gated app | Implemented + post-impl. verified 2026-06-08 (live since 2026-06-03) |
