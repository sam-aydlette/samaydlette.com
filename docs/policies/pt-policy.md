# PT — PII Processing and Transparency

The system processes no personally identifiable information. There are no end users, no customer accounts, no forms, no analytics that collect personal data, no cookies that identify visitors. CloudFront access logs are excluded for cost (AWS-default request metadata only). The site is a static publication surface.

All PT controls in the Moderate baseline are therefore not-applicable as scoped, with this policy doc itself satisfying PT-1. The formal Privacy Threshold Analysis with the negative determination is recorded in [`docs/privacy-threshold-analysis.md`](../privacy-threshold-analysis.md). If the system's data-processing posture ever changes (forms, accounts, analytics that collect PII), the PT family is reactivated, the PTA is re-determined, a full PIA is produced, and this doc is rewritten before the change is deployed.

**20x rule integration.** None directly. Operator awareness of PII obligations is part of the annual training reading-list under AT.

**Review cadence.** Annually; review whether the system's data processing posture has changed.
