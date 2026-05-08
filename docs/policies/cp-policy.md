# CP — Contingency Planning

Recovery posture is documented in [`recovery-plan.md`](../recovery-plan.md). Declared RTO is 21 days; declared RPO is one deploy cycle (S3 versioning preserves prior state, git preserves all source). Multi-region active-passive was excluded as a cost trade-off. Backup strategy: git for code and configuration, S3 versioning for content, AWS-default backup for logs.

CP enhancements covering alternate processing site, alternate storage site, and telecommunications redundancy (CP-6, CP-7, CP-8 and their enhancements) are inherited from AWS East/West Moderate FedRAMP authorization (Package ID: AGENCYAMAZONEW); the system runs on AWS-managed services that already incorporate cross-AZ resilience.

**20x rule integration.** Aligns with KSI-CPL (Recovery Planning). Plan exercise cadence is in [`security-review.md`](../security-review.md).

**Review cadence.** Annually, plus after any Transformative change per SCN.
