# Family Policies and Procedures

One file per NIST 800-53 Rev 5 control family in scope for the FedRAMP Rev 5 Moderate baseline, plus the FedRAMP 20x Secure Configuration Guide. Each file is the per-family `-1` policy and procedures document; together they satisfy the family-level policy controls (AC-1, AT-1, AU-1, CA-1, CM-1, CP-1, IA-1, IR-1, MA-1, MP-1, PE-1, PL-1, PS-1, PT-1, RA-1, SA-1, SC-1, SI-1, SR-1).

The 20x Consolidated Rules for 2026 do not replace the Rev 5 family structure; they layer additional rules (Significant Change Notifications, Vulnerability Detection and Response, Minimum Assessment Scope, Secure Configuration Guide, Collaborative Continuous Monitoring, Incident Communications Procedures, FedRAMP Security Inbox, Using Cryptographic Modules, Certification Data Sharing, Marketplace Listing, FedRAMP Certification) onto the relevant families. Each policy doc names which 20x rules it integrates.

For families that are inherited from AWS, the policy doc says so and cites the authorization package: AWS East/West Moderate FedRAMP authorization, Package ID **AGENCYAMAZONEW**.

## Class designation

This system targets **20x Class C** (the most commonly used class, equivalent to traditional Moderate). VDR timeframes, monitoring cadences, and reporting frequencies in these policies use the Class C variant.

## Cross-references

These policies reference operational documents elsewhere in `docs/`:

- [`incident-response.md`](../incident-response.md) — IR procedures
- [`recovery-plan.md`](../recovery-plan.md) — CP procedures
- [`security-review.md`](../security-review.md) — how the Annual Security Review is generated (`scripts/hold-security-review.py`), and its history
- [`supply-chain.md`](../supply-chain.md) — SR procedures
- [`training-log.md`](../training-log.md) — AT records
- [`architecture-decisions.md`](../architecture-decisions.md) — system design rationale, threat model
- [`data/decisions.json`](../../data/decisions.json) — the decision register (replaced the POA&M under CR26)
- [`ksi-signal.md`](../ksi-signal.md) — KSI signal generation, the control projection and the SDR

## Review

The full family-policy set is machine-checked on every deploy and every night (`scripts/check-non-machine-vv.py`) and re-checked, with each file's sha256, in the Annual Security Review ([`security-review.md`](../security-review.md), `scripts/hold-security-review.py`); a Transformative significant change (SCN) revisits it in the same pull request.
