# CA — Assessment, Authorization, and Monitoring

There is no formal authorization process or independent assessor in scope for this PoC; the controls that depend on a third-party assessor or an authorizing official (CA-2/2.1, CA-6, CA-7.1, CA-8/8.1/8.2) are marked not-applicable in the OSCAL SSP. CA-7 (Continuous Monitoring) is the central live control of the family and is satisfied by:

- The runtime KSI emitter — daily revalidation of the live state versus the deploy-time signal, drift surfaced at `/.well-known/ksi-signal-runtime.json`.
- The deploy-time OPA gate — every PR re-evaluates the Terraform plan, the website tree, and the IAM policy against in-house Rego.
- The build-time VDR aggregator (see RA) — every CI run re-aggregates vulnerability state across SAST/SCA tools and blocks the build if any finding exceeds Class C remediation timeframes. The build is the report.

**20x rule integration.** This family carries Vulnerability Detection and Response (VDR-*) and Collaborative Continuous Monitoring (CCM). VDR is satisfied as described above and in RA. CCM is satisfied by the public-by-default publication of all KSI/SSP/runtime/VDR artifacts at `/.well-known/`, signed via Sigstore, verifiable from anywhere — anyone can run continuous monitoring of this system without privileged access.

The consolidated continuous-monitoring strategy (mechanisms, cadences, reporting, role mapping, NIST control coverage) is documented in [`docs/continuous-monitoring-plan.md`](../continuous-monitoring-plan.md), the document that backs CA-7 specifically.

**Review cadence.** Continuous (automated); annual structural review.
