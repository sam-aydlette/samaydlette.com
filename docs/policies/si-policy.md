# SI — System and Information Integrity

Continuous integrity monitoring runs across three layers:

- **Code:** SAST (Checkov, tfsec, OPA gate) + SCA (Dependabot). See RA.
- **Configuration:** the runtime KSI emitter revalidates the live cloud configuration daily and publishes `/.well-known/ksi-signal-runtime.json`. Drift between the deploy-time signal and the runtime signal is publicly detectable.
- **Content:** every published HTML artifact is content-hashed, the canonical inventory carries the hash, and the Sigstore signature binds the inventory to the published bundle.

Information input validation, error handling, and memory protections (SI-10/11/16) are largely not-applicable as scoped: the only application code in scope is a short-lived Node.js Lambda with no user-facing input surface; the static site has no form inputs or interactive endpoints. SI-7 (software, firmware, and information integrity) is satisfied by the Sigstore signing chain plus the runtime drift detector.

**20x rule integration.** Vulnerability Detection and Response (VDR) — see RA. KSI-MLA monitoring boundary.

**Review cadence.** Continuous (automated); annual structural review.
