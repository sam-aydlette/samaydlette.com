# SA — System and Services Acquisition

The system follows a CISA Secure-by-Design SDLC. Every change passes through a PR with policy-as-code review (the OPA gate evaluates the Terraform plan, the website tree, and the IAM policy). Threat modeling and vulnerability analyses (SA-11.2) are documented in [`architecture-decisions.md`](../architecture-decisions.md). Provenance for every component is captured in the canonical inventory and signed via Sigstore (SA-15.10). External dependencies are PURL-named for unambiguous identification; the deploy chain is reproducible from source.

The system has no acquisition relationships beyond AWS services and GitHub Actions, both of which are inherited or covered under SR.

**20x rule integration.** KSI-PIY-RSD (Reviewing Security in the SDLC) is satisfied by the OPA gate + threat model + signing chain combination. SCN evaluation (CM family) gates every code change before it reaches production.

**Review cadence.** Annually with the [security review](../security-review.md); threat model revisited after Transformative changes.
