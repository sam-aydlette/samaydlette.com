# PL — Planning

The OSCAL Rev 5 SSP at [`/.well-known/oscal-ssp.json`](../../website/.well-known/oscal-ssp.json) is the system security plan, generated deterministically from the canonical inventory and the FedRAMP KSI catalog. It is signed via Sigstore keyless on every deploy.

The KSI signal at [`/.well-known/ksi-signal.json`](../../website/.well-known/ksi-signal.json) is the FedRAMP 20x companion artifact, also signed and published per deploy.

The architectural decision record [`architecture-decisions.md`](../architecture-decisions.md) captures the rationale for system-level decisions (PL-2 approach, threat model under SA-11.2, KSI-aligned justifications). The full set of family policies in this folder satisfies the per-family `-1` controls.

**20x rule integration.** KSI-PIY (Policy and Inventory). The 20x meta-process rules — FedRAMP Certification (`CRT-*`), Certification Data Sharing (`CDS-*`), and Marketplace Listing (`MKT-*`) — are documented in this PoC at the procedure level. The system is not actually FedRAMP-certified, so the obligations these rules impose (data sharing to FedRAMP, marketplace metadata accuracy) are demonstrated rather than executed.

**Review cadence.** Annually with the [security review](../security-review.md), plus after Transformative changes per SCN.
