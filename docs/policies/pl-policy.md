# PL — Planning

Under CR26 the system security plan is replaced by the Security Decision Record at `/.well-known/security-decision-record.json` and the Certification Package Overview at `/.well-known/certification-package-overview.json`. The SDR records how each KSI is met and, in `rev5_controls`, each applicable Rev5 control's parameters, status, mechanisms, verification and validation (`SDR-CSF-CTF`). Both are generated deterministically from the canonical inventory and the FedRAMP KSI catalog through the control projection (`scripts/_controls.py`) and signed via Sigstore keyless on every deploy; the SDR also carries an in-toto provenance attestation. The OSCAL SSP that used to fill this role was retired on 2026-11-05.

The KSI signal at [`/.well-known/ksi-signal.json`](https://samaydlette.com/.well-known/ksi-signal.json) is the FedRAMP 20x companion artifact, also signed and published per deploy.

The architectural decision record [`architecture-decisions.md`](../architecture-decisions.md) captures the rationale for system-level decisions (PL-2 approach, threat model under SA-11.2, KSI-aligned justifications). The full set of family policies in this folder satisfies the per-family `-1` controls.

**20x rule integration.** KSI-PIY (Policy and Inventory). The 20x meta-process rules — FedRAMP Certification (`CRT-*`), Certification Data Sharing (`CDS-*`), and Marketplace Listing (`MKT-*`) — are documented in this PoC at the procedure level. The system is not actually FedRAMP-certified, so the obligations these rules impose (data sharing to FedRAMP, marketplace metadata accuracy) are demonstrated rather than executed.

**Review cadence.** Annually with the [security review](../security-review.md), plus after Transformative changes per SCN.
