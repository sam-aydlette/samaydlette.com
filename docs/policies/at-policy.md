# AT — Awareness and Training

Training is generated and taken by machine (`scripts/_training.py`). The training packet is built from the system's own data on every build of the Security Decision Record: a lesson for every decision of the last 12 months, every incident and exercise, the applicable FedRAMP rules and KSIs, and a fixed core covering the operational runbooks ([incident response](../incident-response.md), [recovery plan](../recovery-plan.md), [supply chain](../supply-chain.md)) and information spillage (NIST IR-9.2). A simulated trainee, Pat Placeholder (simulated), takes its quiz whenever the packet changes (DEC-194), and the SDR counts the packet's currency and the trainee's completion as two automated methods for KSI-CED-RAT. The areas are listed in [`training-log.md`](../training-log.md).

**20x rule integration.** Aligns with KSI-CED (Cybersecurity Education).

**Verification.** Machine-checked on every deploy and every night (`scripts/check-non-machine-vv.py`), and re-checked, with its sha256, in each Annual Security Review (`scripts/hold-security-review.py`); a change is a reviewed pull request.
