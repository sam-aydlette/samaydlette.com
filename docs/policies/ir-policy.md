# IR — Incident Response

Incident response procedures are documented in [`incident-response.md`](../incident-response.md), which satisfies KSI-INR-RIR through KSI-INR-AAR and the IR-9 family (information spillage). The runbook covers detection sources, triage (including the FedRAMP reportability evaluation), containment, eradication, recovery, FedRAMP incident reporting, and after-action reporting. The IR lead is the operator; escalation is single-tier.

External communication paths:

- **Public reporter:** [`/.well-known/security.txt`](../../website/.well-known/security.txt) is the published vulnerability-reporting mailbox.
- **FedRAMP incident reports (IEC):** every incident is recorded in the incident register, [`data/incidents.json`](../../data/incidents.json), with its reportability evaluation. Initial, Ongoing and Final Incident Reports for a FedRAMP Reportable Incident are generated from it, validated against FedRAMP's incident report schema, signed, and published under `/.well-known/` (the incident log is `/.well-known/incident-reports.json`) by an unattended workflow on every change to the register.
- **Notification is publish-only.** Nothing is sent to FedRAMP or to any agency. The operator has not authorized sending, and the system has no FedRAMP certification and no agency customers. Choosing a delivery channel is an operator decision; until it is made, publication is the only channel and every report says so.
- **FedRAMP Security Inbox (FSI, 20x):** the system is not FedRAMP-certified; no actual FSI obligation applies. Notification path is documented in the runbook for reference.

**20x rule integration.** KSI-INR (Incident Response), IEC (Incident Evaluation and Communication), FSI (FedRAMP Security Inbox).

**Reportability (IEC-CSO-EFR).** Every incident is evaluated, promptly and before containment, for whether it affects or is likely to affect the confidentiality or integrity of **federal customer data**; such an incident is a FedRAMP Reportable Incident. The determination, its reason and the federal customer data considered are recorded in the register and published in the incident log. This system holds no federal customer data, so in practice the evaluation is "not reportable"; the machinery runs either way, and it was exercised on 2026-11-05 with one simulated reportable incident and one simulated non-reportable one, both marked as exercises.

**Rating (IEC-CSO-DPR, IEC-CSO-EFI).** A reportable incident is rated at the default the rules set (N5) until the operator records an Incident Rating estimate: a likely minimal, narrow, disruptive or debilitating customer effect on one or more than one agency, with a reason. The register refuses an estimate whose rating is not the one the rules give for that effect.

**Report clocks.** The Initial, Ongoing and Final report deadlines are FedRAMP's Class C timeframes, read from the pinned rules and never restated. An overdue report fails the incident reports workflow (raising a GitHub issue) and pages the operator through the evidence SLA watchdog.

**Vulnerabilities as incidents (VER-TFR-IRI, VER-TFR-NRI).** The operator adopts both rules. An internet-reachable likely exploitable vulnerability above PAIN N3 (i.e. N4 or N5) is a FedRAMP Reportable Incident until it is partially mitigated to N3 or below (`VER-TFR-IRI`), and a non-internet-reachable likely exploitable vulnerability at PAIN N5 is one until it is N4 or below (`VER-TFR-NRI`, a MAY the operator has chosen to use). The VDR triage policy names each such finding; the incident log shows it, and until an incident in the register names it, its Initial report is due and the alarms above apply.

**Review cadence.** Annually with the [security review](../security-review.md); after every actual incident (currently zero; the two recorded incidents are exercises).

_AI-drafted (2026-11-05) to describe what the incident register, report builder and workflow now do; for the operator's review._
