# IR — Incident Response

Incident response procedures are documented in [`incident-response.md`](../incident-response.md), which satisfies KSI-INR-RIR through KSI-INR-AAR and the IR-9 family (information spillage). The runbook covers detection sources, triage, containment, eradication, recovery, and after-action reporting. The IR lead is the operator; escalation is single-tier.

External communication paths:

- **Public reporter:** [`/.well-known/security.txt`](../../website/.well-known/security.txt) is the published vulnerability-reporting mailbox.
- **Incident Communications Procedures (ICP, 20x):** the ICP rules apply at the procedure-documented level even though the system has no actual FedRAMP-customer reporting obligation. The runbook describes what would be communicated and to whom for a real FedRAMP-certified service.
- **FedRAMP Security Inbox (FSI, 20x):** the system is not FedRAMP-certified; no actual FSI obligation applies. Notification path is documented in the runbook for reference.

**20x rule integration.** KSI-INR (Incident Response), ICP (Incident Communications Procedures), FSI (FedRAMP Security Inbox).

**Review cadence.** Annually with the [security review](../security-review.md); after every actual incident (currently zero). VDR thresholds (Class C) treat internet-reachable likely-exploitable vulnerabilities above PAIN N3 (i.e. N4 or N5) as FedRAMP Reportable Incidents per `VER-TFR-IRI`, until they are partially mitigated to N3 or below; non-internet-reachable likely-exploitable vulnerabilities at PAIN N5 are reportable until N4 or below per `VER-TFR-NRI`.

**Reportability trigger (IEC).** A FedRAMP Reportable Incident under `IEC-CSO-EFR` is triggered by an effect on the confidentiality or integrity of **federal customer data**. This system holds none, so no finding here is FedRAMP-reportable in practice and the `IEC-CSO-IIR` reporting clocks (Class C: 1 hour for PAIN 3/4/5) never start. The evaluation step still runs — the VDR aggregator assigns the PAIN rating to every finding — so the machinery is in place the moment federal data ever enters scope.
