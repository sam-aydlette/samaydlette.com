# Training Log

This document satisfies KSI-CED-RAT through KSI-CED-RAT. The system has one employee (Sam Aydlette, the author), who holds every role in the org, including all privileged-access roles, all development, and all incident response. "Persistent review of training effectiveness" is therefore conducted in the same medium in which the training itself occurs: the practitioner's head, with periodic externalization to this document.

## Coverage

The KSI catalog distinguishes general training from role-specific training. The distinctions are kept here for traceability against the catalog even where the roles collapse onto one person.

### KSI-CED-RAT: General security training

Ongoing professional reading on cybersecurity policies, procedures, and security-related topics. Effectiveness is reviewed by the only consumer of the training (the author) on the basis of whether the practices show up in the artifacts produced.

Active sources:

- CISA advisories and Secure-by-Design materials
- NIST SP 800-53 Rev 5; SP 800-61 (incident response); SP 800-218 (SSDF)
- FedRAMP 20x materials, including the KSI catalog this site implements
- Sigstore, in-toto, SLSA documentation
- AWS Security Bulletins
- The author's own published writing on the topic, which serves both as study and as forcing function for clarification

Effectiveness signal: this site exists as the artifact. It implements measures the author has read about. Review is implicit in the act of producing and maintaining the artifact; the OPA gate and the runtime KSI signal are the externally-visible evidence.

### KSI-CED-RAT: Role-specific privileged-access training

Privileged roles in this system: AWS account root, IAM administrator, GitHub repository owner, deployer (CI credentials), Lambda role principal. All held by the author.

Coverage: AWS Well-Architected Framework Security Pillar; AWS IAM best practices documentation; GitHub security model documentation; the cosign / Sigstore keyless threat model. Reviewed when AWS or GitHub publishes major changes (tracked passively via blog feeds and security bulletins).

### KSI-CED-RAT: Development and engineering training

Active sources:

- OWASP Top 10 (web app focus, even though this is a static site)
- CISA Secure by Design principles
- OPA / Rego documentation for policy authoring
- Terraform and AWS best-practices documentation
- The Sigstore + in-toto + SLSA stack of specifications

Effectiveness signal: every commit to this repo is reviewed against these sources before merge to `main`. The OPA gate and the schema validations are the automated counterweight.

### KSI-CED-RAT: Incident response and disaster recovery training

The IR lead is the author. "Training" here means having read NIST SP 800-61, having a runbook (see [`incident-response.md`](incident-response.md)), and having practiced recovery (see [`recovery-plan.md`](recovery-plan.md)). The recovery procedure has been exercised end-to-end during the construction of this implementation; that counts as a tabletop with a much-larger-than-tabletop scope.

## Review cadence

Annually, or whenever a relevant standard updates substantively. Updates are appended to this file as a dated entry.
