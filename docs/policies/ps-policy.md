# PS — Personnel Security

Personnel screening, position-risk designation, separation-of-duty, and termination procedures collapse to a single operator who is also the system architect, content author, and incident-response lead. Where Rev 5 expects role separation, the system instead relies on small blast radius and the public auditability of the deploy chain — every action is recorded in the git log and the Sigstore Rekor transparency log. The operator's own access posture is governed under AC and the [Secure Configuration Guide](secure-configuration-guide.md).

**20x rule integration.** No 20x rule maps to PS specifically.

**Review cadence.** Annually with the [security review](../security-review.md).
