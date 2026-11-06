# Rules of Behavior

## Purpose

Per NIST SP 800-53 PL-4, this document records the rules of behavior the system's privileged users acknowledge before being granted access. For a sole-operator system, the privileged-user population is the operator alone; the rules below are the operator's standing commitments.

## Scope

Privileged accounts in scope:

- AWS root account (operator's email)
- GitHub Actions OIDC roles (the deploy, plan, nightly and maintenance roles; short-lived credentials, no access key)
- AWS Lambda runtime IAM role (machine identity; non-privileged on most operations)
- GitHub repository owner (operator's GitHub account)
- GitHub Actions workflow identity (per-run OIDC token)

The Lambda runtime role and the per-run GitHub OIDC token are machine identities and the rules apply to the operator's behavior in configuring and operating them.

## Operator commitments

By operating this system, the operator commits to the following:

**Authentication.**
- Multi-factor authentication (virtual TOTP from an authenticator app; DEC-025, DEC-150) is enforced by AWS on the root and operator users and by GitHub on the owner account (DEC-151). The operator does not disable MFA.
- Long-lived credentials (AWS access keys, GitHub PATs) are not generated unless required, and when required they are stored only in GitHub Actions encrypted secrets.
- CI reaches AWS only through GitHub OIDC role assumption with short-lived credentials; the deployer access key it replaced was deleted (DEC-001, remediated).
- The operator does not share credentials, sessions, or MFA devices with any other person.

**Access discipline.**
- AWS root is used only for billing, service quotas, and IAM-policy-of-last-resort actions. Deploys run in GitHub Actions under OIDC roles.
- The operator does not perform routine operations from AWS root.
- The operator's GitHub session is the only authenticated path to push to `main`. Branch protection plus the OPA gate plus the SCN-Type validator constitute the technical enforcement.

**Change management.**
- The default workflow is direct push to `main`. Pull requests are used only when collaboration or staged review is desired (rare).
- Every change carries an explicit SCN evaluation (`SCN-CSO-EVA`): an `SCN-Type:` line, an `SCN-Rationale:` line and, where a notification is needed, an `SCN-Record:` line, in the commit message or PR description; there is no default, and the required `scn-tag` check fails a change without them (see the [CM policy](policies/cm-policy.md)). `SCN-Type: emergency` is reserved for emergency changes per `SCN-CSO-EMG`; see [`docs/incident-response.md`](incident-response.md) for the retroactive-documentation obligations that follow.
- The operator does not bypass the OPA gate, the schema validators, the VDR aggregator, or the SCN tag validator with `--no-verify`-style overrides.

**Information handling.**
- The operator does not use corporate or personal email to relay vulnerability information about the system. If such relay ever occurs, the email service comes into scope per ROT #2 and the boundary is reopened.
- The operator does not commit secrets, API keys, or credentials to the repository. GitHub secret scanning with push protection is enforced as a safety net.
- The operator does not introduce PII processing into the system without first re-evaluating the [Privacy Threshold Analysis](privacy-threshold-analysis.md) and producing the corresponding Privacy Impact Assessment.

**Incident response.**
- The operator is the IR lead. Detection sources, triage, containment, and after-action recording follow [`docs/incident-response.md`](incident-response.md).
- Spillage scenarios trigger the IR-9 procedure regardless of severity.

**Continuous monitoring.**
- The operator reviews the runtime KSI signal at least weekly and reconciles any drift against the deploy-time signal.
- The operator runs the annual security review per [`docs/security-review.md`](security-review.md).

**Acceptable use of the system's outputs.**
- Published artifacts at `/.well-known/` are public. The operator does not publish anything to `/.well-known/` that would be confidential, sensitive, or restricted.
- The operator's threat-model review (in [`architecture-decisions.md`](architecture-decisions.md)) governs what gets published.

## Acknowledgment

The Rules of Behavior are acknowledged by the operator on initial system stand-up and on each annual security review. The acknowledgment record is the security review entry for the corresponding year.

| Field | Value |
| --- | --- |
| Operator | Sam Aydlette |
| Initial acknowledgment | 2026-05-08 |
| Next review | 2027-05-08 (annual) |
| Re-acknowledgment trigger | Any Transformative change per SCN |

## Reference

- NIST SP 800-53 PL-4 (Rules of Behavior)
- [`docs/policies/ac-policy.md`](policies/ac-policy.md): Access Control policy
- [`docs/policies/secure-configuration-guide.md`](policies/secure-configuration-guide.md): top-level admin account configuration
- [`docs/incident-response.md`](incident-response.md): incident-response procedures
