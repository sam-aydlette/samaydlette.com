# Incident Response Runbook

This document satisfies KSI-INR-RIR through KSI-INR-AAR. The IR lead is the author. The on-call rotation has one slot and is staffed continuously.

## Scope

In-scope incidents:

- Defacement or unauthorized modification of site content
- Compromise of the AWS account or the GitHub repository
- Compromise of long-lived credentials (AWS access keys, GitHub PATs)
- Supply-chain compromise affecting build tooling or dependencies
- Loss of CDN or DNS availability beyond declared RTO (21 days; see [`recovery-plan.md`](recovery-plan.md))
- Drift between the deploy-time KSI signal and the runtime KSI signal that cannot be explained by a deploy-in-progress

Out of scope:

- Any incident involving federal customer data, end-user accounts, or downstream agencies — this system has none of those
- Service-level incidents around availability promises to anyone, since none exist

## Detection

Active detection sources:

- **GitHub:** Dependabot vulnerability alerts, secret scanning push protection, security advisories — all auto-emailed to the repository owner
- **AWS:** root-account email for billing anomalies, AWS Health Dashboard, CloudTrail (account-wide)
- **The runtime KSI emitter:** publishes `/.well-known/ksi-signal-runtime.json` daily; drift against the deploy-time signal is the strongest single drift indicator the system produces
- **External report:** the mailbox listed in [`/.well-known/security.txt`](../website/.well-known/security.txt)
- **Personal vigilance:** reading the actual site

## Triage and response procedures

1. **Confirm.** Compare the runtime KSI signal at `/.well-known/ksi-signal-runtime.json` against the deploy-time signal. Any unexplained `result: "fail"` validation, or any component drift, is high-confidence signal of a real change.
2. **Contain.**
   - **Credential compromise (AWS):** rotate the IAM access keys via the IAM console; revoke any active sessions; rotate the GitHub Actions secret holding the credentials.
   - **Credential compromise (GitHub):** revoke any compromised PATs; rotate the workflow's `GITHUB_TOKEN` is automatic per-run; reset OAuth grants if external apps are involved.
   - **Content compromise:** revert via `git`, redeploy via `make pipeline`. S3 versioning preserves the prior state; CloudFront invalidation refreshes the edge.
   - **Supply-chain compromise:** pin the offending dependency to a known-good version, redeploy, and file a Dependabot suppression if the alert source is the GitHub Advisory Database.
3. **Eradicate.** Identify the root cause (credential, code, or config) and patch it. Confirm the patch holds via a fresh `make pipeline`.
4. **Recover.** Verify the runtime signal returns to clean. Verify `cosign verify-blob` still passes against the new signal and bundle. Confirm the site is reachable end-to-end.
5. **Lessons learned.** Append an after-action entry to the section below.

## After-action reports (KSI-INR-AAR)

No incidents have occurred to date that warranted a formal after-action report. (This is itself useful evidence of *something*, though the author resists drawing strong conclusions from a sample size of zero.)

When one does occur, the entry takes this template:

```
## YYYY-MM-DD: <short title>

- **Detection time:** <when first noticed>
- **Containment time:** <when scope-limited>
- **Eradication time:** <when root cause patched>
- **Recovery time:** <when service fully restored>
- **Root cause:** <short description>
- **Resolution:** <what was changed>
- **Lessons learned:** <patterns or vulnerabilities noted, links to follow-up items>
- **Follow-up:** <repo issues filed for non-immediate fixes>
```

## Information Spillage Response (NIST IR-9 family)

In-scope spillage scenarios for a static personal site:

- Operator AWS access keys, GitHub PATs, or other credentials accidentally surfaced in a public commit, PR diff, screenshot, or external venue
- Internal AWS resource identifiers (account IDs, ARNs) leaked in a context that materially aids targeting
- Pre-publication content or drafts pushed to the public site before review
- Personally-identifying or otherwise sensitive content in the operator's possession surfacing in site artifacts

Response procedure:

1. **Identify scope.** Determine what spilled, where it surfaced, and how long it has been visible. The git log, GitHub Actions history, and CloudTrail give the timeline.
2. **Remove from public surfaces.** Revert the commit, delete the offending S3 object (S3 versioning preserves the prior state), redact the GitHub issue or PR, force-invalidate CloudFront for the affected paths.
3. **Rotate compromised credentials.** AWS access keys, GitHub PATs, GitHub Actions secrets — rotate immediately, regardless of perceived exposure window.
4. **Preserve evidence.** Record the timeline, the surface, and the actions taken before the public surface is updated. Record in the after-action template.
5. **Notify if applicable.** External notification is generally not required for a personal site; this section exists for the case where it ever is.

(IR-9.2) Training: spillage scenarios are part of the annual review of this runbook (see [`docs/training-log.md`](training-log.md), KSI-CED-RAT section).

(IR-9.3) Post-spill operations: the spillage scope is bounded by the public-static-site surface. After containment, normal site operation continues; there is no production environment to quarantine because the production environment is the public site itself.

(IR-9.4) Exposure to unauthorized personnel: by design the public site has no "unauthorized personnel" — any reader is authorized. Spillage exposure is therefore best understood as premature publication of content not yet ready for public release, which is addressed by the response procedure above.

## Emergency-change procedure (CR26 SCN-CSO-EMG)

CR26 `SCN-CSO-EMG` permits the operator to execute significant changes — including transformative changes — during an emergency without following the formal Significant Change Notification rules in advance, provided the procedures below are followed.

**When permissible.** Emergency procedures apply when delaying a change to follow the standard SCN flow would itself increase risk to the system or to federal customer data. Examples in this scope: a credential leak requiring immediate rotation, a known-exploited vulnerability requiring same-day patching, an active incident requiring infrastructure-level changes to contain.

**What gets bypassed.** During an emergency the operator may:

- Push directly to `main` without the usual SCN-Type categorization deliberation (an `emergency` label is still required on the commit message — see below).
- Skip the standard advance-notification timing for Adaptive (`SCN-ADP-NTF`, 10 business days) or Transformative (`SCN-TRF-NIP`/`NFP`/`NAF`/`NAV`, 30 / 10 / 5 / 5 business days, plus the 30-business-day documentation update in `SCN-TRF-UPD`) changes.
- Defer the threat-model review and per-control implementation-statement updates that a Transformative change would normally trigger.

**What still applies.** During and after an emergency the operator must:

1. Tag the commit message with `SCN-Type: emergency` so the SCN audit record reflects the emergency disposition. The CI workflow recognizes `emergency` as a fourth valid SCN-Type value alongside `routine-recurring`, `adaptive`, and `transformative`.
2. Follow the rest of this IR runbook: detect, contain, eradicate, recover, after-action.
3. Within 5 business days of incident closure, retroactively produce the SCN materials that would have been produced in advance for the equivalent non-emergency change (per `SCN-CSO-EMG`): summary of the change, summary of new risks identified, copy of the security impact analysis, plan for any verification or assessment of impacted KSIs.
4. Append an after-action entry to the section above with the emergency-procedure invocation noted in the timeline.
5. Reopen the threat model in `docs/architecture-decisions.md` if the emergency change altered the threat surface, and update before the next security review.

**Documentation evidence.** Emergency-change procedures are documented in this section, in `docs/policies/cm-policy.md` (referenced under SCN integration), and in the `.github/workflows/scn-tag.yml` validator (which accepts `emergency` as a valid tag). Together these satisfy `SCN-CSO-EMG`'s "procedures should be documented in the FedRAMP Certification package" requirement.

## Pattern review (KSI-INR-RPI)

KSI-INR-RPI calls for persistent review of past incidents for patterns. With zero incidents to date, the review is short. The cadence is annual, conducted as part of [`security-review.md`](security-review.md). When the incident count is greater than zero, the review will look for: repeated root causes, common detection-time gaps, and any patterns that suggest systemic rather than individual fixes.

## Escalation

Single-tier. Author → author. External escalations:

- **AWS Support** — if the issue is AWS-side (account, billing, service-level)
- **GitHub Support** — if the issue is GitHub-side (account, repo, workflow infrastructure)
- The mailbox in `security.txt` for acknowledging external reporters

There is no actual FedRAMP authorization in scope, so the FedRAMP Security Inbox (FSI) and Incident Communications Procedures (ICP) do not apply.

