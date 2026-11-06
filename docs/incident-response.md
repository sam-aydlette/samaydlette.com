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

- Service-level incidents around availability promises to anyone, since none exist

Federal customer data, end-user accounts and downstream agencies: this system has none, so no incident here is expected to be a FedRAMP Reportable Incident. Every incident is still evaluated for it (step 2 below) and the determination is recorded, because the evaluation is what the rules ask for, and because a wrong assumption would otherwise go unrecorded.

## Detection

Active detection sources:

- **GitHub:** Dependabot vulnerability alerts, secret scanning push protection, security advisories — all auto-emailed to the repository owner
- **AWS:** root-account email for billing anomalies, AWS Health Dashboard, CloudTrail (account-wide)
- **The runtime KSI emitter:** publishes `/.well-known/ksi-signal-runtime.json` daily; drift against the deploy-time signal is the strongest single drift indicator the system produces
- **The evidence SLA watchdog:** five CloudWatch alarms email the operator through SNS: when the published VDR is older than its governed freshness window, the runtime signal is older than its window, the evidence nightly fails or stops reporting, any published `/.well-known/` artifact is past its window or unreadable, or an incident report is past its Class C deadline (`infrastructure/watchdog.tf`; windows in `infrastructure/schemas/freshness-config.json`). Response steps: [`docs/runbooks/evidence-sla-alarm.md`](runbooks/evidence-sla-alarm.md)
- **External report:** the mailbox listed in [`/.well-known/security.txt`](../website/.well-known/security.txt)
- **Personal vigilance:** reading the actual site

## Triage and response procedures

1. **Confirm.** Compare the runtime KSI signal at `/.well-known/ksi-signal-runtime.json` against the deploy-time signal. Any unexplained `result: "fail"` validation, or any component drift, is high-confidence signal of a real change.
2. **Record and evaluate FedRAMP reportability (IEC-CSO-EFR).** Add the incident to [`data/incidents.json`](../data/incidents.json) with `detected_at`, `detection_source` and an `evaluation`: when it was evaluated, `reportable` true or false, the `basis` (`IEC-CSO-EFR`, or `VER-TFR-IRI` / `VER-TFR-NRI` for a vulnerability), the `reason`, and the federal customer data considered. Does it affect, or is it likely to affect, the confidentiality or integrity of federal customer data (data an agency or its users supply to the service, not account information or telemetry)? If yes it is a FedRAMP Reportable Incident: continue with [Reporting](#reporting-fedramp-reportable-incidents-iec) in parallel with containment. Push the record; the incident log republishes within minutes.
3. **Contain.**
   - **Credential compromise (AWS):** rotate the IAM access keys via the IAM console; revoke any active sessions; rotate the GitHub Actions secret holding the credentials.
   - **Credential compromise (GitHub):** revoke any compromised PATs; rotate the workflow's `GITHUB_TOKEN` is automatic per-run; reset OAuth grants if external apps are involved.
   - **Content compromise:** revert via `git`, push to `main`, and approve the `prod` deploy. S3 versioning preserves the prior state; CloudFront invalidation refreshes the edge.
   - **Supply-chain compromise:** pin the offending dependency to a known-good version, redeploy, and file a Dependabot suppression if the alert source is the GitHub Advisory Database.
4. **Eradicate.** Identify the root cause (credential, code, or config) and patch it. Confirm the patch holds via a fresh approved deploy.
5. **Recover.** Verify the runtime signal returns to clean. Verify `cosign verify-blob` still passes against the new signal and bundle. Confirm the site is reachable end-to-end.
6. **Lessons learned.** Append an after-action entry to the section below.

## Reporting FedRAMP Reportable Incidents (IEC)

_AI-drafted (2026-11-05) to describe what is now built; for the operator's review._

Reporting is automated from the incident register. A person records facts; the pipeline renders, validates, signs, publishes and keeps the clocks.

- **Register.** [`data/incidents.json`](../data/incidents.json), read through `scripts/_incidents.py` (fails closed; shape in `infrastructure/schemas/incidents.schema.json`). Each report is an entry in the incident's `reports` list (`Initial`, then `Ongoing`, then `Final`) with the time it is issued and the items it sets: description, functional impact, recovery plan, likely affected agencies, observed activity, indicators of compromise, related CVEs, root cause, response and recovery activities, milestones. A report restates everything set before it.
- **Rating.** Until an `estimates` entry exists, the incident is rated N5 (`IEC-CSO-DPR`). An estimate (`IEC-CSO-EFI`) records the customer effect (minimal, narrow, disruptive, debilitating), whether one agency or more than one is likely affected, the reason and the time; the register refuses a rating that is not the one the rules give for that combination (N1 minimal, N2 narrow, N3 disruptive on one agency, N4 debilitating on one or disruptive on several, N5 debilitating on several).
- **Clocks.** Read from FedRAMP's Class C rules: the Initial report is due from the evaluation, each Ongoing report from the previous report until the incident is resolved, and the Final report from `recovery_complete_at` (hours at N3-N5; 24 hours or one business day at N1-N2; business days skip weekends, and holidays are counted, which can only make a deadline earlier). The rating in force when each clock starts sets its length.
- **Build and publish.** `scripts/build-incident-report.py` writes each report in FedRAMP's incident report schema (`incident-<ID>-<NN>-<type>.json`, validated before it is written) and the incident log (`incident-reports.json` and `.md`: every incident, its evaluation and reason, its rating history, each report with its sha256 and what changed, and each clock). `.github/workflows/incident-reports.yml` runs it on every push of the register to `main`, by hand, twice a day and after each nightly VDR refresh; it signs, redaction-gates and publishes under `/.well-known/incident-*` with a role that can write nothing else. Every deploy republishes the same set.
- **Alarms.** The workflow's last step fails, and raises a GitHub issue, when a report is past its deadline. The evidence SLA watchdog reads the published log hourly and pages by email (`incident-report-overdue`, [`runbooks/evidence-sla-alarm.md`](runbooks/evidence-sla-alarm.md)).
- **Vulnerabilities as incidents.** The operator adopts `VER-TFR-IRI` and `VER-TFR-NRI` (`policy.adopted_vulnerability_rules`). The VDR triage policy names each finding they cover; until an unresolved incident in the register lists it under `findings`, its Initial report is due from the finding's first evaluation at N5, so the alarms fire. Open the incident with basis `VER-TFR-IRI` or `VER-TFR-NRI` and the finding's tracking ID or CVE. Reconciliation invariant (m) fails a build whose open incident names a finding the VDR no longer carries: close it with a Final report.
- **Delivery is simulated.** FedRAMP and the affected agencies are "all affected parties" under the rules. This system has no certification and no agency customers, so they are simulated recipients: on every deploy and every run of the incident reports workflow, `scripts/deliver-incident-reports.py` reads back each report the log lists, checks its sha256 and FedRAMP's schema, and records its "delivery" to "FedRAMP Incident Desk (simulated)" and to each affected agency (simulated) in `/.well-known/incident-deliveries.json`. A delivery that fails stops publication. Nothing is sent to anyone.
- **The publisher's role is proved on every deploy.** Before the Security Decision Record is built, the deploy job assumes the incident reports role (`scripts/check-incident-role.py`); if it cannot, the deploy stops.
- **Exercises.** A simulated incident is recorded with `exercise: true` and is published marked as one. Exercised 2026-11-05: `INC-2026-001` (a simulated internet-reachable N5 vulnerability: Initial, two Ongoing and a Final report on a simulated timeline, all on time; rated N5 by default, then estimated N3) and `INC-2026-002` (a simulated page change, evaluated not reportable with its reason). `tests/test_incidents.py` runs the same exercise through the builder on every `make check`.

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

- Merge without the usual categorization deliberation (an `SCN-Type: emergency` evaluation is still required — see below).
- Skip the standard advance-notification timing for Adaptive (`SCN-ADP-NTF`, 10 business days) or Transformative (`SCN-TRF-NIP`/`NFP`/`NAF`/`NAV`, 30 / 10 / 5 / 5 business days, plus the 30-business-day documentation update in `SCN-TRF-UPD`) changes.
- Defer the threat-model review and per-control implementation-statement updates that a Transformative change would normally trigger.

**What still applies.** During and after an emergency the operator must:

1. Carry `SCN-Type: emergency`, a one-line `SCN-Rationale:` and the `SCN-Record:` the retroactive record will use in the pull request description (or the commit message of a direct push), so the evaluation log records the emergency disposition. The `scn-tag` check accepts it and says the record is due.
2. Follow the rest of this IR runbook: detect, contain, eradicate, recover, after-action.
3. Within 5 business days, retroactively produce the SCN materials that would have been produced in advance for the equivalent non-emergency change (per `SCN-CSO-EMG`): summary of the change, summary of new risks identified, copy of the security impact analysis, plan for any verification or assessment of impacted KSIs. Count the 5 business days from the day the emergency change merged. The materials are a row in `docs/scn/scn-register.csv` with `emergency` = `yes` and the change in `evaluation_prs`, plus its record; the next deploy publishes them, which is the notification to all necessary parties. The scheduled SCN deadline check (`.github/workflows/scn-deadlines.yml`) fails and raises an issue if the record is not in the register within 5 business days of the emergency change merging, and the published index marks each retroactive notice against that deadline.
4. Append an after-action entry to the section above with the emergency-procedure invocation noted in the timeline.
5. Reopen the threat model in `docs/architecture-decisions.md` if the emergency change altered the threat surface, and update before the next security review.

**Documentation evidence.** Emergency-change procedures are documented in this section, in `docs/policies/cm-policy.md` (referenced under SCN integration), in the `.github/workflows/scn-tag.yml` gate (which accepts `emergency`), and in the Certification Package Overview, which links this section. Together these satisfy `SCN-CSO-EMG`'s "procedures should be documented in the FedRAMP Certification package" requirement.

## Pattern review (KSI-INR-RPI)

KSI-INR-RPI calls for persistent review of past incidents for patterns. With zero incidents to date, the review is short. The cadence is annual, conducted as part of [`security-review.md`](security-review.md). When the incident count is greater than zero, the review will look for: repeated root causes, common detection-time gaps, and any patterns that suggest systemic rather than individual fixes.

## Escalation

Single-tier. Author → author. External escalations:

- **AWS Support** — if the issue is AWS-side (account, billing, service-level)
- **GitHub Support** — if the issue is GitHub-side (account, repo, workflow infrastructure)
- The mailbox in `security.txt` for acknowledging external reporters

There is no actual FedRAMP certification in scope. Incident reports under the FedRAMP Incident Evaluation and Communication rules are generated and published as described above; they are not sent. The FedRAMP Security Inbox (FSI) is simulated for this proof of concept: no mail is received or sent, and its published contact directs FedRAMP to the operator on LinkedIn (`docs/runbooks/fedramp-security-inbox.md`).

