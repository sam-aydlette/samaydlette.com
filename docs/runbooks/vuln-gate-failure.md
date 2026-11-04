# Runbook: the vulnerability gate failed

The vulnerability gate (`scripts/vuln-gate.py`) fails a run when a scanner reports a vulnerability that is neither fixed nor covered by an in-force decision in `data/decisions.json`, the decision register. It runs on every deploy and every night in `evidence-nightly.yml`. When it fails on the nightly, the published VDR stops refreshing, and the 24-hour reporting policy is breached one day later.

A failing gate is not an outage. It is the system refusing to publish evidence that is out of date with respect to a known vulnerability. The job is to make the finding go away honestly: fix it, or record why it does not apply.

## 1. Read the finding

The alert issue lists each finding the gate named, for example
`grype-GHSA-2883-xcg3-v3hh-pkg:npm/js-yaml@4.3.1`. For each one:

- **Which tree is it in?** The nightly scans four trees at the *published* inventory's commit, not `main`: the Silk Reeling Python dependencies, the Silk Reeling frontend, the compliance Lambda (`infrastructure/lambda`), and the a11y scanner (`tools/a11y`). `npm ls <package>` or the lockfile tells you which one pulls it in, and through what.
- **What is the advisory?** Open `https://github.com/advisories/<GHSA-id>`. Note the severity and the first patched version, if there is one.
- **Does it matter here?** Runtime or build-time? Reachable from the internet? Is it in CISA KEV? These set the remediation clock below.

## 2. Choose one outcome

### Fixed: preferred whenever a fix exists

- Check the alert for an open Dependabot PR on the package, and merge it if CI is green.
- If there is no PR, bump the package or its parent yourself and regenerate the lockfile.
- The fix reaches the nightly only once it is **deployed**. The nightly scans the published inventory's commit, so a merged-but-undeployed fix keeps failing. Approve the deploy.
- Sometimes a parent upgrade removes the vulnerable package entirely: pa11y 10 dropped js-yaml and extract-zip. That counts as fixed.

### Record a decision: the finding does not apply, or cannot be fixed yet

Add a record to `data/decisions.json` with the next free `DEC-NNN` ID. Put the exact ID the gate printed in `applies_to.vuln_ids`:

```json
{
  "id": "DEC-0NN",
  "title": "One line naming the finding",
  "status": "in-force",
  "disposition": "false-positive",
  "justification": "Why it does not apply, specifically enough that a reviewer could check it.",
  "decided_by": "Sam Aydlette",
  "decided_on": "YYYY-MM-DD",
  "review_by": "YYYY-MM-DD (one year later)",
  "original_detection_date": "YYYY-MM-DD",
  "applies_to": {"check_ids": [], "vuln_ids": ["grype-GHSA-xxxx-xxxx-xxxx-pkg:npm/example@1.2.3"], "resources": []}
}
```

The dispositions that pass the gate (`PASS_DISPOSITIONS` in `scripts/vuln-gate.py`):

- `false-positive`: the reason it is not exploitable lies inside the scanned artifact. A false positive whose reason is a control elsewhere is refused; record it as `mitigated`.
- `mitigated`: a control protects it. Name the mitigation record from `data/mitigations.json` in `vuln_fields.mitigation`.
- `vendor-dependency`: the fix has to come from upstream. It lapses when a fix appears.
- `operational-requirement`: it applies and the component is needed. The justification names the compensating controls and the condition that will close it.
- `accepted`: it will not be fixed. The justification is the acceptance explanation.

`under-investigation` and `remediate` are recorded but do not pass.

The loader (`scripts/_decisions.py`) refuses an in-force record without `decided_by`, `decided_on` and `review_by`, and an ID claimed by two in-force records. A record past `review_by` is lapsed: the VDR builder and the gate treat it as absent. The VDR finding carries the record's ID as `decision_id`, and reconciliation invariant (h) fails any finding whose `decision_id` does not resolve to an in-force record.

## 3. Mind the clock

Remediation timeframes come from FedRAMP's machine-readable rules (VDR-TFR-PVR, Class C), read by `scripts/_rules.py`, and are summarized in `docs/continuous-monitoring-plan.md`. The clock runs from first detection, which the VDR's first-detected ledger records. A KEV-listed or internet-reachable high-PAIN finding has days, not weeks.

## 4. Close the loop

- Once a nightly passes, close the alert issue.
- When a fix removes a package that had a disposition, close its record in `data/decisions.json` (`status: closed`, `disposition: remediated`, `closed_on`), so the register describes the system as it is.

## Why the drift check still ran

The nightly's reconciliation gate (the live comparison of the site against its documentation) runs even when the vulnerability gate fails. Publishing still waits for both. The alert reports each gate separately, so a vulnerability failure no longer hides a skipped drift check.
