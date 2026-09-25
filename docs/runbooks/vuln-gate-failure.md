# Runbook: the vulnerability gate failed

The vulnerability gate (`scripts/vuln-gate.py`) fails a run when a scanner reports a vulnerability that is neither fixed nor dispositioned in `data/vuln-dispositions.json`. It runs on every deploy and every night in `evidence-nightly.yml`. When it fails on the nightly, the published VDR stops refreshing, and the 24-hour reporting policy is breached one day later.

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

### False positive: the finding does not apply

The vulnerable code path is unreachable, the component is outside the authorization boundary, or the scanner misidentified the package. Add an entry to `data/vuln-dispositions.json`, keyed by the exact id the gate printed:

```json
"grype-GHSA-xxxx-xxxx-xxxx-pkg:npm/example@1.2.3": {
  "disposition": "false-positive",
  "justification": "Why it does not apply, specifically enough that a reviewer could check it.",
  "poam_ref": "POAM-0NN",
  "decided_by": "Sam Aydlette",
  "decided_on": "YYYY-MM-DD"
}
```

### Operational requirement: it applies, but it cannot be fixed yet

There is no upstream fix, and the component is needed. Use `"disposition": "operational-requirement"`, with a justification that names the compensating controls and the condition that will close it.

### Either disposition needs a POA&M entry

Both dispositions need a `poam_ref`. Add the item to `docs/poam.md` and mirror it in `scripts/build-oscal-poam.py`. The reconciliation gate checks that the two agree (invariant g) and that every dispositioned finding is covered (invariant h). Change both together.

Plain risk acceptance does **not** pass the gate. Only `false-positive` and `operational-requirement` do.

## 3. Mind the clock

Remediation timeframes follow FedRAMP 20x VDR-TFR-PVR for Class C, encoded in `CLASS_C_SLA_DAYS` in `scripts/build-vdr-report.py` and summarized in `docs/continuous-monitoring-plan.md`. The clock runs from first detection, which the VDR's first-detected ledger records. A KEV-listed or internet-reachable high-PAIN finding has days, not weeks.

## 4. Close the loop

- Once a nightly passes, close the alert issue.
- When a fix removes a package that had a disposition, delete the now-dead entry from `data/vuln-dispositions.json` and close its POA&M item, so the register describes the system as it is.

## Why the drift check still ran

The nightly's reconciliation gate (the live comparison of the site against its documentation) runs even when the vulnerability gate fails. Publishing still waits for both. The alert reports each gate separately, so a vulnerability failure no longer hides a skipped drift check.
