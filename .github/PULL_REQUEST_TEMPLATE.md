<!--
PR template. The SCN-Type line below is REQUIRED and is enforced by CI per the
FedRAMP 20x Significant Change Notification rules (SCN-CSO-EVA, SCN-CSO-MAR).
The line is verified by the workflow at .github/workflows/scn-tag.yml — a PR
that omits it or uses an unrecognized value will fail the gate.
-->

## SCN-Type: routine-recurring

<!--
Pick one of: adaptive | routine-recurring | transformative

Categorization criteria (from SCN-CSO-EVA + the per-tier "key tests" in the
FedRAMP 20x SCN rules):

- routine-recurring (default): minor incremental work performed regularly —
  patching, configuration tuning, content updates, dependency bumps with no
  breaking changes, vulnerability remediation that swaps a known-bad component
  for a known-good one. Exempt from formal Significant Change Notifications
  per SCN-RTR-NNR. This is the default; do not change unless your change is
  larger than this.

- adaptive: a change that requires careful planning but does not rise to a
  transformative-class change. Examples: deploying a multi-week feature
  improvement, OS/container/library upgrades with breaking changes,
  swapping a like-for-like component where some procedures need adjustment.
  Notification within 10 business days after finishing per SCN-ADP-NTF.

- transformative: alters the system's risk profile or significantly changes
  customer responsibilities. Examples: replacement of a critical third-party
  service, migration across cloud regions or providers, paradigm shift in
  workload orchestration. 30 / 10 / 5 business-day notification chain per
  SCN-TRF-NIP / SCN-TRF-NFP / SCN-TRF-NAF.
-->

## What this PR does

<!-- A short description of the change. -->

## Customer impact

<!-- "None" is a valid answer for this single-system PoC. -->

## Test plan

<!-- How you validated this PR. -->
