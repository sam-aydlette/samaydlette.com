# Pitfalls that have already happened

Each entry: what went wrong, and the rule that now prevents it. Check your plan against this list. Add an entry when a new failure teaches a rule; delete one when the code makes it impossible.

## Evidence and publishing

- **Twelve days of stale evidence passed with every gate green.** A scheduled deploy could only queue at the `prod` approval gate, and nothing checked staleness. Reconciliation's `check_f_freshness` only asserts that the staged signal carries the current commit and has an `emitted_at`; it never looks at the live edge.
  Rule: don't mistake (f) for a freshness check. Freshness is enforced by `freshness-config.json`, the watchdog and `scripts/check-evidence-freshness.py`. `deploy-with-opa.yml` has no `schedule:` trigger; don't add one.
- **Local publishing bypassed the gate** and put a partial, unsigned artifact set over the live evidence.
  Rule: there is no local publish path. `make -C infrastructure deploy` refuses. Publishing happens only in CI, behind the gate and the `prod` approval.
- **The old `deploy` target synced the wrong directory with `--delete`.** It removed the whole site and the published evidence.
  Rule: same as above. The CI sync uses `website/` with `--exclude ".well-known/*"`.
- **Content sync overwrote the RA-5(6) vulnerability trend ledger, and a deploy deleted published evidence mid-run** (fixed 2026-08-06).
  Rule: anything that writes the bucket must leave `.well-known/` to the signed, post-gate publish step.
- **Same-day fixes after the CR26 merges (2026-11-05).** Six fix PRs followed large changes. The AWS account ID reached published output. The redaction gate scanned the working directory instead of what the deploy publishes. Published claims were wrong: directory URLs returned 404, the CPO logo URL didn't exist, the VDR markdown printed contradictory counts, and every policy carried the deploy date. Missing COEP headers were caught by ZAP.
  Rule: keep changes small (CLAUDE.md §4). When a change alters what is published, verify the published set itself. `tests/test_published_claims.py` and `scripts/check-published-redaction.py` now hold these.

## Infrastructure

- **`make -C infrastructure pipeline` is not a verification step.** It ends in `apply-infra`, which runs `terraform apply` against production.
- **A bootstrap apply from a stale tree reverts merged changes.** A merged `tag:GetResources` grant would have been undone this way.
  Rule: sync `infrastructure/bootstrap/` to `origin/main` before editing and before applying. The plan must show only your change.
- **A bootstrap apply during an in-flight deploy (2026-10-05)** published a trust center whose "pending trust-root changes" predated the apply.
  Rule: apply first and then deploy, or let the run finish and redeploy.
- **Narratives drifted from deployed config.** Baseline text was out of step with DNSSEC being on and with 365-day CMK log retention (fixed 2026-07-09).
  Rule: narrative must match config. Change both in the same PR.

## Tooling

- **A stale `opa` binary silently shrinks the policy suite.** An older `opa` can't parse these Rego v1 policies, and it *skips* about 15 policy tests instead of failing.
  Rule: check `opa version` against `OPA_VERSION` in `deploy-with-opa.yml` if `test-policies` looks suspiciously green.
- **Vendored FedRAMP schemas are byte-pinned.** The loader refuses any file whose hash differs from `SOURCES.json`. Never edit one, even to fix a typo.

## Settled decisions: don't "fix" these

- **WAF is intentionally declined.** SC-7 and SC-5 are met through managed interfaces (CloudFront and API Gateway), AWS Shield Standard and throttling. A WAF's incremental layer-7 filtering is documented as the residual. Don't re-add it.
- **CI proves compliance, not article content.** The prose checks were removed from CI (#356). The long-form checks in `tools/essay/` stay local-only.
- **Parked code doesn't come back as a side effect.** Don't revive a removed generator while doing another change.
- More settled decisions live in `docs/architecture-decisions.md`. Read the relevant section before proposing a change to the same area.
