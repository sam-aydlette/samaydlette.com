# Implementation Report — OPA Compliance Gate Showcase Refactor

Branch: `refactor/opa-showcase` (local only, not pushed). One commit per
phase/recommendation. Companion document: `reports/assumption-verification.md`
(Phase 1 evidence). Everything marked **PROPOSED — needs human review** is my
judgment, not verified fact.

## Execution order

Implemented as R1 → R2 → R4 → R6 → R3 → **R9 → R8 → R7** → R5. The last four
deviate from the brief's stated order (R7 → R8 → R9 → R5) for two reasons,
both discovered during implementation:

1. **R8 before R7:** turning on `--strict-builtin-errors` everywhere (R7)
   while the A3 lookahead regex still existed would have made every HTML
   evaluation of a page containing `<img` a hard error — the broken builtin
   had to be deleted (R8) before strict errors could be global.
2. **R9 before R8:** the real pa11y scan of the live site found two genuine
   WCAG 2 AA failures (details under R8). One is a scanner false positive
   that had to be dispositioned through the exceptions mechanism — so the
   mechanism (R9) had to exist before the scanner (R8) could land with a
   green gate.

## Per-recommendation outcomes

### R1 — Migrate to OPA 1.x / Rego v1 — **DONE (scope adapted)**
`opa fmt --v0-v1` migration + compatibility-import drop; every 0.57.0 pin
(README, terraform-plan.sh, deploy.sh, Makefile, workflow `OPA_VERSION`)
replaced with **1.18.2**. Adaptation per A1-PARTIAL: `policies/triage.rego`
(+tests) co-migrated because CI evaluates it with the same pinned binary;
`scuba/` rego untouched (not evaluated by this workflow; already
v1-compatible via `future.keywords`). Verified: `opa check --strict` clean,
all tests pass, Wasm built by 1.18.2 executes under the Lambda's
`opa-wasm@^1.9.0`, and regenerating the golden corpus under 1.18.2 produced
**zero** behavioral deltas vs the 0.57.0 baseline. Note: `grep -rn "0\.57"`
still matches the frozen baseline goldens and the Phase 1 report — those are
historical records of the old pin, not executable pins; no executable
reference remains.

### R2 — Standard input contract — **DONE**
The policy consumes raw `terraform show -json` directly: iterates
`resource_changes`, gates only changes whose after-state exists (delete-only
changes skipped; replace/update/no-op/create kept), joins the provider-4.x
split S3 sub-resources in Rego — exact `bucket`-value match with a
`configuration.root_module.resources[].expressions.bucket.references`
fallback for names computed at apply time. **Documented limitation:** the
fallback only covers root-module resources; a module-nested bucket with a
computed name will not join and its synthesized security fields stay false —
the bucket *fails* the gate (fail-closed) rather than silently passing.
Unrecognized/empty input yields `input_error` + non-compliant. JSON Schema
for all input shapes at `infrastructure/schemas/policy-input/gate_input.json`
wired via package METADATA and enforced with `opa check --strict --schema`.
The Python flattener inside `terraform-plan.sh` is deleted; the script is a
thin wrapper (plan → show → one strict eval → `validations.json`). The
README debug commands were re-tested verbatim after the change. The runtime
Lambda's single-resource input shape is unchanged and covered by fixtures.
Bonus fix found while testing: a nameless resource used to make the violation
object undefined and vanish; normalization now guarantees `name`/`address`.

### R4 — Package-per-domain, uniform violations, fail-closed — **DONE**
`infrastructure/policies.rego` became `infrastructure/policy/`: `policy.gate`
(the only package that reads raw input), `policy.terraform.s3`,
`policy.terraform.cloudfront`, `policy.tagging`, `policy.accessibility`, and
the `terraform.compliance` aggregator. Uniform violation object:
`{id, type (legacy alias), category, severity, control_ids, ksi_ids,
resource, address, message}` — a strict superset of the published KSI-signal
violation shape (`additionalProperties: true` there). Aggregation is a
`walk(data.policy)` over every `violations` set: proven with a live dummy
package (appeared with zero aggregator edits, removed after) and pinned by a
unit test injecting a mock package. Decision flipped to
`default compliant := false` + one positive rule (valid input ∧ zero active
violations). **Convention discovered and documented:** test packages must
live outside `data.policy` (the walk makes an inside test package statically
recursive). The Wasm entrypoint path and all downstream report shapes are
unchanged.

### R6 — Parameters as data — **DONE (one A8 item deliberately not "fixed")**
All enforcement parameters live in `infrastructure/policy/config/data.json`
(with an explicit 800-53 ODP comment in `tagging.rego`). TLS is an ordered
minimum: `tls.order` ranks CloudFront policy names, anything at/above
`tls.minimum` passes, unknown names fail closed; tests prove a hypothetical
stronger policy passes via a data-only change. A config guard fails the gate
closed on a missing/partial parameter document — including the Wasm host
never calling `setData`, which *did* evaluate to a silent pass until the
guard's absent-document rule was added (found by testing exactly that case).
The Lambda now ships `policy-data.json` from the bundle and loads it.
A8 fixes: governance tags now enforced uniformly across all taggable types
(five `main.tf` resources gained the missing `CostCenter` tag — verified
with offline `terraform validate`; the Silk Reeling resources already
carried all four via `local.silk_tags`, contrary to my first scan); the
TLS message now matches the check; the misplaced comment is gone with the
restructure. **`aws_cloudfront_distribution` was NOT added to
`taggable_types` — documented intent found:** the gated stack's distribution
is a data source (bootstrap owns the managed resource), and
`lambda/index.js` explicitly documents that the Lambda's role lacks
`cloudfront:ListTagsForResource`, so adding the type would turn every runtime
signal red. Recorded as deliberate scope in `tagging.rego` with the flip
procedure (grow role + transformer, then edit config).

### R3 — Control traceability via METADATA — **DONE**
Every violation rule carries METADATA `custom:` fields (`id`, `category`,
`severity`, `nist_controls`, `ksi_ids`; Section 508 rules declare
`framework: section-508` with empty NIST lineage). Violations are built from
`rego.metadata.rule()` through a shared constructor — verified the lineage
survives Wasm compilation (the Lambda's findings carry it).
`scripts/check-policy-annotations.py` diffs annotations against
`ksi-catalog.json` in CI: unknown KSIs, controls not carried by the declared
KSIs, orphan control claims, and missing fields all fail (failure mode
proven with a deliberately wrong annotation, then reverted). All mappings
are **PROPOSED** (see below).

### R7 — Tests and linting as exhibits — **DONE**
50 rego unit tests across per-package `*_test.rego` files with must-fire
negatives for every rule (including absent-field fail-closed postures);
`tests/test_policy_gate.py` runs the full plan-fixture corpus through the
gate with `--strict-builtin-errors` in the existing CI pytest job and pins
verdicts + violation ids + the uniform violation contract. CI enforces:
`opa fmt --fail`, `opa check --strict --schema`, `opa test --coverage
--threshold 90` (actual: **97.1%**), Regal **0.41.1**
(`open-policy-agent/regal` — the project moved from StyraInc; verified) at
**zero findings** — 89 initial findings: ~15 real style/idiom issues fixed
(including one true simplification bug-risk, the superfluous `object.get`),
and three categories ignored with written justification in
`.regal/config.yaml`. The broken `scripts/test-policies.sh` (A9: died on its
first jq expression, never ran in CI) is deleted and superseded.
**A3-reintroduction experiment** (scratch, not committed): re-adding the
lookahead regex was caught statically by Regal (`bugs/invalid-regexp`) and
dynamically by the strict-errors corpus test — while plain `opa test` still
passed 50/50 because no unit test exercised the new rule. That is the
lesson: must-fire tests protect known rules; the linter and strict-error
evals protect against unknown broken ones.

### R8 — HTML checks out of Rego — **DONE**
The five string/regex rules are deleted (including the dead lookahead rule
and the WCAG-inverting `alt=""` rule — `decorative-empty-alt.html` now
correctly passes). pa11y **9.1.1** (pinned, `tools/a11y/`, WCAG 2 AA via
HTML_CodeSniffer in headless Chromium) produces one JSON facts document;
`policy.accessibility` decides over it — fail-on issue types are config, one
violation per (page, WCAG code) so exceptions can be code-precise. The
pattern is named in both the scanner and the policy: **scanners produce
facts, OPA decides.** The wrapper fails closed when the scanner is
unavailable (`SKIP_A11Y=1` is the explicit local opt-out; CI installs the
scanner against the runner's system Chrome with `PUPPETEER_SKIP_DOWNLOAD`).
The retired `{html_content, file_name}` input shape is now an `input_error`.
Scanning the real site (43 pages) found two genuine WCAG failures the old
string checks could not see:
1. `pages/articles.html` — search input with no accessible name → **fixed**
   (`aria-label="Search articles"`).
2. `silk-reeling-mirror.html` — two contrast failures on `aria-hidden`
   decorative dot separators → **false positive** per WCAG 1.4.3's
   pure-decoration exemption; dispositioned as POAM-033 (poam.md False
   Positives + the OSCAL POA&M generator) and suppressed via the exceptions
   register (expires 2027-01-15), still visible under `excepted`.
   **PROPOSED:** the FP classification and the expiry date are my judgment.

### R9 — Exceptions-as-code — **DONE**
`infrastructure/policy/exceptions/data.json`: `{resource, rule_id,
justification, expiry, ticket}` (+ optional `code` for finding-level
precision). Suppression happens only in the aggregator; rules keep reporting
raw facts; suppressed findings stay in the report under `excepted` with the
exception that silenced them. Expiry is checked against
`data.runtime.evaluated_at` (supplied as *data* by the wrapper and the
Lambda — inputs stay pure, evaluation stays deterministic/Wasm-clean); no
timestamp or past expiry ⇒ no suppression (fail-safe), and
`scripts/check-exceptions.py` fails CI on expired/malformed entries.
Cross-linked from `docs/poam.md` as POA&M-as-code. Tests cover active
suppression, excepted-visibility, expiry resurfacing, missing-timestamp
fail-safe, and code-scoped precision.

### R5 — One artifact, two enforcement points — **ADAPTED (A7 refuted)**
The recommendation's end state already ships in production: CI compiles
`infrastructure/policy/` to Wasm and the Lambda executes it via
`@open-policy-agent/opa-wasm`; there is no JS rule logic to delete. The
review was misled by a stale line in `docs/ksi-signal.md` ("Runtime emitter
ports the same rules to JavaScript") — now corrected, along with a matching
stale comment in `scripts/deploy.sh`. What survived of R5 is its parity
requirement, implemented as `scripts/policy-parity-test.js`: the full
fixture corpus through both the OPA CLI and the compiled Wasm, full-report
diff, wired into CI immediately after the exact Wasm that ships is built.
**It found a real divergence on first run:** `sprintf("%v", set)` renders
differently in the Go runtime vs the Wasm JS host (and `%q` throws outright
in the JS host — hit separately during R6 testing). Both fixed in Rego;
parity is green across the corpus. The `compliance_report` entrypoint also
carries `entrypoint: true` METADATA.

## Behavioral deltas vs the frozen baseline (`tests/golden/baseline/`)

Post-refactor goldens: `tests/golden/current/` (regenerate with
`tests/golden/regen-current.sh`). Every delta is intentional:

| Delta | Where | Rationale |
|---|---|---|
| Raw plan JSON evaluated directly now yields real verdicts (baseline: vacuous `compliant: true` for **every** fixture, incl. maximally non-compliant ones) | all `plan-*` goldens | R2 — the fail-open README debug path is now the *only* path |
| Empty/garbage input → `compliant: false` + `input_error` (baseline: vacuous pass; the old flattener crashed outside OPA) | `plan-empty`, `plan-garbage` | R2 input guard |
| `missing-alt` page now fails (baseline: silent pass — dead regex) | a11y goldens | A3 fix via R8 |
| `empty-alt` on a decorative image now **passes** (baseline: failed; the old rule inverted WCAG) | a11y goldens | R8; pa11y implements WCAG correctly |
| `missing-doctype` / `missing-h1` no longer fail per se (not WCAG 2 AA error-level conformance failures) | a11y goldens | R8 — scope now = WCAG 2 AA errors; old checks were bespoke |
| `{html_content, file_name}` input shape retired → `input_error` | a11y goldens | R8 — scanner facts replaced raw HTML input |
| Violation objects gained `id`, `category`, `control_ids`, `ksi_ids`, `address`; messages for tag sets are now sorted/comma-joined; TLS message names the configured floor | all goldens | R4/R3/R5-parity; superset of the published schema shape |
| `compliance_report` gained `excepted`; counts/violations reflect active (non-excepted) findings; `violations_by_type` gained `input` | all goldens | R9/R4 |
| Governance tags enforced beyond S3 (uniform across taggable types, `tags` or `tags_all`) | `missing-classification`-class fixtures, live plan | R6/A8 — with matching `main.tf` tag additions so the real stack stays green |
| Stronger-than-floor TLS policy passes after a config append; unknown policy names fail | cloudfront goldens | R6 ordered minimum |
| `policy_version` `"1.0"` → `"2.0"` | everywhere | input contract + decision-polarity change |
| Nameless resources no longer evade violation reporting | resource goldens | R2 normalization fix |

Unchanged by design (verified): every legacy single-resource (Lambda-shape)
fixture verdict matches baseline; `compliant-stack`, `data-source-website-
bucket` (documented runtime-covered blind spot), and `delete-only` keep
their verdicts for the right reasons rather than vacuously.

## Tool versions (pinned)

| Tool | Version | Where pinned |
|---|---|---|
| OPA | 1.18.2 (was 0.57.0) | workflow `OPA_VERSION`, README, Makefile, terraform-plan.sh, deploy.sh |
| Regal | 0.41.1 (`open-policy-agent/regal`) | workflow `REGAL_VERSION` |
| pa11y | 9.1.1 (exact) | `tools/a11y/package.json` + lockfile |
| @open-policy-agent/opa-wasm | ^1.9.0 (pre-existing) | `infrastructure/lambda/package.json` |
| node (scanner/parity) | >= 20 (engines) | `tools/a11y/package.json`; CI runner node |
| Verification-only (not pinned in repo) | terraform 1.6.3-dev, python 3.13.12, chromium (system) | local validation |

## PROPOSED — needs human review

1. **Every rule→KSI→NIST mapping** in the METADATA annotations
   (`s3.rego`, `cloudfront.rego`, `tagging.rego`, `gate.rego`). The CI diff
   guarantees *consistency with the catalog*, not correctness of my choices.
   Notable judgment calls: versioning → KSI-RPL-ABO (cp-9/cp-10/si-12);
   input_error → KSI-PIY-RSD (si-10); config_error → KSI-MLA-EVC (cm-6/ca-7).
2. **Severity assignments** — carried over from the pre-refactor strings, now
   authoritative in METADATA.
3. **POAM-033 disposition** (contrast FP per WCAG 1.4.3) and its 2027-01-15
   expiry; also the `DataClassification`/`CostCenter` values added to five
   `main.tf` resources.
4. **Fixture realism** — all plan fixtures are synthetic (no credentials →
   no real plan). Modeled on terraform 1.9.x / provider-4.x output and the
   resource layout observed in public CI logs; labeled in each `_fixture`
   block. A real `terraform show -json` capture would be a strictly better
   fixture source.
5. **`reports/` publicity** — this report and the Phase 1 report are
   committed per the task brief; the repo is public, so decide whether they
   ride along in any pushed branch/PR or stay local.

## Known local-environment caveat (not caused by this branch)

`pytest tests/` locally fails `test_inject_figures.py::test_published_targets_are_current`:
an **untracked** stale build artifact (`infrastructure/oscal-ssp.json`, June 29,
333 requirements — Phase-2/CR26 local work) disagrees with the published SSP
(331) that README correctly cites. Evidence it predates this branch: artifact
mtime, and published/README agree with each other. In CI the artifact either
doesn't exist (test skips) or is regenerated fresh. Everything else: 164/165
pass, and the full CI-equivalent policy suite is green end-to-end.

## Follow-ups recommended (not done)

1. **CloudFront tag scope flip:** grant the Lambda role
   `cloudfront:ListTagsForResource`, grow the transformer, then add
   `aws_cloudfront_distribution` to `taggable_types`/`governance_tag_types`
   in config (a data-only change once live tags are verified).
2. **Deploy-time blind spot:** the website bucket is a data source, so the
   deploy gate never evaluates it (runtime Lambda covers it). Consider a
   deploy-time live-read check or importing the bucket.
3. **Signal enrichment:** `build-ksi-signal.py` still maps KSI status at
   family level; violations now carry per-rule `ksi_ids` that could drive a
   finer per-indicator status.
4. **Runtime `excepted` surfacing:** the runtime signal could publish the
   `excepted` list for full external auditability of active exceptions.
5. ~~Checksum-pin the Regal/OPA binaries in CI~~ — **done in the CodeGuard
   remediation commit** (see below).
6. ~~Run CodeGuard against the branch diff~~ — **done**; findings and
   dispositions below.

## CodeGuard security review of the branch diff

Run post-implementation over `git diff main...HEAD` (Project CodeGuard
software-security skill). Scans clean: no hardcoded credentials (the only
account id in fixtures is the AWS documentation placeholder, labeled), no
injection patterns (no shell=True/eval; execFileSync list-form; all shell
expansions quoted; jq fed via --arg/--argjson only), TLS floor consistent
with modern-crypto guidance, no new workflow permissions or secret usage,
and fail-closed behavior at every error path. Findings and dispositions:

1. **FIXED — real bug caught:** the workflow already pinned the OPA binary
   by SHA-256, and the R1 version bump updated `OPA_VERSION` but not
   `OPA_SHA256` — every CI job would have failed (closed) at the checksum
   step. Updated to the published v1.18.2 hash, verified against the exact
   binary used for all of this branch's local verification.
2. **FIXED:** the new Regal download step lacked the checksum verification
   the OPA steps have — added `REGAL_SHA256` (from the release's
   checksums.txt) + `sha256sum -c`. The operator-run install paths
   (deploy.sh, Makefile, README quickstart) now verify the OPA hash too.
3. **FIXED:** `npm ci` for the scanner in the credentialed compliance job
   now runs `--ignore-scripts` — none of pa11y's 113 transitive packages
   can execute lifecycle scripts there (re-verified the scanner works when
   installed this way).
4. **Recorded, not changed (informational):** pa11y executes scanned pages'
   JavaScript in headless Chromium inside the credentialed compliance job.
   Exposure is limited — the workflow triggers on `pull_request` (fork PRs
   receive no secrets), so only content from write-access authors is
   rendered, and CI Chromium keeps its sandbox (`--no-sandbox` is a local
   opt-in only). Defense-in-depth option if wanted: move the scan to an
   uncredentialed job that publishes the facts document as an artifact.
5. **Recorded, not changed (by design):** the exceptions register is a
   policy-suppression path gated by PR review. That is the design —
   suppressions are diffable, expire, fail CI when stale, and stay visible
   under `excepted`.
