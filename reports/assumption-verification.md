# Assumption Verification Report

Phase 1 of the OPA-gate showcase refactor. Every claim from the external static
review was re-verified locally against commit `678ec21` (branch point of
`refactor/opa-showcase`) with the repo's pinned OPA v0.57.0
(`/usr/local/bin/opa`, Build 2023-09-28).

Statuses: **CONFIRMED** (claim holds as written), **PARTIAL** (core holds,
details differ — recommendation adapted), **REFUTED** (claim does not hold —
dependent recommendation skipped or re-scoped).

| ID | Claim | Status | Evidence (command + output excerpt) | Dependent recommendations |
|----|-------|--------|-------------------------------------|---------------------------|
| A1 | `infrastructure/policies.rego` exists, is the **only** `.rego` in the repo, declares `package terraform.compliance`, pre-1.0 syntax | **PARTIAL** | `find . -name '*.rego'` → 5 first-party files (`infrastructure/policies.rego`, `infrastructure/policies_test.rego`, `policies/triage.rego`, `policies/triage_test.rego`, `scuba/policies/*.rego` ×2) plus ~300 generated `scuba/dist/policies/*.rego`. The target file itself matches the review exactly: line 17 `package terraform.compliance`; bracket-style partial sets (e.g. line 39 `missing_required_tags[tag] {`); no `if`, no `import rego.v1`. Line-precise matches for A3/A6/A8 (regex at line 230, union at line 318, `default compliant = true` at line 290) prove the review inspected **this exact file** — only the repo-wide "only .rego" conjunct is stale. | All. Adaptation: scope is `infrastructure/policies.rego` + its harness; `policies/triage.rego` is co-migrated in R1 **only** because CI tests it with the same pinned OPA binary (`deploy-with-opa.yml:136`). `scuba/` rego is not evaluated by this workflow and is untouched. |
| A2 | OPA v0.57.0 pinned in README/scripts/CI | **CONFIRMED** | `grep -rn "0\.57" README.md scripts/ Makefile .github/` → 5 hits: `README.md:301`, `scripts/terraform-plan.sh:32`, `scripts/deploy.sh:37`, `.github/workflows/deploy-with-opa.yml:78` (`OPA_VERSION: 0.57.0`), `Makefile:33`. | R1 |
| A3 | `alt`-text rule uses RE2-rejected lookahead `(?!alt=)`; silently never fires by default; errors under `--strict-builtin-errors` | **CONFIRMED** (dynamic repro) | Pattern at `policies.rego:231`. Fixture `{"html_content": "...<img src=\"x\">...", "file_name": "t.html"}`: default eval → `compliant: True, violations: []` (no `missing_alt_text`); with `--strict-builtin-errors` → `regex.find_all_string_submatch_n: error parsing regexp: invalid or unsupported Perl syntax: '(?!'` at row 230. Silent false pass confirmed. | R7, R8 |
| A4 | Bespoke input contract: rules read pre-flattened `input.resource` with synthesized fields, produced by a wrapper | **CONFIRMED** | 20 `input.resource.*` references in the rego. Flattener is an inline Python heredoc in `scripts/terraform-plan.sh` (lines 94–193): reads `tfplan.json` (`terraform show -json`), synthesizes `versioning_enabled` / `encryption_enabled` / `public_access_blocked` by joining `aws_s3_bucket_versioning` / `..._server_side_encryption_configuration` / `..._public_access_block` sub-resources on substring bucket-name match, then evals OPA **once per resource** (line 218). | R2 |
| A5 | README pipes raw `terraform show -json` into `opa eval` → vacuous `compliant: true` | **CONFIRMED** (dynamic repro) | `README.md:266–267` shows exactly that pipe. Synthetic raw-plan fixture (an S3 bucket with no tags, no versioning, no encryption — should be maximally non-compliant) → `compliant: True, total_violations: 0`. Fail-open reproduced. | R2 |
| A6 | `all_violations` = hardcoded union of exactly 4 sets; `compliant` = `default true` + 4 `false` overrides | **CONFIRMED** | `policies.rego:290` `default compliant = true`; lines 293–309 four `compliant = false { count(...) > 0 }` rules; line 318 `all_violations := ((s3_bucket_violations \| cloudfront_violations) \| accessibility_violations) \| classification_violations`. | R4 |
| A7 | Runtime Lambda **re-implements** the rules in JavaScript (no Wasm, no OPA runtime) | **REFUTED** | `infrastructure/lambda/index.js:26` `require('@open-policy-agent/opa-wasm')`; lines 72–78 load `policy.wasm` bundled by CI (`deploy-with-opa.yml:267` and `:462` run `opa build -t wasm -e terraform/compliance/compliance_report`). No JS rule logic exists — the Lambda only flattens AWS API responses into the `input.resource` shape and calls `policy.evaluate()`. The review's source was the **stale doc line** `docs/ksi-signal.md:222` ("Runtime emitter ports the same rules to JavaScript"), which no longer matches the code. | R5 → re-scoped: Wasm single-artifact is already shipped; remaining work is a CI parity test (CLI eval vs. Wasm eval over the fixture corpus) + fixing the stale doc line. |
| A8 | Scope asymmetries: 4 governance tags only in `s3_bucket_violations`; `aws_cloudfront_distribution` missing from `taggable_types`; TLS equality-pin vs "or higher" message; misplaced comment | **CONFIRMED** (with intent evidence on one item) | (1) `missing_required_tags` consumed only at `policies.rego:128` inside `s3_bucket_violations` — confirmed. (2) `taggable_types` (lines 65–77) has 11 types, no `aws_cloudfront_distribution` — confirmed; **however** the distribution is a *data source* in the gated stack (`infrastructure/main.tf:123` `data "aws_cloudfront_distribution"`; the managed resource lives in the operator-applied bootstrap stack), and data sources are excluded by `is_managed` — so its absence has a plausible rationale, though adding the type is harmless and future-proof. (3) Line 197 `!= "TLSv1.2_2021"` vs line 200 message "TLS 1.2 or higher" — confirmed. (4) Lines 302–305: comment "Block deployment if any accessibility violations are found" sits above the **classification** override — confirmed, pure comment bug. | R6 |
| A9 | A test harness exists (`scripts/test-policies.sh` and/or make target) — uncharacterized | **PARTIAL** | Two harnesses exist. (1) `scripts/test-policies.sh` (10 scenario cases + perf test) is **broken and cannot run**: every check reads `.result.compliant`, but `opa eval` outputs `.result[0].expressions[0].value.compliant`; first jq errors ("Cannot index array with string \"compliant\"") and `set -e` kills the script — exit 5 on test case 1. Not referenced by CI or Makefile; only by a README directory listing (`README.md:218`). (2) `opa test policies.rego policies_test.rego` (Makefile `validate`, CI `deploy-with-opa.yml:135`) runs and passes 7/7 — but covers **only** the PR-D classification gate. **Neither harness would have caught A3**: the rego tests don't touch accessibility rules, and the shell harness (whose case 7 *is* a missing-alt must-fire test) dies before reaching it. | R7 scoped: replace/supersede the broken shell harness; keep + extend the rego unit tests. |
| A10 | Machine-readable KSI→control catalog exists, parseable, feeds the OSCAL SSP generator (192 implemented-requirements) | **PARTIAL** (core confirmed; count stale) | `infrastructure/schemas/ksi-catalog.json`: parses, 10 KSI families, each indicator carries `controls: [{control_id, title}]` (209 distinct 800-53-style IDs). `scripts/build-oscal-ssp.py:12` names it as input. But the published SSP has **331** implemented-requirements, not 192 (`python3 -c "...len(reqs)"` → 331) — the review's number predates the CR26 work. | R3 (CI diff target confirmed usable) |

## Gating outcome

- **A1 is PARTIAL, not REFUTED** — the review demonstrably targeted this repo
  state's gate file (four independent line-precise matches). Proceeding, with
  the scope adaptation recorded above.
- **A7 REFUTED** → R5 is re-scoped (see table): the recommendation's end state
  (one Rego artifact, executed at both enforcement points via Wasm) already
  ships in production. What survives of R5 is its parity-test requirement and
  a fix for the stale `docs/ksi-signal.md` line that misled the review.
- All other recommendations proceed, adapted where noted.

## Additional constraints discovered (not in the review)

These are facts the refactor must respect; recorded here so Phase 3 decisions
are traceable:

1. **`validations.json` is a load-bearing contract.** `scripts/terraform-plan.sh`
   emits it; `scripts/build-ksi-signal.py:1131` (`build_validations`) and
   `scripts/build-vdr-report.py` (`--opa validations.json`) consume it. Its
   `results[]` entry shape (`kind`, `resource_type`/`resource_name` or
   `file_name`/`file_path`, `compliant`, `violations[]`, `policy_version`) must
   survive the refactor. The published KSI-signal schema requires violation
   objects to keep `type`/`message`/`severity` (severity enum
   LOW/MEDIUM/HIGH/CRITICAL) but allows additional fields
   (`additionalProperties: true`) — so R4's uniform violation object must be a
   superset, not a replacement.
2. **The Wasm entrypoint is referenced in two workflow steps**
   (`deploy-with-opa.yml:267`, `:462`) and the Lambda feeds it single-resource
   input `{resource: {...}}`. Any repackaging must keep an entrypoint that
   accepts that input shape and returns the `compliance_report` fields the
   Lambda reads, and both `-e` flags must be updated in lockstep.
3. **`policies/triage.rego` + tests run under the same pinned OPA binary in CI**
   (`deploy-with-opa.yml:136`) and use v0 syntax (`import future.keywords.in`,
   no `if`). Bumping the pin to 1.x without migrating them breaks CI. They are
   co-migrated in R1.
4. **The root `Makefile` is written to run from `infrastructure/`** (relative
   `policies.rego`, `./terraform-plan.sh` paths) but lives at the repo root, and
   the README says `cd infrastructure && make pipeline`. As-is, several targets
   are not copy-paste runnable. Fixed as part of the docs pass (Phase 4).

## Tool environment recorded for this phase

| Tool | Version | Source |
|------|---------|--------|
| opa | 0.57.0 (repo pin) | `/usr/local/bin/opa`, matches all five pin sites |
| terraform | not exercised (no plan/apply run in Phase 1; fixtures are synthetic) | — |
| python3 | 3.13.12 | system |
| node / npm | v22.16.0 / 10.9.2 | system (used later for Wasm parity + scanner) |
| chromium | present at `/usr/bin/chromium` | system (enables local pa11y runs for R8) |
