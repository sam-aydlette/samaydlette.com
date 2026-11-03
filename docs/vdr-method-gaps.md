# VDR method gaps register

Gaps between the method in `website/research/vulnerability-evidence.html` ("Vulnerability Evidence as a Product") and this repo's pipeline. The article defines the method; where they differ, this register records the difference and a recommendation. Sam decides each one.

- **Code audited:** `bc4e00d` (origin/main, 2026-11-03).
- **Live report used for effects:** `/.well-known/vdr-report.json`, emitted 2026-11-03T15:05:42Z. It has 38 findings (32 Checkov, 6 tfsec), every one dispositioned (35 false-positive or risk-accepted in findings, plus 3 records in `risk_accepted`); 0 open, 0 blocking, 0 Grype findings, 0 CVSS vectors.
- **How it was audited:** read-only. The 17 gaps from the 2026-11-02/03 review were re-checked by reading code; every other Appendix A requirement was audited in three groups; decisive citations were spot-checked by re-reading the line or running the function.
- **Labels.** *Verified* = read in code or the live artifact. *Inference* = reasoned, not tested. Line numbers are at `bc4e00d`.
- **Size:** S under a day, M a few days, L an architecture change.
- **Recommendation:** *Fix code*, *Change article*, *Document gap* (keep, state it publicly), or *Decide* (a method decision for Sam).
- Drafted by Claude for Sam's review. Recommendations are proposals, not decisions.

## 1. Corrections to the 17-gap list

Only corrections. Everything not listed here was confirmed as written.

| Gap | Correction |
| --- | --- |
| 4 | The inference is now verified. Today's FIRST feed starts with `#model_version:v2026.06.15,score_date:2026-11-03T12:00:27Z`; `build-vdr-report.py:823` skips every `#` line. The feed URL now redirects to `epss.empiricalsecurity.com`. |
| 5 | Wider than listed, and partly in the unsafe direction. Running `is_internet_reachable()` on inventory resources: `aws_cognito_user_pool.silk_reeling` → False (inventory says True, `build-ksi-signal.py:669`); `aws_lambda_function.silk_reeling` → False (inventory override True, `:691`; the hint `silk-reeling` has a hyphen, Terraform uses `_`); `aws_s3_bucket_public_access_block.logs` → True (inventory False). Component resolution also falls back to substring matching (`build-vdr-report.py:1102-1107`), and unresolved findings are not queued. |
| 7 | Now established; see N-G4/G5 below. Nothing compares declared reachability with observed exposure. The nearest pieces: `reconcile.py --live` (a) every live ARN is in the inventory and (i) live tags equal the inventory, both fail-closed on deploy and nightly; `check-runtime-divergence.py` blocks the next deploy on a "diverged" runtime signal (S3 and CloudFront settings only); `corroborate.py` is operator-run and never fails anything; ZAP is monthly, `fail_action: false`, and `security/zap/` currently holds only a README, so DAST contributes nothing. |
| 13 | Confirmed, and stronger: no maximum-overdue logic exists anywhere in `scripts/`. |
| 14 | Extended. Same reset also hits the other `risk_accepted` records (`:1398`); live: all 3 records carry `first_detected` = `emitted_at`. Separately, the ledger carries clocks only by `tracking_id`, and tfsec/Checkov IDs embed a line number or location (`:587`, `:457`), so editing a Terraform file restarts a finding's clock. See N-DLN-1. |
| 16 | Wider. Two more fetches fail open: the previous VDR (`deploy-with-opa.yml:1384`, `evidence-nightly.yml:425`; the nightly's own warning says "the SLA clock restarts for every finding this run") and Dependabot alerts (`deploy:1404`, `nightly:440`). Grype errors are swallowed by `|| true` (`nightly:401`, `deploy:999`), and there is no Grype DB age check. |
| 17 | Detail: `policies/triage.rego` is a full disposition chain (false-positive, operational-requirement, risk-adjustment, remediate) with historical and escalation layers. It is run only by `opa test` (`deploy:205`). |
| "Already matches" | Three items are weaker than listed. **REQ-GOV-1:** the build checks the PAIN config by hand-written key and range checks (`build-vdr-report.py:75-100`); full JSON-schema validation runs only in a test that uses `importorskip` (`tests/test_pain_config.py:103-106`). **REQ-DSP-1:** only the 2 register entries and 21 of 37 POA&M items carry `decided_by`/`decided_on`/`review_by`; the published VDR finding carries neither. **REQ-PUB-1:** the core JSON is signed, but `vdr-status.json`, the `.md` renderings and `ksi-signal.schema.json` are not. **REQ-PUB-4:** see N-PUB-4. |

## 2. The register

### Exploitability

| ID | Requirement / tests | Current behavior (verified) | Effect on published results | Size | Recommendation |
| --- | --- | --- | --- | --- | --- |
| G1 | REQ-LEV-1, LEV-3; T8 | `is_likely_exploitable()` `build-vdr-report.py:891-918` has no floor (IRV and AV:N/PR:N/UI:N). | None today: no live finding has a CVSS vector. Any future reachable network/no-auth/no-UI CVE below θ=0.10 would become LEV, and if N5 + IRV, block (G2 gate). | S | Fix code |
| G2 | Figure 7; T9 | No EPSS score → HIGH/CRITICAL/ERROR is LEV, else NLEV (`:891-913`). | Under Figure 7 as written, all 38 live config findings (no CVE, so no score) would become LEV; today 3 are LEV. All are dispositioned, so nothing would block. **Inference:** the article may not intend "no score = LEV" for findings that can never get an EPSS score (config findings). Sam to confirm scope before the fix. | S | Fix code, after confirming scope |
| G3 | REQ-MIT-1, MIT-2, DSP-4, PAI-1; T15, T23-T25 | No mitigation record type. Allowed dispositions: `false-positive`, `operational-requirement` only (`vuln-gate.py:38`, `build-vdr-report.py:240`). Compensating controls appear only as prose in justifications (`data/vuln-dispositions.json:19, :27`). No N0 / fully-mitigated path. | Records resting on a control or a deployment flag (POAM-034, POAM-035, and Checkov FPs for declined features such as CKV_AWS_50) would move from false-positive to mitigated, each naming a control by inventory ID. | M | Fix code |
| G4 | REQ-LEV-2 | `ingest_epss()` `:789` returns `{cve: score}`; `:823` drops the version/date line. | Each scored finding would carry feed date and model version. No determinations change. | S | Fix code |
| N-LEV-4 | REQ-LEV-4 | No LEV-override record. Neither the VDR builder nor the gate reads `review_by`. | None today (no overrides exist). | S | Document gap, or fix with G15 |
| SSVC | REQ-LEV-5 to LEV-8 | Absent. No `ssvc`/`automatable` anywhere; the methodology block correctly claims no overlay. | — | — | Absent (optional). Not a gap. |

### Reachability

| ID | Requirement / tests | Current behavior (verified) | Effect on published results | Size | Recommendation |
| --- | --- | --- | --- | --- | --- |
| G5 | REQ-IRV-6; T7 | IRV from finding flag or name hints only (`:870-888`, hints `:388-396`); the inventory classification feeds PAIN only (`:1171`). Unresolved findings get fail-safe PAIN but not forced IRV, and aren't queued. Grype/ZAP hardcode IRV True (`:709`, `:750`). | Findings on Cognito and the app Lambda would become IRV (today NIRV). Findings matched by `public_access` on internal buckets would become NIRV. Exact counts need a run against today's inputs. | M | Fix code (read IRV from the inventory) |
| G6 | REQ-IRV-1, IRV-2, IRV-8; T4-T6, T39 | No `exposure_intent` anywhere outside the article. Per-type boolean default (`build-ksi-signal.py:650-676`), overrides (`:686-703`), fail-safe (`:707-712`); `archetype` mixes role and reachability. `flows` (`docs/boundary/boundary-classification.json:50+`) carry free-text `data` and are consumed only by the map builder (`build-boundary-graph.py:390-398`). | The app Lambda and its log groups would be public-backed; the log-group case (Log4Shell pattern) is uncovered today (**inference**). | L | Decide |
| G7 | REQ-IRV-3, IRV-4; T1-T3, T27, T72 | See correction above. No Figure 6 matrix; `is_internet_reachable` takes no reconciliation input (`:1265`). | None until G6 exists. | L | Decide |
| N-IRV-5 | REQ-IRV-5, IRV-9 | NIRV from hardcoded per-check values (`CKV_AWS_117` → `irv: False`, `:292`, applied to all Lambdas including the inventory-reachable one) and free-text justifications. No deflection record, no lapse on change. | `CKV_AWS_117` on `silk_reeling` would become IRV. | M | Fix with G5 |
| N-IRV-7 | REQ-IRV-7 | No template/autoscale inheritance. | None: estate has no autoscaled instances (**inference**). | — | Document gap (not applicable today) |
| N-IRV-10 | REQ-IRV-10 | `scn-tag.yml:48-67` checks only SCN-Type syntax; missing tag defaults to routine-recurring (`:62`). An exposure change is never evaluated as a potential significant change. | None directly. | S-M | Fix code (after G6) |
| N-IRV-11 | REQ-IRV-11 | ZAP result `resource` is the site name (`:748`); no allowlist field. | — | S | Document gap |
| N-IRV-12 | REQ-IRV-12 | Schedule-only (`variables.tf:144`, `watchdog.tf:190`); no change-event subscription. | — | M | Document gap |
| N-IRV-13 | REQ-IRV-13 | Inventory publishes `internet_reachable` (IRV sense), no BOD 26-04 `publicly_exposed`. App Lambda published `true`, though public-backed under the method. | Per-component publication would change. | S (after G6) | Fix with G6 |

### Impact

| ID | Requirement / tests | Current behavior (verified) | Effect on published results | Size | Recommendation |
| --- | --- | --- | --- | --- | --- |
| G8 | REQ-PAI-6, PAI-3; T44 | `_FAILSAFE_CLASSIFICATION` single-agency (`:933-935`); `multi_agency_default: 0` (`vdr-pain-config.json:36`); ("debilitating", 0) → N4 (`:943`). | Unresolved-asset findings could reach N5. No live finding is unresolved-and-debilitating today (**inference** from all-N1–N3 live ratings). | S | Fix code (config change is governed: version bump) |
| G9 | REQ-PAI-2 | `historical_pain = pain` (`:1335-1336`, `:1350`); `completed_reductions = []` (`:1354`). | Ratings would gain a history; needs the previous report's ratings carried like the clock. | M | Fix code |
| N-PAI-3 | REQ-PAI-3 | Data sensitivity derived from FIPS-199 confidentiality (`build-ksi-signal.py:737`), single value, not "PII and/or CUI"; no declarer recorded; scope hardwired single (`:747`). | None today. | M | Document gap; revisit with G6 |
| N-PAI-4 | REQ-PAI-4 | CVSS-environmental function published with config sha256 (`:1588-1597`) but not labeled a deviation from the method's default tables. | Methodology text only. | S | Fix code (one methodology field) |
| N-PAI-5 | REQ-PAI-5 | Flows state contents in prose only; no data flags, no propagation. | — | M | Fix with G6 |
| N-PAI-7 | REQ-PAI-7 | `technical_impact == "total"` branch (`:1148`) is read (`:1175`) but never set anywhere; vectorless/severityless defaults to MEDIUM/N2 (`:1165-1167`), not total. | C:H/I:H CVEs would rate higher. None live (no vectors). | S | Fix code |

### Rules, clock and deadlines

| ID | Requirement / tests | Current behavior (verified) | Effect on published results | Size | Recommendation |
| --- | --- | --- | --- | --- | --- |
| G10 | REQ-RUL-1; T19 | `CLASS_C_SLA_DAYS` typed in (`:345-366`); config description says the matrix "is fixed by FedRAMP and lives verbatim in code". | None if values match the pinned rules. | M | **Decide** (article vs repo) |
| N-RUL-2 | REQ-RUL-2 | `fedramp_corpus_pin: "2a75592"` is in config (`vdr-pain-config.json:6`) but in no output; not a required key (`:75-78`); `rules_reference` is unversioned prose (`:1427-1435`). Verified absent from the live VDR. | Reports would name the rules version they used. | S | Fix code |
| G11 | REQ-DLN-1; T34, T35 | `completed_eval = now` (`:1299`); `due_at = first_detected + sla` (`:1300`); comment at `:341` says "Days from evaluation". | Due dates move to first evaluation (later, by up to the evaluation lag). Evaluation time would stop changing every build. | M | Fix code |
| N-DLN-1 | REQ-DLN-1, SRC-1 | Ledger keyed by `tracking_id` only (`:841-866`); tfsec/Checkov IDs embed line/location (`:587`, `:457`); per-scanner IDs for one CVE (`:615`, `:698`). A failed previous-VDR fetch resets every clock (see G16). | Editing a `.tf` file today silently restarts affected clocks. Fix would keep them. | M | Fix code |
| G12 | REQ-DLN-2 | `will_be_overdue: False` (`:1362`). | Warning would appear before deadlines. None live (nothing open). | S | Fix code |
| G13 | REQ-DLN-3; T14, T36 | Not implemented anywhere. CR26: VER-TFR-MAV (192 days from evaluation, Class C). | Findings past the period would publish as accepted. None live. | M (needs G11) | Fix code |
| G14 | REQ-SRC-1 | `risk_accepted` `first_detected = now` (`:1398`); ingests never use the source's own time (Dependabot `created_at`, ZAP `@generated` only for staleness, `:766`). | 3 live records would keep stable first-detected dates. | S | Fix code |

### Sources, third parties, vendor dependency

| ID | Requirement | Current behavior (verified) | Effect | Size | Recommendation |
| --- | --- | --- | --- | --- | --- |
| N-SRC-1 | REQ-SRC-1 | Only scanners and the OPA plan gate feed findings (`:1526-1541`). Pen tests, disclosures, manual reviews live only as POA&M items with free-text `weakness_detector_source`. | Manual POA&M weaknesses would appear in the VDR. | M | Fix code |
| N-SRC-2 | REQ-SRC-2 | A failing KSI downgrades the SSP control to `partial` (`build-oscal-ssp.py:1484-1488`); no finding is opened. | KSI failures would become findings. | M | Fix code |
| N-SRC-3/4 | REQ-SRC-3, SRC-4 | SDR records have no finding field (`build-sdr.py:78-92`); SDR uses VDR totals only (`:108-111`). | SDR would list open finding IDs per entry. Ties into the FedRAMP-shape work (N-PUB-3). | M | Fix code |
| N-SRC-6 | REQ-IRV-6, SRC-1 | Live Checkov findings carry a file path as `resource` (e.g. `infrastructure/cloudtrail.tf`), not a Terraform address, so they cannot resolve to an inventory component. Verified in the live VDR. | Component resolution, IRV and mitigation lookups for Checkov would work. | S | Fix code |
| N-SRC-5 | REQ-SRC-5 | Control statements name KSIs, not components (`build-oscal-ssp.py:1519`); no `by-components`. | — | L | Document gap |
| N-TPR | REQ-TPR-1 to TPR-5 | Third-party services are inventory components (`build-ksi-signal.py:1301-1311`) with no upstream package/component ID, no per-component responsibility split, no linked upstream findings, no fix state, no full-tier field. | — | M-L | Document gap (TPR-1 partly met) |
| N-VD | REQ-VD-1, VD-2 | Grype `fix.state`/`fix.versions` and Dependabot `first_patched_version` dropped (`:684-701`, `:612-624`). No vendor-dependency disposition; `vendor_dependency: true` is a static POA&M boolean beside `status: false-positive` (`data/poam-items.json:732-736, :760-764`). | POAM-034/035 would become vendor-dependency, lapsing when a fix ships. | M | Fix code |

### Dispositions

| ID | Requirement / tests | Current behavior (verified) | Effect | Size | Recommendation |
| --- | --- | --- | --- | --- | --- |
| G15 | REQ-DSP-2; T16 | `review_by` read only by the trust center (`build-trust-center.py:360-363`). | A lapsed disposition would stop exempting its finding; G2/G3 gates could then block. Need a check of today's `review_by` dates before merging. | S | Fix code |
| N-DSP-1 | REQ-DSP-1 | Published VDR finding carries only `current_disposition` and `poam_ref`; 16 of 37 POA&M items lack decision fields; missing fields published as `null` + `gaps`, not "not recorded"; vocabulary lacks mitigated, overdue, accepted. | — | S-M | Fix code |
| N-DSP-3 | REQ-DSP-3 | Not-present vs protected, under-investigation vs waiting, will-not-fix vs cannot-fix-yet: all collapsed into false-positive. | Several FPs would be relabeled. | M (with G3, N-VD) | Fix code |
| N-DSP-4 | REQ-DSP-4 | POAM-034 and POAM-035 are in the register, POA&M and trust center, but not in the signed VDR (live `false_positives` lists 6 Checkov items only). Live VDR has 0 Grype findings. **Cause (verified 2026-11-03):** neither finding exists any more. GitHub withdrew GHSA-hp3w-g68c-fv3c on 2026-10-22, and pa11y 10.0.0 (#444) removed extract-zip from `tools/a11y`. Nightly Grype counts were 1–3 through 2026-10-22 and 0 since 2026-10-23. The two register entries were stale, and nothing reported that. | None on the VDR. The register, trust center and POA&M stop listing two dead items. | S | Fix: close both (#476); publish unmatched dispositions (#475) |
| N-DSP-5 | REQ-DSP-5 | No VEX ingestion. | — | — | Not applicable |
| N-DSP-6 | REQ-DSP-4, MIT-1 | POAM-035's justification cites `check-wasm-safe.py` as a control gating `sprintf`; it bans only `%q`, `%v`, `time.now_ns(` (`check-wasm-safe.py:28-32`). The literal-format condition is unenforced. | Published justification overstates a control. | S | Fix code (strengthen check) and correct the record |
| G17 | (architecture) | See correction above. | None. | S (retire) / M (wire in) | **Decide** |

### Gates, governance, publication

| ID | Requirement / tests | Current behavior (verified) | Effect | Size | Recommendation |
| --- | --- | --- | --- | --- | --- |
| G16 | T52 (G7) | KEV, EPSS, previous VDR, Dependabot fetch failures continue with a warning; Grype `|| true`; no Grype DB age check; missing ZAP report only warns (`:1538-1539`). G7 does not exist. | A feed outage would fail the run instead of publishing a report with no KEV flags or reset clocks. Adds a new way for the nightly to fail. **Live instance (verified 2026-11-03):** the Dependabot fetch has logged "Could not fetch Dependabot alerts; proceeding with an empty SCA set" in every sampled nightly from 2026-08-29 to 2026-11-03. The job grants `GITHUB_TOKEN` `security-events: read`. The likely cause is that this token can't read Dependabot alerts (inference; the error is discarded by `2>/dev/null`). The repository has 0 open alerts today, so nothing is missing from the VDR now, but the run can't tell. Fixing it needs a token or GitHub App with Dependabot-alerts read, which only Sam can provision. | M | Fix code (T8) + Sam: token |
| N-GAT-1 | REQ-GAT-1 | G1, G2, G3 exist (`:1314-1324`) fail-closed on both paths. G4 partial (reconcile --live), G5 proxy only (invariant (l), deploy only), G6 partial (deploy writes no status record), G7 absent. G1 ignores the KEV `dueDate` and is stricter (blocks any KEV). G1 runs after `terraform apply`. | — | M | Fix code (G7 via G16; G5 with G6) |
| N-GAT-2 | REQ-GAT-2 | Only `tests/fixtures/broken/` (reconcile; covers invariants c, d, e, g/h). No test for the N5+LEV+IRV block or past-SLA block; KEV test is inline (`tests/test_vuln_gate.py:210`). CLAUDE.md's rule holds only for reconcile.py, partly. | — | M | Fix code (first: fixtures for G2/G3 blocks) |
| N-GAT-3 | REQ-GAT-3 | One owner; scoping trivially met. | — | — | Document gap |
| N-GAT-4 | REQ-GAT-4 | Gate modes are code comments (`check-runtime-divergence.py:35`); no governed register. | — | S | Fix code |
| N-GAT-5 | REQ-GAT-5 | No planted known-bad conditions in the live system. | — | M | Document gap |
| N-GOV-1 | REQ-GOV-1 | See correction. SLA matrix, freshness windows (`build-trust-center.py:40-41`, `watchdog.tf:49/54`) and gate modes are hardcoded. | — | S | Fix code |
| N-GOV-2 | REQ-GOV-2 | No profile version or conformance results in any output. | — | M | Fix code (follows N-GAT-2) |
| N-PUB-2 | REQ-PUB-2 | Hourly watchdog (`watchdog.tf:190`, `logic.mjs:4-8`) covers VDR, runtime signal, beacon only; window is a Terraform literal. | — | S | Fix code |
| N-PUB-3 | REQ-PUB-3 | No VEX output. CDS builders name FedRAMP 2026-06-24 schemas (`build-cpo.py:64`, `build-sdr.py:167`, `build-ocr.py:80`) but emit snake_case; `build-cds-overview.py:49` names a schema not in the current rules list. storycheck 0.1 against live: FMT-3 and FMT-4 fail. | Artifacts would validate against FedRAMP schemas. | L | Fix code (Sam decided 2026-11-03: site emits FedRAMP shapes) |
| N-PUB-4 | REQ-PUB-4 | One public tier; no recorded VER-RPT-NID determination that publishing it openly is safe. Moot today (0 open). | — | S | Fix code (record the determination) |
| N-PUB-5 | REQ-PUB-5 | `vdr-status.json` overwritten each run (`nightly:743`), no start time, input counts or versions. Trend upserts by date, passing runs only (`build-vdr-trend.py:43-50`). Live trend: 6 gaps May–Oct. Missed runs not published. | Missed and failed runs would become visible. | M | Fix code |
| N-QUE-1 | REQ-QUE-1 | Queue items lack an options field; `since` null for several kinds (`build-trust-center.py:304, :363`); one aggregate escalation rate; rebuilt on deploy only. | — | S | Fix code |
| N-ASR-1 | REQ-ASR-1 | `assessor_comment_responses: []` (`build-sdr.py:90`); no assessor port. | — | M | Document gap (no assessor) |

### Folded-in site work (decided 2026-11-03)

| ID | What | Notes |
| --- | --- | --- |
| W-1 | Emit FedRAMP-shaped JSON (N-PUB-3) | Plan mode; one generator per PR; storycheck FMT-3/4 as acceptance. |
| W-2 | Remove the customer-responsibility tool | `scuba/`, `scripts/build-scuba-bundle.py`, `/.well-known/scuba-bundle.json`, reconcile invariant (k) (`reconcile.py:534`) and its tests; move to its own renamed repo. Removing an invariant is not weakening a gate only if the artifact it binds is gone in the same PR. |
| W-3 | Stable tracking IDs | Same as N-DLN-1. |

## 3. Decisions

Recorded 2026-11-03 from Sam.

| # | Question | Decision | Consequence |
| --- | --- | --- | --- |
| 1 | G10: where do timeframes come from? | **FedRAMP rules.** | Repo changes; the config description that says the matrix "lives verbatim in code" is wrong and goes. See 3.1. |
| 2 | G6/G7: exposure intent and observer reconciliation? | **Implement.** | L-sized; needs a plan (plan mode) before code. Pulls in N-IRV-5, -10, -13, N-PAI-5 and G5. |
| 3 | G17: `triage.rego`? | **Wire it into the report.** | The Python disposition logic becomes a caller of the Rego; needs a plan (plan mode). Must keep KEV-blocks-even-when-dispositioned. |
| 4 | G2: config findings with no EPSS score? | **LEV unless an automated, justifiable rule moves them to NLEV. Rules 1 and 2 of 3.2 adopted; rule 3 rejected.** | Rule 2 needs a governed per-check vector file and article text. |
| 5 | POAM-035 | **Fix as recommended in 3.3.** | Strengthen `check-wasm-safe.py`; re-record as mitigated + vendor-dependency; same review for POAM-034. |
| 6 | CR26 Rev5 transition (no POA&M, no SSP) | **Transition fully to CR26 now.** | Section 4. The OSCAL SSP and POA&M are retired, not kept as exports. |
| 7 | N-SRC-6: Checkov findings to components | **Match them.** | Use Checkov's Terraform address (native JSON), else file + line → enclosing resource block. |

### 3.1 G10: what "from the FedRAMP rules" means concretely (verified 2026-11-03)

- FedRAMP publishes the rules as JSON at `github.com/FedRAMP/rules`, file `fedramp-consolidated-rules.json` (latest change to that file: commit `64fa769`, 2026-11-02).
- The remediation matrix is structured data: `FRR/VDR/data/all/TFR/VDR-TFR-PVR/varies_by_class/c/pain_timeframes/<N>/{irv_lev,nirv_lev,nlev}/{timeframe_type,timeframe_num}`. The maximum period is `FRR/VER/.../VER-TFR-MAV` (`timeframe_num: 192`), and the evaluation window is `VER-TFR-EVU` (Class C: 5 days).
- **Problem with the current pin.** `fedramp_corpus_pin: "2a75592"` is not a commit in `FedRAMP/rules` or `FedRAMP/docs-legacy` (GitHub API: "No commit found"). I don't know what repo it pins. The local corpus at `~/workspace/final_consolidated_rules_2026` was generated 2026-06-25 from `fedramp/rules@7b9b5ea` and is stale: the rules JSON records that CPO-CSF-CPM was **removed 2026-10-31** (FedRAMP/rules issue #44), and the local markdown still shows it.
- **Plan:** vendor `fedramp-consolidated-rules.json` at a full commit SHA with its sha256 (as storycheck vendors schemas); read the Class C matrix, MAV and EVU from it at build time; fail closed if the path is missing or the hash differs; publish the SHA in every report (closes N-RUL-2); one test asserts the code's lookups against the vendored file, and a known-bad fixture (a rules file missing the Class C matrix) must fail the build. Bumping the pin becomes a governed, reviewed change. Size M.

### 3.2 G2: proposal for an automated, justifiable NLEV for config findings (AI-drafted, for Sam to decide)

The question is what lets a finding with no prediction score be NLEV without a person deciding each one. Three candidate rules, strongest first:

1. **Observed full mitigation (Figure 7 step 1, already in the method).** If the pipeline can observe a control that removes the precondition, the finding is fully mitigated, not merely NLEV. Example: a bucket-level public-access block is missing, but the account-level block is on and `reconcile.py --live` reads it. This needs G3 (mitigation records naming a control by inventory ID, voided on change). It's automatic, and its justification is an observation. No article change.
2. **No attacker action (needs an article change).** Give each check ID a governed CVSS vector (the same file also fixes N-PAI-7 and the "no vector" PAIN fallback). If the vector has no direct impact (v4 `VC:N/VI:N/VA:N`; in v3.1 `C:N/I:N/A:N`), the misconfiguration gives an attacker nothing to exploit: it weakens detection, recovery or key custody (logging off, versioning off, AWS-managed instead of customer-managed key). Rule: no-direct-impact vector → NLEV. The per-check vector is a human decision made once per check ID, recorded with `decided_by` / `review_by` and versioned like θ; the pipeline applies it automatically. The floor (AV:N/PR:N/UI:N + IRV → LEV) still runs first, so a public-exposure check can never land here.
3. **Requires prior access.** Rejected. A vector with PR:L/H says the attacker needs credentials, but that's a lower likelihood, not a justified "not likely". No published prediction backs it. These stay LEV under "no score = LEV".

- **Effect on today's 38 (inference, to verify when vectors are written):** most are logging, notification, versioning, replication or key-type checks (CKV_AWS_18, CKV_AWS_145, CKV2_AWS_62, CKV_AWS_35, AVD-AWS-0015/0089/0132/0162 …) and would be NLEV under rule 2. IAM wildcard-resource checks (CKV_AWS_355, CKV_AWS_356: 3 findings) and the CloudFront WAF check (CKV2_AWS_47) would stay LEV. All 38 are dispositioned, so nothing blocks.
- **Recommendation:** adopt rules 1 and 2; reject 3. Rule 2 needs a sentence in Figure 7 and Appendix A (Sam's prose).
- **Side finding:** Checkov findings carry a file path as `resource` (e.g. `infrastructure/cloudtrail.tf`), not a resource address, so they can't resolve to an inventory component. That weakens G5 and rule 1. Added as N-SRC-6 below.

### 3.3 POAM-035 (verified)

- **What it is:** sprintf-js 1.1.3, a production dependency of the runtime compliance Lambda (via `@open-policy-agent/opa-wasm` 1.10.0, implementing Rego `sprintf`). Advisory GHSA-hp3w-g68c-fv3c / CVE-2026-97058, Medium: denial of service when an attacker controls the **format string** (unbounded precision specifiers throw a RangeError). No fixed release exists. Detected 2026-10-06, dispositioned false-positive 2026-10-20, `review_by` 2027-10-20 (`data/poam-items.json`, `data/vuln-dispositions.json:25-31`).
- **The argument:** every Rego `sprintf` format is a literal compiled into `policy.wasm` behind the deploy gate, so no runtime input reaches the format.
- **The record overstates its control.** The record says `scripts/check-wasm-safe.py` "gates Rego sprintf usage". It bans only `%q`, `%v` and `time.now_ns(` (`check-wasm-safe.py:28-32`). It does not ban precision specifiers or non-literal format strings. The "all formats are literals" condition is true by inspection today but enforced by nothing.
- **Classification under the method:** the vulnerable code is present and deployed, so it isn't a false positive under REQ-DSP-4. It is a mitigation (the literal-format condition) plus a vendor dependency (no fix). Recommendation: (a) extend `check-wasm-safe.py` to fail on any `sprintf` whose format isn't a string literal and on precision specifiers, with a known-bad fixture (a gate strengthening; plan mode); (b) re-record POAM-035 as mitigated, naming that check as the control, plus vendor-dependency; (c) correct the justification text. POAM-034 (extract-zip, build-time only, not deployed) has the same "compensating control" wording and needs the same review.
- New register rows: N-DSP-6 (the overstated control).
- **Update 2026-11-03 (verified):** the advisory was withdrawn on 2026-10-22 and Grype no longer reports it. The item's own remediation plan says to close it then, so it is closed rather than re-recorded (#476). POAM-034 is closed on the same basis: extract-zip left the tree with pa11y 10.0.0. (a) shipped in #468. The mitigated and vendor-dependency vocabulary from (b) exists in #475 for the next such finding. As a mitigation under rule 1, the literal-format check would be partial, not full, because it reads source rather than live state.

## 4. CR26 Rev5 transition: no POA&M, no SSP (planning only)

Decided 2026-11-03: implement now; OSCAL is retired and there is no separate Rev5 track. Facts are verified against FedRAMP's rules JSON and the CR26 markdown corpus; the plan is AI-drafted for Sam.

### What CR26 says (verified)

- **POA&Ms are gone.** "Plans of Action & Milestones (POA&Ms) have been eliminated entirely and replaced with a list of Accepted Weaknesses" (`providers/updating/changes.md`). A vulnerability not fully mitigated or remediated within 192 days of evaluation MUST be categorized as accepted (VER-TFR-MAV). Agencies keep their own POA&Ms; providers "should not be expected to convert" their lists into them (`agencies/use/ongoing/poams.md:21`).
- **The SSP is gone.** For Rev5, the Certification Package Overview "replaces the historically required System Security Plan (not including appendices)", and the Security Decision Record "replaced a traditional System Security Plan". The Rev5 SDR summarizes each applicable control (SDR-CSF-CTF): ODP values, implementation status (Implemented / Partially Implemented / Planned / Alternative Implementation / Not Applicable), mechanisms including inheritance, verification, validation, independent verification, independent validation, responses to assessor comments, and artifacts.
- **Format:** "a transition away from Word and Excel-based templates to simplified JSON documents or (in some cases) optional OSCAL."
- **Dates:** no new Rev5 certifications after 2027-06-11; existing Rev5 certifications active until at least 2028-12-31.
- **Rules drift:** CPO-CSF-CPM (Rev5 package maintenance) was removed 2026-10-31. Pinning the rules JSON (3.1) is what keeps the site honest about changes like this.

### What the site has today (verified)

- `docs/cr26-applicability.md` says the Rev5 track is "maintained in parallel": OSCAL Rev5 SSP (`scripts/build-oscal-ssp.py`) and OSCAL POA&M are generated alongside the 20x artifacts.
- POA&M dependencies: `data/poam-items.json` (37 items), `docs/poam.md`, `oscal-poam.json`, `poam_ref` on every dispositioned VDR finding and register entry, `vuln-gate.py` requiring `poam_ref`, reconcile invariants (g)/(h) and the broken fixture's empty POA&M, and the trust center's `poam_overdue` queue kind.
- SSP dependencies: the SDR reads SSP control status (`build-oscal-ssp.py:1484-1488` → SDR), and KSI-to-control mapping lives in the SSP generator.

### Proposed shape (for discussion)

| Today | Under CR26 | Notes |
| --- | --- | --- |
| POA&M item for an open vulnerability | VDR / VDT finding with its disposition | Already mostly true; `poam_ref` becomes a `decision_id` into the disposition register. |
| POA&M item past 192 days, or will-not-fix | AVI (accepted vulnerability) record | Needs G13 (MAV) first. AVI is also storycheck PRS-4 (today a warning). |
| POA&M item for a non-scanner weakness (manual review, operator investigation) | A finding in the VDR stream (N-SRC-1), with the same lifecycle | Removes the second, parallel weakness list. |
| POA&M decision fields | Disposition register entries (`decided_by`, `decided_on`, `review_by`) | Fixes N-DSP-1's 16 missing records on the way. |
| OSCAL SSP | Rev5 SDR (per control, SDR-CSF-CTF) + CPO | Same control hub; new FedRAMP-shaped JSON. Overlaps W-1. |
| OSCAL output | Optional export, or retired | Sam to decide. CR26 allows optional OSCAL. |
| Reconcile (g)/(h) on the POA&M | Equivalent invariants on the disposition register and AVI | Replaced in the same PR, never just removed (never weaken a gate). New known-bad fixture. |

### Order and dependencies

1. W-1 (FedRAMP-shaped CPO and SDR) and 3.1 (pinned rules JSON).
2. G11 and G13 (evaluation clock, maximum period), so accepted status is computed rather than declared.
3. N-SRC-1 (non-scanner weaknesses enter the VDR stream).
4. Migrate POA&M items: open → findings; past MAV or will-not-fix → AVI; closed → history (VER-TFR-MRH). One PR, with a mapping table checked by a test that every POA&M ID lands somewhere.
5. Rev5 SDR from the control hub; then retire the OSCAL SSP and POA&M (or keep as optional exports).
6. Update `docs/cr26-applicability.md` and the article where it says POA&M.

### Open questions for Sam

1. Keep OSCAL SSP/POA&M as optional exports, or retire them?
2. Keep a Rev5-shaped track at all, given no new Rev5 certifications after 2027-06-11? Or present the site as 20x-only with the Rev5 SDR as a demonstration?
3. The talk: should the transition appear in the January 20 segment as "planned", or stay out of scope?

## 5. Talk tracker

Nothing is merged yet. Updated as PRs merge. Open PRs as of 2026-11-03: trunk #467 (T1) → #470 (T2) → #471 (T3) → #472 (T4) → #474 (T5) → #475 (T6), plus #466, #468 → #476, #469, #473, and this register (#465).

| PR | Gaps it closes on merge |
| --- | --- |
| #467 T1 | G10, N-RUL-2 |
| #470 T2 | G1, G2 (rule 2), G4, N-PAI-7, N-LEV-4 |
| #471 T3 | N-SRC-6, N-DLN-1, G5 (IRV from the inventory), N-IRV-5 |
| #472 T4 | G8, N-PAI-4 |
| #474 T5 | G9, G11, G12, G13, G14 |
| #475 T6 | G3, G15, N-VD, N-DSP-1, N-DSP-3, rule 1 |
| #468 + #476 | N-DSP-6, N-DSP-4 |
| #466 | W-2 |
| #469 | N-QUE-1 |
| #473 | N-PUB-2, N-GOV-1 (windows) |

| Target | Gaps planned | Closed |
| --- | --- | --- |
| By 2027-01-08 (form edit deadline) | G1, G2 (with "no score = LEV"), G8, G15, G16, G12, G14, N-DSP-6 | — |
| By 2027-01-20 (talk) | G10 + N-RUL-2 (pinned rules JSON), G11, G13, N-DLN-1, G4, N-DSP-4, N-GAT-2 (G2/G3 fixtures), 3.2 rule 2 if approved | — |
| After the talk | G5-G7 and G17 (decided; need plans), N-PUB-3/W-1, W-2, Rev5 transition (section 4), the rest | — |
