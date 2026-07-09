# Remediation Report — verify-then-fix engagement, 2026-07

Scope: the five Phase-0 verification questions and the prioritized gap list from
the July 2026 remediation brief. Ground rule applied throughout: where the brief
conflicted with the repository or live AWS state, the repo/live state won and
the discrepancy is recorded here. All live checks were read-only CLI or curl
against the published `/.well-known/` artifacts.

Headline: **a majority of the brief's findings were already fixed on `main`
before this engagement began** (the brief appears to have been written against
a ~mid-June snapshot). The real, still-open gaps were: two failing tag
validations, stale narrative strings inside the signal generator, an over-broad
SSP downgrade heuristic, SSP auth controls still dispositioned for the pre-app
world, a runtime emitter blind spot, stale human docs, a missing SCN record,
and the absence of any CloudTrail trail. All of those are fixed in PRs #218–#225.

## Phase 0 — verification results

### 0.1 App auth ground truth
**Deployed reality (live CLI, 2026-07-02..06): Amazon Cognito** — pool with
`MfaConfiguration: ON` (TOTP), 14-char password policy, admin-only creation;
API Gateway JWT authorizer on `ANY /api/{proxy+}` (issuer = the pool, audience
= the pinned SPA client); `$default` route open serving only the SPA shell;
stage throttling 20 req/s / burst 10; access logging to a CMK-encrypted log
group. Terraform, article-28, the live KSI signal, and the published SPA auth
config all agree. The brief's premise ("Basic Auth deployed, article
overclaims") was **inverted**: the article was right; the stale surfaces were
`docs/poam.md`'s POAM-021/022/023 narrative paragraphs (present-tense Basic
Auth; fixed in PR #223) and one marketing sentence (fixed, same PR). The app
Lambda does call the Anthropic API directly (POAM-020, risk-accepted; see 3.4).

### 0.2 POA&M set reconciliation
Authoritative set: **POAM-001..031 with POAM-016 retired → 30 items**, exactly
what the live `oscal-poam.json` carries (regenerated daily) and what `main`'s
`build-oscal-poam.py` and `docs/poam.md` already encode. The brief's "poam.md
ends at 024" and "README lists only 001/002" were stale-branch/README issues:
main's poam.md has all rows; the README genuinely was stale (presented 001/002
as open; both closed June) — fixed in PR #223. Article-28's POAM-025 reference
is real (hardware/phishing-resistant MFA, open operational-requirement, added
from the 2026-06-22 Prowler triage). The brief's "192 implemented-requirements"
README claim did not exist (README said 331; the builder now emits 333 and the
figure is machine-stamped via inject-figures, PR #223).

### 0.3 Failing validation identity
Two real findings, both tag gaps, plus two tooling defects:
- **v-0015** (deploy-time signal): access-log bucket missing the `CostCenter`
  required tag → fixed in Terraform (PR #218).
- **r-0000** (runtime signal): website bucket (not Terraform-managed; data
  source only) missing all six classification tags → fixed live via
  `put-bucket-tagging` (2026-07-06), preserving the existing tags, values
  mirroring the inventory's projected classification.
- Tooling defect 1: the SSP builder downgraded controls via a hardcoded
  policy-id→KSI map, dragging in passing KSIs (CA-7/SI-7(7) went partial with
  no failing evidence) → now reads the signal's own per-KSI attribution
  (PR #220).
- Tooling defect 2: the runtime emitter validated only the *first* S3 bucket,
  so the log bucket was never re-checked at runtime → now iterates every
  object_store component, with a metadata-only IAM grant (PR #221).
The brief's "45 passing / 1 failing" matched the deploy signal; the SSP partial
cluster (12 controls) resolves once #218 deploys and #220 corrects attribution.
A third alleged defect (deployed policy wasm containing a rule with no
committed source) was an artifact of reading a stale branch — the
classification rules are committed in `infrastructure/policies.rego` on main.

### 0.4 KSI completeness vs final CR26
**No gap.** The final CR26 corpus (local clone, HEAD 2026-06-25) defines **46**
Class C KSIs (the ~56 figure was pre-final; Class B and C share the same 46);
the live SDR's 46 `rule_records`, the local `ksi-catalog.json`, and the corpus
are identical sets — zero diff. VDR-* vs VER-*: **both families exist as
distinct stable rulesets** in the final corpus (VDR = Detection & Response, 18
rules; VER = Evaluation & Reporting, 25 rules); the generator and the live
`vdr-report.json` (regenerated 2026-07-02, not stale) already cite both
correctly. No action taken; none needed.

### 0.5 Audit trail reality
**No CloudTrail trail exists** (no TF resource, no delivery bucket; the
operator IAM user is denied `cloudtrail:DescribeTrails`, so absence was
established structurally). All three live CloudWatch log groups are **365-day
retention, CMK-encrypted** — POAM-017/018/024 closures are real; the brief's
"7-day retention" was pre-closure. The one true residue: the live signal's
`baseline_configuration` strings still said "7-day retention" and "DNSSEC not
enabled" — hardcoded generator text, fixed in PR #219. The log bucket has a
400-day lifecycle in TF (live check denied to the operator user; flagged, not
asserted). CloudTrail gap remediated in PR #225.

## Phase 1 — truth reconciliation

| Item | Result |
|---|---|
| 1.1 inventory native_id bug | **Already fixed on main** before this engagement (per-resource ARN as native_id; duplicate-native_id fail-closed gate in `validate-ksi-signal.py` with unit tests). Verified in the live signal: 212 components, zero duplicate native_ids, the app Lambda carries its own ARN. No action needed. |
| 1.2 boundary vs deployed surface | The ABD/DFD (`authorization-boundary.html`) was **already current** (flow H: Cognito JWT ingress). The real gap was the **SSP**: IA-2 (+enh), IA-8, AC-7, AC-11/12 still `not-applicable`. Fixed per the brief's preferred design: dispositions now **derive from the inventory's identity_provider component** and revert automatically if the app is torn down (PR #222). AC-11 stays honestly N/A (device session lock; AC-12 token expiry bounds it). SC-5 was already implemented. |
| 1.3 impact-level contradiction | **Premise not reproducible on main.** `docs/poam.md` is uniformly Moderate (header and rationales); no "FIPS-199 Low" text exists. The only Low-flavored friction is the Prowler scan baseline name (`fedramp_20x_ksi_low`), which is a scanner-tier issue (see 2.1), not a categorization claim. `reconcile.py` passed because there was nothing to fail. No invariant added — there is no textual pattern to guard that wouldn't be theater. |
| 1.4 stale surfaces sweep | README POA&M section, POAM-016 ghost reference, old KSI IDs, hand-typed counts → PR #223 (README joins inject-figures targets; the 331/333 headline figure is now machine-stamped). poam.md narratives → PR #223. VDR staleness: **not stale** (emitted 2026-07-02; 0.4). Risk-accepted count basis (VDR 18 vs SDR 10) and the three `poam_ref: null` suppressions could not be fully reconciled in this pass — left open, see "Not completed". DNSSEC claim → PR #219 (the signal was wrong in the *other* direction: DNSSEC is ON). |
| 1.5 freshness enforcement | **Largely satisfied by design already:** the deploy workflow runs on a daily cron and executes `reconcile.py --live --expect-commit` before and after publish; every artifact regenerates daily (live signal `emitted_at` was same-day on every check). The brief's "deploy signal stuck at 2026-06-12" no longer reproduces. No extra skew job added — a second scheduled checker would duplicate the daily pipeline; noted as a conscious skip. |

## Phase 2 — CR26 Class C mechanics

| Item | Result |
|---|---|
| 2.1 two independent methods per KSI | **Open — the one substantive P1 gap remaining.** Today's two persistent methods (OPA deploy gate, runtime Lambda) share the same compiled Rego, so independence is arguable; the Prowler runs (2026-06-22/23) were manual and used the Low KSI baseline. Plan: scheduled Prowler on the moderate/Class-C-appropriate baseline (verify the exact framework id against the installed Prowler version rather than assuming a name), results mapped to KSI ids and merged into the SDR's per-KSI verification fields, with explicit exceptions where a second automated method is genuinely N/A (documentation-method KSIs). Deferred rather than shipped half-wired — see "Not completed". |
| 2.2 sign the runtime signal | **Already done (POAM-002 closed 2026-06-17)** and verified live: `provenance.attestation` carries a KMS ECDSA-P256 signature; `/.well-known/runtime-signing-pubkey.pem` serves the public key (HTTP 200). No action needed. |
| 2.3 clear the failing validation | Done via PR #218 (config fix, the honest disposition — no POA&M entry needed for a promptly-remediated tag) plus the live website-bucket tagging. SSP partials self-resolve on the next deploy. |
| 2.4 SCN hygiene | The app addition had SCN-2026-001 (Adaptive, verified). The **auth change had no SCN record** — backfilled as SCN-2026-002 with SIA and a fresh post-implementation verification (PR #224). The CloudTrail addition ships with its own SCN-2026-003 (PR #225). Commit/PR SCN-Type tagging follows the existing validator (missing tag = routine-recurring by policy). |

## Phase 3 — cross-framework gaps

| Item | Result |
|---|---|
| 3.1 CI credentials (POAM-001) | **Already done (closed 2026-06-15), verified:** the workflow assumes a role via `aws-actions/configure-aws-credentials` with OIDC (`role-to-assume` from a repo variable); the bootstrap layer defines the OIDC provider + repo-scoped trust; poam.md/OSCAL record the legacy user and secrets deleted. No action needed. |
| 3.2 app access-control ladder | **Already done:** stage throttling (POAM-023 closed), access logging (POAM-024 closed), and the full IdP upgrade (Cognito, POAM-021/022 closed) are live-verified. The CloudWatch metric-filter + alarm on credential-guessing was **not** built: Cognito lockout + gateway throttling structurally addressed the trigger, and the WAF pre-authorization stands on record in the POAM-023 closure text (PR #223). POAM-025 (hardware/phishing-resistant MFA for operator accounts) remains open by operator choice — TOTP keeps CMMC 3.5.3 green; the SSP now says exactly that (PR #222). |
| 3.3 audit retention (POAM-017/AU-11) | Log groups already at 365-day CMK (closed, verified). The missing piece was CloudTrail: **PR #225** adds a multi-region, validation-enabled management trail with 12-month active + Deep-Archive-to-30-months tiering; the deploy role deliberately cannot stop or delete it. Cost < $1/month. Needs one manual bootstrap apply (called out in the PR). |
| 3.4 external interconnection (POAM-020) | **Deferred, documented.** Bedrock migration was not executed (model/feature parity and app-code changes are an operator product decision; the app source lives outside this repo). Verified the SSP emits the interconnection only via the app's presence in inventory. The annual terms-verification task exists implicitly via the secret-rotation check; a calendarized terms review is listed as follow-up. |
| 3.5 DNSSEC | **Enabled all along** (live: `SIGNING`; TF manages the KSK). The false claim was the signal saying "not enabled" — fixed in PR #219. The baseline strings remain type-level constants rather than live-derived; deriving them from config is noted as follow-up hardening, with the reconciliation gate as the drift backstop. |
| 3.6 vulnerability evidence | **Mostly already done on main:** Syft/Grype SCA feeds the VDR (CVE-keyed ledger), monthly scheduled OWASP ZAP baseline exists (`zap-dast.yml`), Dependabot is configured. "Zero CVEs" is scanner-proven in the current pipeline. pip-audit for Python deps not separately added (Grype covers the built Lambda artifact). No action this pass. |
| 3.7 GuardDuty | **Not enabled — needs an operator cost decision.** Expected low single-digit $/month (within the stated ceiling) but it is a recurring spend on a detective service whose findings would also need a surfacing path into the runtime signal/VDR; flagged rather than silently enabled. |

## Phase 4 — framework profile currency

Not executed this pass (P2–P3): TX-RAMP PM 4.0 baseline re-derivation (4.1),
800-171A objective decomposition + inherited-count re-derive (4.2), GovRAMP/
CJIS re-run + conditional CJI trigger template (4.3), FedRAMP OSCAL validator
run (4.4). 4.2/4.3 depend on the 1.2 re-dispositions (PR #222) merging first,
so sequencing them after this batch is correct, not just convenient.

## Deliverables

| PR | Branch | What |
|---|---|---|
| #218 | fix/logs-bucket-costcenter-tag | CostCenter tag → clears v-0015 |
| #219 | fix/signal-baseline-truth | DNSSEC/retention narrative truth in the signal + SIEM section |
| #220 | fix/ssp-downgrade-attribution | SSP partial-downgrade follows per-KSI verdict |
| #221 | fix/runtime-emitter-all-buckets | Runtime emitter validates every inventory bucket |
| #222 | fix/ssp-auth-controls-from-inventory | IA-2*/IA-8/AC-7/AC-12 derived from inventory |
| #223 | docs/human-surfaces-currency | README / poam.md narratives / architecture-decisions / mirror page |
| #224 | docs/scn-002-cognito-auth | SCN backfill for the auth change |
| #225 | infra/cloudtrail-management-trail | CloudTrail trail + bootstrap grant (stacked on #219) |

Live changes applied directly (additive, reversible, verified): website-bucket
classification tags (2026-07-06; next runtime emission clears r-0000).

CodeGuard (software-security) ran against every PR diff; no findings. All
branches pass the python suite; figure/reconcile gates run in CI per normal.

## Not completed, and why

1. **2.1 second independent method (P1).** Requires verifying the correct
   Prowler Class-C/moderate framework id, an SDR schema decision for per-KSI
   verification-method fields, and a result-ingestion path that doesn't
   involve CI pushing to main. Shipping a guessed framework name or a
   half-wired merge would violate the don't-fabricate rule. Concrete next
   step: one PR adding `prowler.yml` (monthly, OIDC read-only role) + a
   `data/verification/prowler-ksi-map.json` consumed by `build-sdr.py`.
2. **VDR risk-accepted count basis + 3 null poam_refs (1.4 tail).** Needs a
   counting-basis decision (findings vs suppressions vs POA&M items) that
   should be made once, in the VDR generator, with the operator's definition.
3. **3.4 Bedrock migration** — operator product decision; app source is in a
   separate repository.
4. **3.7 GuardDuty** — recurring-cost + findings-surfacing decision; flagged.
5. **Phase 4 items** — sequenced behind PR #222 by design.
6. **POAM-025 hardware token** — operator-physical action, unchanged.

## Operator actions needed now

1. Review/merge PRs #218–#224 (independent; any order). For #225: apply the
   bootstrap layer first (new `cloudtrail-management` deploy-role policy),
   then merge #219, retarget #225 to main, merge.
2. After the next daily deploy + runtime emission: confirm the dashboard/SDR
   show 46/46 passing and the SSP has no unexplained partials.
3. Decide: GuardDuty (3.7), Bedrock migration (3.4), and the Prowler
   second-method PR (2.1) — say the word and each becomes its own branch.
