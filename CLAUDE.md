# CLAUDE.md

Guidance for working in this repository. Keep it accurate: when this file and the working tree disagree, the working tree wins — fix the code or fix this file.

## What this repository is

samaydlette.com is a static personal website on AWS **and** a working continuous-compliance pipeline: every deploy derives a set of signed, machine-readable compliance artifacts (an OSCAL SSP and POA&M, a KSI signal, a VDR) from **one canonical inventory** and publishes them under `/.well-known/`.

Hold two facts at once — they shape every decision:

- **It is a real, functioning production system.** Real AWS infrastructure, real CI/CD, real cryptographic signing. Changes must keep it deployable and keep the compliance gate green. Treat `main` as production.
- **It is also a proof of concept for a scaled version** — a reference architecture for what agency- or enterprise-grade automated compliance ("evidence reciprocity") would look like across many systems. Favor designs that generalize and stay legible; treat the single-account, single-site specifics as stand-ins for a multi-system deployment. **Be honest about the gap:** this repo has **no federal data and no agency sponsor**. It demonstrates the mechanism; it is **not** an authorized system. Never imply otherwise in code, docs, or generated artifacts.

## Codebase map

Confirm against the working tree on first run; correct this section if reality differs.

- `infrastructure/` — Terraform (`main.tf`), OPA policy (`policies.rego`), JSON schemas (`schemas/ksi-signal.schema.json`, `schemas/ksi-catalog.json`), runtime Lambda (`lambda/index.js`).
- `scripts/` — the artifact **generators**: `build-ksi-signal.py` (the canonical inventory), `build-oscal-ssp.py`, `build-oscal-poam.py`, and the VDR builder. These are the source of truth for everything published.
- `website/` — static site content. `website/.well-known/` holds the **published** artifacts (KSI signal + bundle, OSCAL SSP/POA&M, VDR + trend, IIW CSV, runtime signal, signing pubkey, schema).
- `docs/` — `poam.md` (the human POA&M, including the False Positives register), `policies/`, and `assessment/` (e.g. `ground-truth.md`).
- `website/research/` — methodology and scope docs rendered on the site: `authorization-boundary.html`, `the-plumbing.html`. **Read these first for the "why."**
- `website/viewer.html` — the dashboard. It is a presentational shell; **the JSON under `/.well-known/` is the source of truth, not the HTML.**
- `.github/workflows/deploy-with-opa.yml`, `Makefile`, `.checkov.yaml` — the pipeline, entry points, and IaC scan config.

AWS: account is referenced in the published KSI signal; `us-east-2` for the site/app/Lambda/S3/CloudWatch/API Gateway/Secrets Manager, `us-east-1` for ACM/CloudFront and the DNSSEC/CloudFront KMS keys. Confirm before acting.

## The core invariant — do not break this

The system rests on one idea: **the canonical inventory is the single source of truth; every other artifact is derived from it and reconciled against live reality.**

- **NEVER hand-edit generated artifacts** (`/.well-known/*.json`, the SSP/POA&M, the KSI signal, the VDR). Change the **generator** in `scripts/` and regenerate.
- All artifacts must build from one inventory `signal_id`/hash and carry it. Keep `docs/poam.md` and the generated `oscal-poam.json` in sync — change both together.
- A **reconciliation gate** runs in CI before publish and **fails closed**. **NEVER disable, weaken, or bypass it (or the OPA gate) to make a build pass.** Fix the underlying issue or raise it.
- **Publish freshness:** a green pipeline must publish *this run's* artifacts. The served `/.well-known/*` must carry the current commit and a fresh `emitted_at`; a stale serve is a bug, not a cache quirk. This has bitten before — verify the post-deploy round-trip.

## How to work

- **Work autonomously — don't ask for routine permission.** Default to acting, not asking. Editing files, running builds/tests, applying additive infra after a `plan` review, and opening PRs do not need a check-in — make the call, note it in the PR, and keep moving. **Pause for only two things: a genuine security concern, or a genuine architecture decision** — an irreversible or hard-to-reverse fork with lasting consequences (a data model, a trust boundary, a vendor or region choice). Everything reversible verifies its way forward (confirm the new path before removing the old one) rather than stopping to ask. The cost-ceiling flag and the DS-record handoff below are the only other interrupts.
- **Ground truth first, verified independently.** Do not treat any artifact, the pipeline's own output, or Terraform state as proof of what is deployed. Confirm **live cloud state** via the `aws` CLI (credentials are configured locally) or Steampipe, and paste the API output into the PR. A check that only re-reads the build does not count.
- **Build / verify:** `make pipeline` (full build), the reconciliation gate (e.g. `make reconcile`), `terraform plan` before any apply, `checkov` per `.checkov.yaml`. Keep a unit test per gate invariant and the committed broken fixture that must fail the gate.
- **Plan before large changes.** Use plan mode for anything touching the generators, the gate, or `infrastructure/`.
- **Apply policy:** additive, reversible changes can be applied after a `terraform plan` review in the PR. For cutovers/deletions, verify the new path works and keep the old one until then; the only step that requires a human is publishing the DNSSEC **DS record** at the registrar.
- **Cost ceiling:** no recurring cost above ~$2/month without flagging it.
- Keep a running `TASKS.md` for multi-step work so progress survives context limits.

## Parallel work (multiple agents / worktrees)

Speed comes from parallelizing *independent* work, not from putting more agents on the same files.

- **One worktree per task.** Give each concurrent agent its own `git worktree` + branch + directory so they never share a working tree. Don't run two agents in the same checkout.
- **Parallelize the leaves, serialize the trunk.** Independent tasks that don't share a generator, the canonical inventory, or the same artifact can run concurrently (e.g. OIDC vs logging vs docs). Anything that touches the **keystone** — the inventory builder or the reconciliation gate — or the same generated artifact (`docs/poam.md`, a `/.well-known/*` file) must be serialized; concurrent edits there will collide and thrash the gate.
- **Let the gate arbitrate.** The fail-closed reconciliation gate is what makes concurrency safe: if two branches produce inconsistent artifacts, CI catches it at merge instead of shipping drift. Never weaken the gate to resolve a conflict — rebase and regenerate.
- **Subagents for investigation.** Fan out read-only research/inspection to subagents (separate context windows); keep artifact-mutating work to a single owner per artifact.
- Realistic parallelism here is modest — a handful of genuinely independent tasks. Prefer worktree-per-independent-task over deep orchestration.

## Security & compliance rules

- **Impact level is FIPS-199 Moderate / FedRAMP 20x Class C, authoritative everywhere.** No "system is Low" text anywhere. Re-rate; never downgrade-by-relabel.
- **Least privilege always.** Never broaden IAM to make something work — scope down or ask.
- **NEVER hardcode account IDs, ARNs, or secrets** in committed code/Terraform — use variables and data sources. Reading the account ID for verification is fine; committing it is not. Never commit credentials.
- **NEVER assert any service's FedRAMP authorization status without verifying it from a current source.**
- **Don't fabricate compliance.** If a control can't be met, document the residual honestly with a Moderate-level rationale. Dismissed scanner findings must be classified as **false positive** (with justification) or **risk-accepted** — never silently dropped.
- **WAF is intentionally declined.** SC-7/SC-5 are met via managed interfaces (CloudFront + API Gateway) + AWS Shield Standard + throttling, with a WAF's incremental layer-7 filtering documented as the residual. Don't re-add it as a "fix."
- **Narrative must match config.** Every at-rest-encryption (and similar) claim in the docs must match the deployed configuration; they must not drift.

## Pull requests

- **Run CodeGuard on every PR.** Before opening a PR, invoke the CodeGuard security skill (`/codeguard`; underlying Agent Skill `software-security`, from Project CodeGuard) against the diff. Address its findings or record why a finding doesn't apply, and note in the PR that CodeGuard ran. CodeGuard is also useful during planning/generation, not only at review.
- One PR per logical change; the title references the relevant finding / POAM IDs.
- PR body has four parts: **Changed** (what + why), **Verified** (the live API/Steampipe output, not just the build), **Residual / needs human**, **Couldn't verify**.
- Open PRs for review; do not merge your own unless told to.

## Where to find context

- **Why it's built this way:** `website/research/the-plumbing.html`, `website/research/authorization-boundary.html`.
- **Current compliance posture:** `docs/poam.md` (POA&M + False Positives register) and the published `/.well-known/` artifacts.
- **Assessment + remediation plan:** `docs/assessment/ground-truth.md`, plus the standing remediation prompt / SAR when provided alongside a task.
