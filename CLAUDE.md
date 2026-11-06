# CLAUDE.md

Rules that apply to every task in this repository. Procedures live in two project skills (`.claude/skills/`). Load the one that matches the task, or both when a change crosses them:

- **`site-content`**: anything a visitor reads. Articles, research pages, section pages, nav and footer, CSS/JS, `feed.xml`, `sitemap.xml`.
- **`compliance-pipeline`**: generators and gates (`scripts/`), registers (`data/`), Terraform, OPA and Lambdas (`infrastructure/`), workflows, the Trust Center, and anything published under `/.well-known/`.

When this file, a skill and the working tree disagree, the working tree wins. Fix the code or fix the file, in the same PR. Facts belong here; procedures belong in a skill.

## What this repository is

Two things in one repo:

1. **A personal site** (essays, books, projects): static HTML on AWS.
2. **A working continuous-compliance pipeline.** Every deploy derives signed, machine-readable compliance artifacts (the KSI signal, the VDR, the CR26 SDR and CPO, the boundary map, the trust-center data) from **one canonical inventory** and publishes them under `/.well-known/`.

It is a real production system (`main` is production) and a proof of concept for a scaled, multi-system version. Favor designs that generalize and stay legible. It has **no federal data and no agency sponsor**: it demonstrates the mechanism and is **not** an authorized system. Never imply otherwise in code, docs, pages or generated artifacts.

## How much to do on your own

The two recurring failures here are **overbuilding** and **mistakes that ship inside large changes**. These rules trade a little speed for fewer of both.

### 1. Size the task before touching anything

- **Small: go straight to a PR, no plan needed.**
  - A procedure a skill marks *(small task)*, or
  - a change to at most 3 files, none of them protected, that does exactly what was asked.
- **Everything else: post a plan and wait for an explicit OK.** If unsure, it is not small.
- **A question gets an answer, not a change.** Don't edit files unless asked to.

**Protected paths** (a change touching any of these is never small): `scripts/`, `data/`, `infrastructure/`, `policies/`, `.github/`, `Makefile`, `website/.well-known/`, `website/trust/`, `website/assets/js/trust.js`, `docs/boundary/`, `CLAUDE.md`, `.claude/`.

### 2. The plan (15 lines or fewer)

- **Goal:** one sentence, in the requester's terms.
- **Files:** each file you will change or add, with a reason.
- **Out of scope:** what you noticed but will *not* do.
- **Verify:** the commands you will run and what passing looks like.
- **Production or irreversible steps** (`terraform apply`, bootstrap, DNS, deleting published evidence): name each one, or it is not approved.

Once the plan is approved, work inside it without asking.

### 3. Scope tripwire: stop and check in when

- you need to touch a file that is not in the plan, or the diff is outgrowing it;
- you are about to add something the request did not ask for: a file, script, function, flag, config value, dependency, workflow, abstraction or tool;
- a gate or test fails and the fix would change the gate, the test or its fixture rather than the code under test;
- the request can't be done as stated, or the plan turns out to be wrong. Report it; don't improvise a different solution;
- you face a production or irreversible step the approved plan does not name, anything that widens IAM, recurring cost above ~$2/month, a genuine security concern, or an architecture decision (data model, trust boundary, vendor, region).

When you stop, send one message: what you found, the options, your recommendation, and the exact action or identifier you need from the operator.

### 4. Don't overbuild

- Make the smallest change that fully meets the request.
- Before adding anything, search for something that already does it. Prefer editing to adding, and deleting to adding.
- No "while I'm here" changes. List them under **Follow-ups noticed** in the PR instead.
- Don't build tooling to help with a task unless asked. The prose tooling, the parked generators in `scripts/staged/` and the planning backlog were all built and later removed.
- One PR per logical change. If the work needs several PRs, say so in the plan.

### 5. Don't ship mistakes

- Read the files you will change, and their tests, before editing. Trust the working tree over this file, a skill, or memory.
- Verify by exit code, not by reading output. **`make check` is the gate for every change**: hermetic, ~4s, one-time `make dev-setup`. Skills add task-specific checks.
- Before opening a PR, read your own diff as a reviewer would. Anything not in the plan comes out or becomes a check-in.
- When a change alters what the deploy publishes, verify the published result, not the working tree. Six fix PRs followed the CR26 merges on 2026-11-05.
- For multi-step work, keep a running `TASKS.md` (gitignored) so progress survives context limits.

## Invariants: never break these

- **One canonical inventory is the source of truth.** Every published artifact derives from it, carries its `signal_id`, and is reconciled against live reality.
- **Never hand-edit generated artifacts** (anything under `/.well-known/`; the generated block of `website/feed.xml`). Change the generator and regenerate.
- **Never disable, weaken or bypass the reconciliation gate, the OPA gate or any other gate** to make a build pass. Fix the cause or raise it.
- **Site content is inventoried content.** Every `*.html` under `website/` is hashed into the inventory, so editing or adding a page is a pipeline change. The pipeline handles it; never hand-add an inventory entry.
- **A decision about a finding lives only in `data/decisions.json`**, referenced by its `DEC-NNN` ID.
- **Deploys are human-approved.** Merging to `main` does not deploy: the `deploy` job waits for a reviewer on the `prod` environment. The one unattended production write is `evidence-nightly.yml`; never widen its role (the trade-off is spelled out in `compliance-pipeline`).
- **There is no local publish path.** `make -C infrastructure deploy` refuses by design. `make -C infrastructure pipeline` runs `terraform apply` against production: never run it to "check" anything.
- **Impact level is FIPS-199 Moderate / FedRAMP 20x Class C** everywhere. Never relabel it down.
- **Least privilege.** Never broaden IAM to make something work.
- **Never commit account IDs, ARNs, secrets or credentials.** Use variables and data sources.
- **Claims must be true.** Narrative in docs, pages and the trust center must match deployed config. Never assert any service's FedRAMP status without a current source. Never fabricate compliance: a control that isn't met is documented as a residual, and a dismissed scanner finding is a false positive (with justification) or risk-accepted, never silently dropped.
- **The opinions on the site are the operator's.** Claude may draft; it never supplies a position (see `site-content`).

## Pull requests

- Before opening a PR, run CodeGuard (`/codeguard`, Agent Skill `software-security`) on the diff. Address its findings or record why one doesn't apply, and note in the PR that it ran.
- One PR per logical change. The title references the relevant finding or `DEC-NNN` IDs, if any.
- Body: **Changed** (what and why) · **Verified** (what you ran and the outcome) · **Residual / needs human** · **Couldn't verify** · **Follow-ups noticed**.
- **The repo is public.** Titles, bodies and commit messages are world-readable. No chat transcript or debugging narrative. No account IDs, ARNs, key IDs, role or secret names, raw IAM policy text, or error dumps that carry them. Refer to resources by Terraform address or role, and state verification outcomes, not live values.
- If something needs a human (a permission, a registrar step, a console-only action), ask the operator directly and now, with the exact action and identifier. Don't leave it as a vague line in the PR.
- Open PRs for review. Don't merge your own unless told to.

## Repo map

Confirm against the working tree, and fix this table when it is wrong.

| Path | What it is | Skill |
|---|---|---|
| `website/pages/`, `website/research/`, `website/index.html` | Articles, section pages, long-form research pages and redirect stubs | site-content |
| `website/assets/` | CSS, JS modules, images, fonts, vendored libraries | site-content |
| `website/feed.xml`, `website/sitemap.xml` | Feed (generated from `pages/articles.html`) and sitemap (hand-maintained) | site-content |
| `website/trust/`, `website/assets/js/trust.js` | Trust Center: a shell over `/.well-known/trust-center.json` | compliance-pipeline |
| `website/.well-known/` | Published artifacts. Git tracks only `security.txt` and `vdr-trend.json`; the rest is gitignored build output | compliance-pipeline |
| `scripts/` | Artifact generators and gates. `scripts/staged/` is parked and not wired in | compliance-pipeline |
| `data/` | Registers: `decisions.json`, mappings, profiles, third-party components | compliance-pipeline |
| `infrastructure/` | Terraform, OPA policies, schemas, Lambdas. `bootstrap/` is operator-applied | compliance-pipeline |
| `.github/workflows/` | `deploy-with-opa.yml` (gated deploy), `evidence-nightly.yml` (unattended VDR refresh), ZAP, SCN tagging | compliance-pipeline |
| `docs/` | Policies, runbooks, SCNs, boundary classification, `architecture-decisions.md` | compliance-pipeline |
| `tools/essay/`, `tools/preview/`, `tools/a11y/` | Long-form checks, local preview server, accessibility scanner | site-content |
| `tests/` | pytest suite run by `make check` | either |

## Where to find the "why"

- `website/research/authorization-boundary.html` and the Trust Center: why the system is built this way.
- `docs/architecture-decisions.md`: settled decisions. Don't relitigate one unless asked.
- `data/decisions.json` and the published `/.well-known/` artifacts: current compliance posture.
- A remediation prompt or SAR, when one is provided with a task.
