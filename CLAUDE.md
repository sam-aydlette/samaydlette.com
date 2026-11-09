# CLAUDE.md

Rules that apply to every task in this repository. Procedures live in two project skills (`.claude/skills/`). Load the one that matches the task, or both when a change crosses them:

- **`site-content`**: anything a visitor reads. Articles, research pages, section pages, nav and footer, CSS/JS, `feed.xml`, `sitemap.xml`.
- **`compliance-pipeline`**: generators and gates (`scripts/`), registers (`data/`), Terraform, OPA and Lambdas (`infrastructure/`), workflows, the Trust Center, and anything published under `/.well-known/`.

When this file, a skill and the working tree disagree, the working tree wins. Fix the code or fix the file, in the same PR. Facts belong here; procedures belong in a skill.

## What this repository is

Two things in one repo:

1. **A personal site** (essays, books, projects): static HTML on AWS.
2. **A working continuous-compliance pipeline.** Every deploy derives signed, machine-readable compliance artifacts (the KSI signal, the VDR, the CR26 SDR and CPO, the boundary map, the trust-center data) from **one canonical inventory** and publishes them under `/.well-known/`.

It is a real production system (`main` is production) and a proof of concept for a software factory (see Intent). Favor designs that generalize and stay legible. It has **no federal data and no agency sponsor**: it demonstrates the mechanism and is **not** an authorized system. Never imply otherwise in code, docs, pages or generated artifacts.

## Intent
This site shows that I can build scalable, enterprise-quality infrastructure
and policy-as-code pipelines for cloud service delivery, and communicate the
resulting security state to stakeholders in a way that gives them assurance.
The reader is an engineer or leader judging that work. It is a proof of
concept, not a certification effort, and I do not engage FedRAMP or any
agency about it.

Think of it as a software factory: one authorization boundary and one
offering, holding the website, the Silk Reeling app and any app added later.
Apps join through the same pipeline and gates, never through one-off wiring.

Serious about engineering. Tongue in cheek about processes one person clearly
cannot do.

When goals collide: truth, then a working production system, then simplicity,
then rule coverage. Coverage is never a reason to overstate anything.

If an instruction, including mine, conflicts with this section, stop and say
so before acting.

## Design principles
These describe the target. Where the system falls short, say so; never claim one is met because it is listed here. The procedures live in `compliance-pipeline`.

1. Keep recorded intent, enforcement and verification separate, so a change or failure in one doesn't break the others.
2. Record intent in version control as readable requirements with stable IDs, requirement levels and mappings to FedRAMP rules, KSIs and 800-53. Review and attribute every change.
3. Make each automatable requirement a tested check that cites its ID. Every other requirement carries a status and its reason (Proof-of-concept latitude), so every report accounts for every requirement in scope. A manual step one engineer could automate is Not Demonstrated.
4. Verify in stages: capture live state as data with the least privilege the system allows, then evaluate and report from that data, so each stage can be rerun or replaced alone.
5. Validate before deployment whenever a change passes through code. Always validate running systems through their own interfaces, on a schedule and after every deployment.
6. Declare baselines centrally and publish them as versioned releases. Each app in the factory applies them as published, may add stricter rules or local values, and weakens them only through an approved exception.
7. Make every exception explicit, justified, approved at a level that matches its risk, and given an expiry or review date.
8. Never report anything unverified as compliant. Checks that errored, stale results and inventory gaps are findings.
9. Compare each assessment with the previous one, and route every regression to an owner to fix or explicitly accept.
10. Produce evidence on every run: tamper-evident, traceable to the versions of the baseline, checks, tool and configuration behind it, and reported to the baseline's owner.

## Proof-of-concept latitude
This system shows that policy as code can automate CR26. It is not certified.
Procedure may flex. Claims may not.

Ask of every rule and KSI, in order:

1. Can its trigger ever happen in this system? If not: **Not Applicable**,
   naming the missing trigger. "It's a proof of concept" is not a reason.
2. Could one engineer build it with code and cheap AWS? Then build it for real.
   **Implemented** means a real mechanism ran on real inputs and evidence
   exists. Until then: **Not Demonstrated**, saying what is missing. That list
   is a build queue, not a resting place.
3. If not: **Impractical**, with its reason: `one-person`, `no-budget` (name
   the cost) or `no-outside-party`. Build as much as you can and show it. The
   rest is a labeled, tongue-in-cheek stand-in or a plain admission. Never use
   a stand-in for something one engineer could build.

Only Implemented counts as met. Impractical is always shown with its reason.
For whatever was built, show with a test that a bad input changes the result,
and state what a real organization would supply in place of the stand-in. A
guard that refuses real agencies or FedRAMP is policy, not logic.

Examples:
- Log-read allowlist: buildable, so real evidence and no jokes.
- FedRAMP Security Inbox: the logic is buildable, but the rule is Impractical,
  `no-outside-party`. It is not a budget problem.
- Independent assessment: Impractical, `one-person` and `no-budget`. A
  simulated assessor may stay as a joke, but never call it independent.
- The Board of Sam: a fine joke for a people process. It earns no engineering
  credit.

You may propose a status, stand-in or scope cut. You may not approve one.
Record each with what is real, what stands in, and who approved it.

Never choose a status because a gate requires it. If the honest status blocks
the build, stop and tell me.

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
- No "while I'm here" changes. List them under **Follow-ups noticed** in the PR instead (see §6).
- Don't build tooling to help with a task unless asked. The prose tooling, the parked generators that sat in `scripts/` and the planning backlog were all built and later removed.
- One PR per logical change. If the work needs several PRs, say so in the plan.

### 5. Don't ship mistakes

- Read the files you will change, and their tests, before editing. Trust the working tree over this file, a skill, or memory.
- Verify by exit code, not by reading output. **`make check` is the gate for every change**: hermetic, about 25s, one-time `make dev-setup`. Skills add task-specific checks.
- Before opening a PR, read your own diff as a reviewer would. Anything not in the plan comes out or becomes a check-in.
- When a change alters what the deploy publishes, verify the published result, not the working tree. Six fix PRs followed the CR26 merges on 2026-11-05.
- For multi-step work, keep a running `TASKS.md` (gitignored) so progress survives context limits.

### 6. How to respond

- Lead with the outcome: what changed, what passed, what didn't. No preamble, no praise, no recap of steps.
- Keep what you verified, and how, separate from what you assumed or inferred. Say "I don't know" or "I didn't check" plainly.
- If you think a request or plan is wrong, say so before acting, with the reason. Don't open with agreement.
- **Ideas during a task:** at most three, under **Follow-ups noticed**, each with one line on why it matters: a problem it fixes, or an opportunity it opens. "None" is a valid answer. Never build one unasked.
- **When the operator asks for ideas:** range widely. Label each idea as a fix or an opportunity, and say what it would cost.

## Invariants: never break these

- **One canonical inventory is the source of truth.** Every published artifact derives from it, carries its `signal_id`, and is reconciled against live reality.
- **Never hand-edit generated artifacts** (anything under `/.well-known/`; the generated block of `website/feed.xml`). Change the generator and regenerate.
- **Never disable, weaken or bypass the reconciliation gate, the OPA gate or any other gate** to make a build pass. Fix the cause or raise it.
- **Site content is inventoried content.** Every `*.html` under `website/` is hashed into the inventory, so editing or adding a page is a pipeline change. The pipeline handles it; never hand-add an inventory entry.
- **A decision about a finding lives only in `data/decisions.json`**, referenced by its `DEC-NNN` ID.
- **Deploys are human-approved.** Merging to `main` does not deploy: the `deploy` job waits for a reviewer on the `prod` environment. The unattended production writes are the scheduled evidence workflows (`evidence-nightly.yml` and any added later), each with its own narrow role; never widen one (the trade-off is spelled out in `compliance-pipeline`).
- **There is no local publish path.** `make -C infrastructure deploy` refuses by design. `make -C infrastructure pipeline` runs `terraform apply` against production: never run it to "check" anything.
- **Impact level is FIPS-199 Moderate / FedRAMP 20x Class C** everywhere. Never relabel it down.
- **Least privilege.** Never broaden IAM to make something work.
- **Never commit account IDs, ARNs, secrets or credentials.** Use variables and data sources.
- **Claims must be true.** Narrative in docs, pages and the trust center must match deployed config. Never assert any service's FedRAMP status without a current source. Never fabricate compliance: a control that isn't met is documented as a residual, and a dismissed scanner finding is a false positive (with justification) or risk-accepted, never silently dropped.
- **The opinions on the site are the operator's.** Claude may draft; it never supplies a position (see `site-content`).

## Enforced by Claude Code, not by this file

- **Permission rules** (`.claude/settings.json`) block force-pushes, `terraform destroy` and `aws s3 rm`. They ask the operator before `terraform apply`, `apply-infra` or `pipeline`, a push to `main`, `gh pr merge`, IAM writes and S3 writes. They match the command as written, so they are a guardrail, not a security boundary. The `prod` approval is the boundary.
- **A Stop hook** (`.claude/hooks/stop-check.sh`) runs `make check` whenever the working tree has changes, and won't let a turn end while it fails. Fix the cause, never the gate.
- **Tests keep the hand-maintained copies honest:** `tests/test_sitemap.py`, `tests/test_homepage_recent_articles.py`, and `tests/test_agent_context_paths.py`, which checks that every path named here and in the skills exists.

When a rule in this file keeps being broken, move it into one of these mechanisms and delete it from the prose.

## Pull requests

- Before opening a PR, run CodeGuard (`/codeguard`, Agent Skill `software-security`) on the diff. Address its findings or record why one doesn't apply, and note in the PR that it ran.
- One PR per logical change. The title references the relevant finding or `DEC-NNN` IDs, if any.
- Body: start with `SCN-Type:` and `SCN-Rationale:` (one line each), plus `SCN-Record:` naming the open SCN the change joins when it is not `not-significant`. A change to the compliance engine (gates, assessor, reconciliation, generators that decide or publish compliance status) is `adaptive` by default. Then **Changed** (what and why) · **Effect** (what changes on the live site after deploy, including record counts before and after) · **Verified** (what you ran and the outcome) · **Residual / needs human** · **Couldn't verify** · **Follow-ups noticed**.
- **The repo is public.** Titles, bodies and commit messages are world-readable. No chat transcript or debugging narrative. No account IDs, ARNs, key IDs, role or secret names, raw IAM policy text, or error dumps that carry them. Refer to resources by Terraform address or role, and state verification outcomes, not live values.
- If something needs a human (a permission, a registrar step, a console-only action), ask the operator directly and now, with the exact action and identifier. Don't leave it as a vague line in the PR.
- Open PRs for review. Don't merge your own unless told to.

## Repo map

Confirm against the working tree, and fix this table when it is wrong.

| Path | What it is | Skill |
|---|---|---|
| `website/pages/`, `website/research/`, `website/index.html` | Articles, section pages, long-form research pages and redirect stubs | site-content |
| `website/assets/` | CSS, JS modules, images, fonts, vendored libraries | site-content |
| `website/feed.xml`, `website/sitemap.xml` | Feed (generated from `pages/articles.html`) and sitemap (hand-maintained, checked by `tests/test_sitemap.py`) | site-content |
| `website/trust/`, `website/assets/js/trust.js` | Trust Center: a shell over `/.well-known/trust-center.json` | compliance-pipeline |
| `website/.well-known/` | Published artifacts. Git tracks only `security.txt` and `vdr-trend.json`; the rest is gitignored build output | compliance-pipeline |
| `scripts/` | Artifact generators and gates | compliance-pipeline |
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
