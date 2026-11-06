---
name: compliance-pipeline
description: Use for any change to the samaydlette.com compliance pipeline. That covers artifact generators and gates in scripts/; registers in data/ (decisions.json); Terraform, OPA policies and Lambdas in infrastructure/, including bootstrap/; GitHub workflows; freshness windows; the boundary map; the Trust Center (website/trust/, trust.js); and anything published under /.well-known/. Not for article or page prose, nav or styling: use site-content for those.
---

# Compliance pipeline

Procedures for changing the pipeline. The invariants and the autonomy rules in `CLAUDE.md` apply on top of everything here. Nearly every task here touches a protected path, so **plan first** (CLAUDE.md §2). Use plan mode for generators, gates and `infrastructure/`.

Supporting files. Read them before planning:

- `references/codebase.md`: what each generator, gate and workflow does, and how they connect.
- `references/pitfalls.md`: failures that have already happened here. Check your plan against it.

## Before you plan

1. Read the generator, its tests and fixtures, and the gate that consumes its output.
2. Search `docs/architecture-decisions.md` and `data/decisions.json` for a decision that already covers the topic.
3. Decide which published artifacts change. If any do, the plan says how you will verify the published result.

## Procedures

### Change a generated artifact

1. Change the generator in `scripts/`, never its output.
2. Every artifact builds from one inventory `signal_id` and carries it.
3. A new artifact published under `/.well-known/` needs a freshness window in `infrastructure/schemas/freshness-config.json`, with who decided it and a review date. Otherwise `tests/test_freshness_config.py` fails. Never put a window back as a literal.
4. Keep one unit test per gate invariant, plus a committed broken fixture that must fail the gate.
5. Shared helpers live in `scripts/_common.py`. Scripts import it through an `__file__`-relative `sys.path.insert`, so each stays standalone-runnable from any cwd. A new shared module is a check-in.
6. Never edit the vendored FedRAMP schemas in `infrastructure/schemas/fedramp-2026-06-24/`. The loader refuses any file whose hash differs from `SOURCES.json`.

### Record a decision about a finding

- Every decision is a record in `data/decisions.json`, read through `scripts/_decisions.py`. Every in-force record carries `decided_by`, `decided_on` and an annual `review_by`; `tests/test_decision_records.py` enforces this.
- Decisions are human. Claude may draft a record, then stops for the operator to confirm who decided and when. A field that was not recorded is published as a gap; never fill it in.
- A dismissed finding is a **false positive** (with justification) or **risk-accepted**. Never drop one.

### Change infrastructure (`infrastructure/`, excluding `bootstrap/`)

1. Run `make -C infrastructure plan` first. The plan in the PR must show only your intended change.
2. Classify any new resource in `docs/boundary/boundary-classification.json` in the same change. Reconciliation invariant (l) fails the deploy on an unclassified component. Never hand-draw the boundary.
3. Run `checkov` per `.checkov.yaml`.
4. Apply policy: an additive, reversible change may be applied after the `terraform plan` review, **if the approved plan names the apply**. For cutovers and deletions, prove the new path works and keep the old one until it does.
5. Recurring cost above ~$2/month is a check-in. WAF is declined on purpose; see `references/pitfalls.md`.
6. Publishing the DNSSEC **DS record** at the registrar is always a human step.

### Change the bootstrap stack (`infrastructure/bootstrap/`)

The operator applies this stack by hand; CI never does. Every build plans it read-only and reports pending changes in the trust center. Its state is remote (`bootstrap/terraform.tfstate` in the state bucket). Its working tree drifts from `main` easily, and an apply from a stale tree silently reverts changes already merged.

1. Before editing it, sync the directory: `git fetch origin && git checkout origin/main -- infrastructure/bootstrap/`.
2. Before any `terraform apply` there, sync again. The plan must show *only* your intended change. Unrelated adds or removes mean the tree is stale: stop and sync.
3. Never apply from a divergent branch.
4. Never apply while a deploy run is in flight. The run plans the trust root before the `prod` approval and reads bootstrap state again after it. Apply first and then start the deploy, or let the run finish and redeploy.
5. If a merged change can't be applied through a synced tree, prefer a surgical, IaC-matching apply over applying a stale stack. Example: the exact `aws iam put-role-policy` the merged config specifies.

A bootstrap apply is a production step. It must be named in the approved plan.

### Touch `evidence-nightly.yml` or its role

It runs twice a day, plus once after every successful deploy to `main`, with **no reviewer**. That is acceptable only because its OIDC role (`infrastructure/bootstrap/evidence-nightly.tf`) is narrow. It can write only `.well-known/vdr-*`, invalidate CloudFront, and make the read-only calls the `--live` reconciliation needs. It cannot apply Terraform, sync the website, delete an object or write anywhere else.

- "The nightly needs one more permission" means: ask whether that work belongs on the unattended path at all. Don't widen the role; check in.
- It refreshes the VDR only, and binds to the **published** inventory. It fetches `/.well-known/ksi-signal.json` and verifies its Sigstore bundle against the deploy workflow's pinned identity. It fetches and verifies the SDR and CPO **as gate inputs only**: never re-signed, never re-published. A changed inventory means changed infrastructure, which belongs on the reviewed deploy path.
- A newly disclosed CVE cannot auto-publish. Invariant (h) requires an in-force decision record for every finding, so the nightly fails until a person dispositions the CVE. That is the gate working; the `alert` job (a GitHub issue) makes the failure visible.
- The `--live` reconciliation runs even when the vulnerability gate has failed, and the alert names which gate stopped the run. Publishing requires both gates to pass.
- The `prod` environment and its reviewer requirement stay as they are.

### Change the Trust Center

- `website/trust/index.html` and `website/assets/js/trust.js` are a presentational shell over `/.well-known/trust-center.json` and `boundary-map.json`. The JSON is the source of truth. To change what it reports, change `scripts/build-trust-center.py`, not the HTML.
- It is written from an Authorizing Official's seat. The site adheres to FedRAMP 20x Class C requirements; it never claims to be certified or authorized.

## Verify

**Ground truth first.** No artifact, pipeline output or Terraform state proves what is deployed. Confirm live state independently with the `aws` CLI (credentials are configured locally) or Steampipe. A check that only re-reads the build does not count. In the PR, state the outcome; never paste live values (the repo is public).

| Command | When |
|---|---|
| `make check` | Always. The exit code is the verdict. `test-policies` needs `opa` at the `OPA_VERSION` pinned in `deploy-with-opa.yml`; see pitfalls |
| `make check-full` | Generator or gate changes, with AWS access. Adds `reconcile` over artifacts built from `terraform output -json`, and fails loudly when they are absent |
| `make -C infrastructure reconcile RECONCILE_FLAGS=--live` | Infrastructure changes. Enumerates live AWS |
| `make -C infrastructure plan` | Before any apply |
| `checkov` per `.checkov.yaml` | Infrastructure changes |
| `make -C infrastructure verify-published` | After a deploy: checks the live evidence from outside |
| `scripts/check-evidence-freshness.py --all <site>` | After a deploy, or when freshness is in doubt |

**Publish freshness.** A green pipeline must publish *this run's* artifacts: the served `/.well-known/*` carries the current commit and a fresh `emitted_at`. A stale serve is a bug, not a cache quirk; verify the post-deploy round-trip.

## Parallel work

- One `git worktree`, branch and directory per concurrent task. Never two agents in one checkout.
- Parallelize the leaves, serialize the trunk. Anything that touches the inventory builder, the reconciliation gate, `data/decisions.json` or a `/.well-known/*` artifact has one owner at a time.
- The fail-closed gate arbitrates conflicts: rebase and regenerate, never weaken the gate.
- Fan read-only investigation out to subagents, and keep artifact-mutating work to one owner per artifact.
- Realistic parallelism here is a handful of genuinely independent tasks.
