# =============================================================================
# Root Makefile — the uniform verification interface for this repo.
# =============================================================================
# Four verbs, the same in every project:
#
#   make check      the single gate. exit 0 = shippable, non-zero = not.
#   make test       unit/integration suite
#   make lint       real-bug lint (pyflakes + bugbear)
#   make fmt        format (opt-in; NOT part of check — see the target)
#
# `make check` is hermetic: no AWS, no network, no Terraform state, no
# generated artifacts. It runs anywhere a clone exists, which is what makes it
# usable as an automated gate. Read the exit code, not the output.
#
# This file WRAPS what already exists. The policy/reconciliation/figure gates
# live in infrastructure/Makefile and are delegated to, never reimplemented.
#
# ---------------------------------------------------------------------------
# What is deliberately NOT in `check`
# ---------------------------------------------------------------------------
# Nothing here calls AWS, `terraform plan`, `terraform apply`, or
# `make pipeline`. In particular `make pipeline` (in infrastructure/) is
# `dev-setup validate plan deploy` — it DEPLOYS TO PRODUCTION. It is not a
# verification step and must never be reachable from `check`.
#
# `reconcile` and `figures-check` are also excluded, for a different reason:
# they consume generated artifacts (ksi-signal.json, oscal-ssp.json, ...) which
# are built by scripts/build-ksi-signal.py from `terraform output -json` /
# `terraform show -json`, i.e. they need AWS credentials and remote state. They
# cannot run in a fresh clone. They are CI-enforced on every deploy, and are
# available here as `make check-full` for when the artifacts are present.
# =============================================================================

.PHONY: help dev-setup check check-full test lint typecheck fmt test-policies \
        reconcile figures-check require-tools require-artifacts

VENV     := .venv
VENV_PY  := $(VENV)/bin/python

# ---------------------------------------------------------------------------
# Tool resolution — explicit, never ambient PATH.
# ---------------------------------------------------------------------------
# A gate that only works in one shell is not a gate. The interpreter is chosen
# at parse time, in this order:
#
#   1. .venv/bin/python  — the local path, created by `make dev-setup`
#   2. python3           — the CI path, where the workflow does
#                          `pip install --user pytest ... ruff==... mypy==...`
#
# Tools are then invoked as `$(PY) -m ruff` / `-m mypy` / `-m pytest`, which is
# exactly how CI invokes them. A bare `ruff` or `mypy` off PATH is never used,
# so a stray global install cannot silently change what this gate means.
#
# Run `make -n check` to see the resolved interpreter in every command.
PY := $(shell if [ -x "$(VENV_PY)" ]; then echo "$(VENV_PY)"; else echo "python3"; fi)

help:
	@echo "Verification interface:"
	@echo "  make check       - THE GATE: lint + typecheck + test + test-policies"
	@echo "                     hermetic (no AWS/network/artifacts). exit 0 = shippable."
	@echo "  make check-full  - check + reconcile + figures-check"
	@echo "                     needs generated artifacts (see 'make check-full')"
	@echo "  make test        - Python unit/integration suite (tests/)"
	@echo "  make lint        - ruff check scripts/ tests/"
	@echo "  make typecheck   - mypy scripts/"
	@echo "  make fmt         - ruff format scripts/ tests/ (opt-in, rewrites files)"
	@echo "  make dev-setup   - create .venv and install requirements-dev.txt"
	@echo ""
	@echo "Resolved Python: $(PY)"

# ---------------------------------------------------------------------------
# Local environment
# ---------------------------------------------------------------------------
dev-setup:
	@echo "Creating $(VENV) and installing requirements-dev.txt (CI's pins)..."
	python3 -m venv $(VENV)
	$(VENV_PY) -m pip install --quiet --upgrade pip
	$(VENV_PY) -m pip install --quiet -r requirements-dev.txt
	@echo "✅ dev-setup complete. Tools: $$($(VENV_PY) -m ruff --version), mypy $$($(VENV_PY) -m mypy --version)"

# Fail closed, and say exactly what to do about it. This fires when neither
# .venv nor a --user install provides the tools.
require-tools:
	@$(PY) -m ruff --version >/dev/null 2>&1 \
	  && $(PY) -m mypy --version >/dev/null 2>&1 \
	  && $(PY) -m pytest --version >/dev/null 2>&1 \
	  || { \
	    echo "❌ Python dev tools not found (tried: $(PY))."; \
	    echo "   No $(VENV_PY), and 'python3 -m ruff/mypy/pytest' is unavailable."; \
	    echo "   Run:  make dev-setup"; \
	    exit 1; \
	  }
	@command -v opa >/dev/null 2>&1 \
	  || { \
	    echo "❌ 'opa' not found on PATH, and 'make check' runs the policy suite."; \
	    echo "   Install the version pinned in .github/workflows/deploy-with-opa.yml"; \
	    echo "   (OPA_VERSION / OPA_SHA256). An older opa cannot parse these Rego v1"; \
	    echo "   policies and will fail with rego_parse_error."; \
	    exit 1; \
	  }

# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------
# Ordered cheapest-and-most-specific first, so the fastest signal comes back
# soonest. Each sub-gate is a separate recipe line: make stops at the first
# non-zero exit, so first failure wins regardless of -j.
check: require-tools
	@$(MAKE) --no-print-directory lint
	@$(MAKE) --no-print-directory typecheck
	@$(MAKE) --no-print-directory test
	@$(MAKE) --no-print-directory test-policies
	@echo "✅ check: PASS"

# check + the artifact-dependent gates. Run this where the generated artifacts
# exist (after a build, or in CI's deploy job). It FAILS LOUDLY when they are
# absent rather than skipping: a gate that quietly downgrades itself to a no-op
# is how stale artifacts go unnoticed.
check-full: check require-artifacts
	@$(MAKE) --no-print-directory reconcile
	@$(MAKE) --no-print-directory figures-check
	@echo "✅ check-full: PASS"

require-artifacts:
	@missing=""; \
	for f in ksi-signal.json oscal-ssp.json oscal-poam.json vdr-report.json; do \
	  [ -f "infrastructure/$$f" ] || missing="$$missing infrastructure/$$f"; \
	done; \
	if [ -n "$$missing" ]; then \
	  echo "❌ check-full needs generated artifacts that are missing:"; \
	  for f in $$missing; do echo "     $$f"; done; \
	  echo "   These are gitignored build products, derived from 'terraform output -json'"; \
	  echo "   by scripts/build-ksi-signal.py — they need AWS credentials and remote state."; \
	  echo "   CI builds and enforces them on every deploy."; \
	  echo "   For a hermetic gate that needs none of this, run:  make check"; \
	  exit 1; \
	fi

# ---------------------------------------------------------------------------
# Sub-gates
# ---------------------------------------------------------------------------
# Scopes below match CI exactly (deploy-with-opa.yml): ruff over scripts/ AND
# tests/, mypy over scripts/ only. Widening a scope here without widening it
# there would make local green stop predicting CI green.
lint:
	@echo "==> lint (ruff)"
	$(PY) -m ruff check scripts/ tests/

typecheck:
	@echo "==> typecheck (mypy)"
	$(PY) -m mypy scripts/

test:
	@echo "==> test (pytest)"
	$(PY) -m pytest tests/ -q

# Delegated to infrastructure/Makefile: opa fmt + coverage floor + policy tests.
test-policies:
	@echo "==> test-policies (opa)"
	@$(MAKE) --no-print-directory -C infrastructure test-policies

# Artifact-dependent; reachable via check-full, never via check.
reconcile:
	@echo "==> reconcile"
	@$(MAKE) --no-print-directory -C infrastructure reconcile

figures-check:
	@echo "==> figures-check"
	@$(MAKE) --no-print-directory -C infrastructure figures-check

# ---------------------------------------------------------------------------
# fmt — opt-in, and deliberately NOT wired into check.
# ---------------------------------------------------------------------------
# WARNING: CI does not run `ruff format`, and this codebase has never been
# formatted with it. As of this writing it would rewrite 70 of 71 files under
# scripts/ + tests/. Running this produces an enormous, purely-cosmetic diff
# that no gate asks for. It is here for interface uniformity; think before you
# use it, and never mix its output into a substantive change.
#
# For Terraform/Rego formatting (which CI DOES enforce via `opa fmt --fail`),
# use: make -C infrastructure fmt

# The RSS feed is generated from the article index; this fails if the committed
# feed no longer matches it. Same shape as figures-check: derived artifacts are
# regenerated, never hand-edited.
feed-check:
	@echo "Checking the feed against the article index..."
	python3 scripts/build-feed.py --check

fmt:
	@echo "==> fmt (ruff format) — rewrites files under scripts/ and tests/"
	$(PY) -m ruff format scripts/ tests/
