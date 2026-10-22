# Optional: project each component's owner role into its resource tags and reconcile it live.
REPO: samaydlette.com
STATUS: QUEUED            # QUEUED | IN_PROGRESS | PARKED | DONE | FAILED
ACCEPTANCE: `make check` passes and CodeGuard ran on the PR, plus: Terraform sets `OwnerRole` per resource from the service model; invariant (i) reconciles the per-component owner role against live tags; `terraform plan` shows tag-only changes. Because this is a reviewed artifact change it also requires an approved deploy, `make verify-published` exit 0, and the served artifact carrying the merge commit and a fresh `emitted_at`.
OUT OF SCOPE: Changing any non-tag attribute.
LANDMINES: Measured 2026-10-22 on `main` @ 985fe06: `OwnerRole` is a provider default tag at `infrastructure/main.tf` L67; invariant (i) maps it at `scripts/reconcile.py` L217.
DEPENDS ON: 017
LIVE-EDGE: `make reconcile RECONCILE_FLAGS=--live` passes (i).
---
Filed 2026-10-22 from the data-mesh plan (see `backlog/README.md` for the sequence). Optional.
