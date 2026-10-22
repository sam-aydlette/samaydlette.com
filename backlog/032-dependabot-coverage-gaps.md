# Optional: close the Dependabot coverage gaps without breaking version parity.
REPO: samaydlette.com
STATUS: QUEUED            # QUEUED | IN_PROGRESS | PARKED | DONE | FAILED
ACCEPTANCE: `make check` passes and CodeGuard ran on the PR, plus: `.github/dependabot.yml` covers pip for `requirements-dev.txt` together with a test that fails when a CI-installed pin differs from `requirements-dev.txt`, and covers Terraform in `infrastructure/bootstrap`; tool versions pinned in workflow env are listed as not coverable.
OUT OF SCOPE: Bumping anything.
LANDMINES: Measured 2026-10-22 on `main` @ 985fe06: there is no pip ecosystem entry; a lone ruff bump in `requirements-dev.txt` without the matching CI line (L181) would break parity. Bootstrap pins `hashicorp/aws ~> 5.0` (`infrastructure/bootstrap/main.tf` L13) while the main stack pins `~> 6.58` (`infrastructure/main.tf` L37). Both `.terraform.lock.hcl` files are gitignored. `OPA_VERSION`, `TERRAFORM_VERSION`, `SYFT_VERSION` and `GRYPE_VERSION` are invisible to Dependabot.
DEPENDS ON: 001
LIVE-EDGE: none.
---
Filed 2026-10-22 from the data-mesh plan (see `backlog/README.md` for the sequence). Optional.
