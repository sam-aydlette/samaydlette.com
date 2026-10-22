# Declare the service model: CSP → CSO → Feature → Service, with services keyed to the existing boundary groups.
REPO: samaydlette.com
STATUS: QUEUED            # QUEUED | IN_PROGRESS | PARKED | DONE | FAILED
ACCEPTANCE: `make check` passes and CodeGuard ran on the PR, plus: `docs/portfolio/service-model.json` and its schema exist. It names the CSP; the CSOs `website` (`urn:samaydlette:cso:website`) and `silk-reeling` (`urn:samaydlette:cso:silk-reeling`); `features[]`, each belonging to one CSO; `services[]`, each keyed by a boundary group key with an `owner_domain` and `consumed_by` (CSOs or features); and the shared-services product id (`urn:samaydlette:shared-services`). A test asserts that every group key in `docs/boundary/boundary-classification.json` is exactly one service and that every `owner_domain` exists in the 013 registry.
OUT OF SCOPE: Generator changes (016, 018). Changing the boundary groups themselves.
LANDMINES: Measured 2026-10-22 on `main` @ 985fe06: the 11 groups are at `docs/boundary/boundary-classification.json` L11-34 and already map components to groups with `match` globs, which is why services are keyed to them rather than redeclared. External groups (github, sigstore, vuln-feeds, ai-provider) are services too. `ai-provider` is consumed only by Silk Reeling (POAM-020). Shared services (audit, trust-root, compliance, watchdog, github, sigstore, vuln-feeds) are consumed by both CSOs and are published once (018).
DEPENDS ON: 013
LIVE-EDGE: none until 018 publishes from it.
---
Filed 2026-10-22 from the data-mesh plan (see `backlog/README.md` for the sequence). Phase 1 leaf. Work item 3 of the data-mesh plan. The operator chose one authorization boundary containing two CSOs, with shared services published once and referenced.
