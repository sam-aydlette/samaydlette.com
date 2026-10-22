# Add a governed registry of roles and domains, and map every KSI family to exactly one owning domain.
REPO: samaydlette.com
STATUS: QUEUED            # QUEUED | IN_PROGRESS | PARKED | DONE | FAILED
ACCEPTANCE: `make check` passes and CodeGuard ran on the PR, plus: `docs/governance/domains.json` and `infrastructure/schemas/governance-domains.schema.json` exist. The registry holds `roles[]` (role labels only, such as `role:platform-owner`); `domains[]` (platform and change, edge delivery, identity, observability and response, vulnerability and supply chain, risk and authorization, and the Silk Reeling application domain), each with one owning role; `ksi_families` mapping exactly CED, CMT, CNA, IAM, INR, MLA, PIY, RPL, SCR and SVC to one domain each; and a `holder_statement` saying plainly that one person, the operator, holds every role. `pytest tests/test_governance_registry.py` asserts schema validity, that every family in `infrastructure/schemas/ksi-catalog.json` maps to exactly one domain, and that no value looks like a personal name or an email address.
OUT OF SCOPE: Consuming the registry in any generator (016). Decision rights (021).
LANDMINES: Measured 2026-10-22 on `main` @ 985fe06: the catalog's families start at `infrastructure/schemas/ksi-catalog.json` L148 and carry no owner field. Apply the tool-swap test to every domain: it must still exist if a scanner, CDN or CI vendor is swapped, so no domain is named after a tool. Owners are role labels; the repository is public.
DEPENDS ON: none
LIVE-EDGE: none until 016 consumes it.
---
Filed 2026-10-22 from the data-mesh plan (see `backlog/README.md` for the sequence). Phase 1 leaf (runs in parallel with 003, 005 and 006). Work item 1 of the data-mesh plan: ownership as data.
