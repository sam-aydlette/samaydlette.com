# Add reconciliation invariant (m): every component and every KSI has exactly one owning domain.
REPO: samaydlette.com
STATUS: QUEUED            # QUEUED | IN_PROGRESS | PARKED | DONE | FAILED
ACCEPTANCE: `make check` passes and CodeGuard ran on the PR, plus: `check_m_ownership` is registered in `run_all`, `INVARIANT_TITLES` and the summary strings in `scripts/reconcile.py`; it fails on a component or KSI with no domain, on a domain unknown to the registry, and on a service with no owner; the committed broken fixture gains an ownerless component and still fails; the clean fixture passes; a dedicated test covers each failure case. Because this is a reviewed artifact change it also requires an approved deploy, `make verify-published` exit 0, and the served artifact carrying the merge commit and a fresh `emitted_at`.
OUT OF SCOPE: Weakening, reordering or special-casing any existing invariant.
LANDMINES: Measured 2026-10-22 on `main` @ 985fe06: `run_all` is at `scripts/reconcile.py` L631-652 and `INVARIANT_TITLES` at L781; registration is by hand in three places. The broken-fixture test (`tests/test_reconcile.py` L222) skips when the fixture directory is missing (L226-227); add an assertion that it exists so the test cannot silently vanish.
DEPENDS ON: 016
LIVE-EDGE: `curl -s https://samaydlette.com/.well-known/reconcile-report.json | jq` lists (m) as passed.
---
Filed 2026-10-22 from the data-mesh plan (see `backlog/README.md` for the sequence). Phase 2 trunk, serialized.
