# Show product owners, contracts, live freshness, the CSOs, decision rights and the single role holder in the Trust Center.
REPO: samaydlette.com
STATUS: QUEUED            # QUEUED | IN_PROGRESS | PARKED | DONE | FAILED
ACCEPTANCE: `make check` passes and CodeGuard ran on the PR, plus: `website/trust/index.html` and `website/assets/js/trust.js` render, from the signed JSON: every product with owner role, contract version, freshness target, consumers and a live within/outside-target status; the CSO and shared-services structure; global and local rules with who may change each; the decision queue grouped by owner role; the registry's holder statement verbatim; and a copy-paste cosign command per product. pa11y passes; `grep -rniE 'certified|authorized system|agency sponsor' website/trust` finds nothing new.
OUT OF SCOPE: Generator changes beyond 019 and 021. Any claim of certification, authorization, an agency sponsor or federal data.
LANDMINES: Measured 2026-10-22 on `main` @ 985fe06: `trust.js` already re-checks live freshness for the runtime signal, nightly and corroboration (`evaluateRuntime`, `evaluateNightly`, `evaluateCorroboration` at L56-98; `recheckLive` at L254); reuse that pattern. The JSON is the source of truth, not the HTML. Pages are inventoried, so this changes their hashes in the signal, SSP and VDR; that is expected.
DEPENDS ON: 019, 021
LIVE-EDGE: load https://samaydlette.com/trust/ and confirm each product's status agrees with `curl -s <product url> | jq .emitted_at` against its contract's target.
---
Filed 2026-10-22 from the data-mesh plan (see `backlog/README.md` for the sequence). Phase 2; can run in parallel with 022 and 023.
