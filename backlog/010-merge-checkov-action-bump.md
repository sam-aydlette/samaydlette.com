# Merge checkov-action #420 (12.3125.0→12.3134.0) on its own, then disposition any new Checkov findings before trunk work starts.
REPO: samaydlette.com
STATUS: QUEUED            # QUEUED | IN_PROGRESS | PARKED | DONE | FAILED
ACCEPTANCE: `make check` passes and CodeGuard ran on the PR, plus: #420 is merged; the next approved deploy is green, or every new IaC finding it raises has a POA&M entry in both `data/poam-items.json` and `docs/poam.md` (reconciliation invariants (g) and (h)); the next nightly run is green.
OUT OF SCOPE: Suppressing or skipping a check to make the run pass. Weakening invariant (h). Any other bump.
LANDMINES: Measured 2026-10-22 on `main` @ 985fe06: PR CI never runs the reconciliation gate (the Deploy job is skipped), so a new Checkov check cannot be ruled out before merge. The unattended nightly also runs Checkov (`evidence-nightly.yml` L168) and reconciles (L580), so a new check fails the nightly until it is dispositioned; that is the gate working, and the `alert` job will open an issue. (h) is `check_h_finding_coverage` at `scripts/reconcile.py` L478-511; (g) is `check_g_poam_parity` at L569-588. Change both POA&M registers together.
DEPENDS ON: 009
LIVE-EDGE: `make verify-published` exit 0; `python3 scripts/check-evidence-freshness.py` exit 0.
---
Filed 2026-10-22 from the data-mesh plan (see `backlog/README.md` for the sequence). Phase 0. Landed alone and followed by a deploy so that any new dispositions do not collide with the serialized trunk changes in Phase 2.
