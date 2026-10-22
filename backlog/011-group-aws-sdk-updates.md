# Group the `@aws-sdk/*` Dependabot updates into one PR and retire the five overlapping SDK PRs.
REPO: samaydlette.com
STATUS: QUEUED            # QUEUED | IN_PROGRESS | PARKED | DONE | FAILED
ACCEPTANCE: `make check` passes and CodeGuard ran on the PR, plus: `.github/dependabot.yml` has a `groups:` entry matching `@aws-sdk/*` under the `/infrastructure/lambda` npm entry; #419, #421, #422, #423 and #410 are closed by the operator with a comment naming the grouped PR as the successor; the grouped PR is merged; `jq -r '.packages|to_entries[]|select(.key|test("@aws-sdk/client-"))|.value.version' infrastructure/lambda/package-lock.json | sort -u` prints one version.
OUT OF SCOPE: Major SDK upgrades. Other npm directories. Changing the Lambda's code.
LANDMINES: Measured 2026-10-22 on `main` @ 985fe06: the four Dependabot PRs (3.1138.0→3.1151.0) all edit one lockfile and conflict with each other after the first merge; human PR #410 (3.1146.0) overlaps all four and is behind them. The lockfile feeds the canonical inventory (`scripts/build-ksi-signal.py` L1645), so the merged bump changes component purls in the signed KSI signal, SSP and VDR at the next deploy. POAM-035 (sprintf-js 1.1.3, a false positive) arrives through opa-wasm, not the SDK; confirm with `grep -n sprintf infrastructure/lambda/package-lock.json` that the bump leaves it alone, because invariant (b) resolves its affected-asset string against the inventory.
DEPENDS ON: none
LIVE-EDGE: after the next approved deploy, `curl -s https://samaydlette.com/.well-known/ksi-signal.json | jq '[.components[]|select((.purl//"")|test("aws-sdk"))|.purl]'` shows the new versions.
---
Filed 2026-10-22 from the data-mesh plan (see `backlog/README.md` for the sequence). Phase 0. Closing PRs is an operator action; this task only names them.
