# Vendored third-party asset: Cytoscape.js

Self-hosted so the live boundary map loads no third-party script origin at runtime
(SA-9 external information services / KSI-3IR third-party information resources). The
site's Content-Security-Policy (`script-src 'self'`) would refuse a CDN copy anyway.

| Field | Value |
|-------|-------|
| Library | Cytoscape.js |
| Version | **3.34.3** (pinned) |
| Licence | MIT (`LICENSE`, copied verbatim from the package) |
| Source | npm registry tarball: `https://registry.npmjs.org/cytoscape/-/cytoscape-3.34.3.tgz` |
| Tarball SHA-256 | `5d9e479216ed58a5f1ac639e746fd7d9770c4393f8c355dd133abc90bcc9ff3f` |
| Tarball integrity (npm) | `sha512-yfYGhRcGAntq6YBD583j4n0Eg3jIxvWmZtz/5uz9UYkeIStSlMxuUja+ec5j3iBD8nv1rwaOAYMW09tBdkSeaQ==` (matches the registry's `dist.integrity`) |
| Files vendored | `dist/cytoscape.esm.min.mjs` → `cytoscape.esm.min.js`, `LICENSE` |
| Consumed by | `website/research/authorization-boundary.html` via `assets/js/boundary-map.js` |
| Vendored on | 2026-09-28 |

**Why the rename.** The ES-module build ships as `.mjs`. Browsers refuse a module script
served with a non-JavaScript MIME type, and `.mjs` is not reliably mapped to
`text/javascript` by an S3 sync. The bytes are unchanged; only the extension differs.

**Why this version.** 3.34.3 is the version TAP's own graph panel pins in its
`package-lock.json`, so the static map renders with the same engine that produced its
layout.

## Patching / CVE monitoring (RA-5 / SI-2)

This is a vendored dependency, so it is NOT covered by `package-lock.json` dependency
scanning. To update:

1. Download the new pinned tarball from the npm registry and record its SHA-256 and
   integrity here.
2. Replace `cytoscape.esm.min.js` (from `dist/cytoscape.esm.min.mjs`) and `LICENSE`.
3. Re-verify the live boundary map on the authorization-boundary page renders, pans,
   zooms and traces flows.
4. Bump the `Version` and `Vendored on` fields above.

Watch Cytoscape.js security advisories: https://github.com/cytoscape/cytoscape.js/security/advisories
