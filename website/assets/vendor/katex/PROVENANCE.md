# Vendored third-party asset: KaTeX

Self-hosted to remove a runtime dependency on `cdn.jsdelivr.net` (SA-9 external
information services / KSI-3IR third-party information resources). No third-party
script origin is loaded at runtime; the site serves these from its own bucket.

| Field | Value |
|-------|-------|
| Library | KaTeX |
| Version | **0.16.11** (pinned) |
| Source | npm registry tarball: `https://registry.npmjs.org/katex/-/katex-0.16.11.tgz` |
| Tarball SHA-256 | `8c5494c5f7d8e8bf73ff3fe64d4bd09a340e4878b7eec9bbd9ef8d8f3e24193f` |
| Files vendored | `katex.min.js`, `contrib/auto-render.min.js` → `auto-render.min.js`, `katex.min.css`, `fonts/*` (60 files) |
| Consumed by | `website/research/tuning-the-eigenvalue.html` via `katex-init.js` |
| Vendored on | 2026-06-26 |

## Patching / CVE monitoring (RA-5 / SI-2)
This is a vendored dependency, so it is NOT covered by `package-lock.json` dependency
scanning. To update:

1. Download the new pinned tarball from the npm registry and record its SHA-256 here.
2. Replace `katex.min.js`, `auto-render.min.js`, `katex.min.css`, and `fonts/*`.
3. Re-verify the eigenvalue research page renders math correctly.
4. Bump the `Version` and `Vendored on` fields above.

Watch KaTeX security advisories: https://github.com/KaTeX/KaTeX/security/advisories
