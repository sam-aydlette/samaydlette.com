# Vendored third-party assets: Inter + JetBrains Mono web fonts

Self-hosted to remove a runtime dependency on Google Fonts
(`fonts.googleapis.com` for CSS + `fonts.gstatic.com` for the woff2 files) — a
third-party origin (SA-9 external information services / KSI-3IR). The site now
serves these from its own bucket, so the strict CSP keeps `style-src 'self'` and
`font-src 'self'`.

| Field | Value |
|-------|-------|
| Families | Inter, JetBrains Mono |
| Weights | 300, 400, 500, 600, 700 (normal) |
| Subsets | latin, latin-ext (English site; CJK on the separate app falls back to system fonts) |
| Source | Google Fonts `css2` API → `fonts.gstatic.com` woff2 |
| @font-face CSS | `assets/css/fonts.css` (replaces the former `@import` in `main.css`) |
| Files | 20 × `.woff2` under `assets/fonts/{inter,jetbrains-mono}/` |
| Vendored on | 2026-06-29 |

## Updating (RA-5 / SI-2)
These are vendored, so not covered by `package-lock.json` scanning. To refresh:

1. Re-fetch the Google Fonts `css2` URL with a modern browser User-Agent.
2. Re-download the `latin` + `latin-ext` woff2 files and overwrite those under
   `assets/fonts/`.
3. Regenerate the `@font-face` blocks in `assets/css/fonts.css` (preserve each
   `unicode-range` so the browser only fetches the subset it needs).
4. Bump `Vendored on` above.
