---
name: site-content
description: Use when writing, editing, adding, retiring or restyling anything a visitor reads on samaydlette.com. That covers articles (website/pages/article-N.html); long-form research pages; the home, articles, books, projects, about and contact pages; the nav and footer; CSS and JS under website/assets; feed.xml; and sitemap.xml. Not for the Trust Center, /.well-known artifacts, generators, gates, Terraform or workflows: use compliance-pipeline for those.
---

# Site content

How to change what visitors read. The invariants and autonomy rules in `CLAUDE.md` apply on top of this.

## Voice and authorship: read first

- **The opinions are the operator's.** Draft toward the position they have stated, and never supply one. If the position isn't clear, ask rather than fill the gap.
- Draft only what was requested and leave final wording to the operator. List AI-drafted passages in the PR so they can rework them in their own voice.
- Don't "improve" prose you weren't asked to touch: no tightening, retitling or restructuring of neighboring text.
- Every article and long-form page carries the disclaimer, worded identically on every page. Copy it verbatim from an existing article (`<div class="disclaimer">`, which links "outsourcing my opinions" to `/pages/article-22.html`). Change its wording only when asked, and then change every copy in one PR.
- Claims about the system (encryption, controls, authorization) must match deployed config. Never assert a service's FedRAMP status without a current source, and never imply the site is authorized.

## What a content change really is

- **Every `*.html` under `website/` is hashed into the compliance inventory.** Editing or adding a page changes the inventory on the next deploy. That is expected and automatic. Never touch `website/.well-known/` or an inventory entry by hand.
- **Cache-busting is automatic.** The deploy rewrites the `?v=` value on every CSS and JS reference. Don't hand-edit those values or commit `npm run cache-bust` output.
- **The CSP is strict:** `script-src 'self'`, `style-src 'self'`, `img-src 'self' data:`, `font-src 'self'`, no frames. That means no inline `<script>`, `<style>`, `style=""` or `on*=` attributes, and every asset is self-hosted. A new external origin is an infrastructure change (`compliance-pipeline`), so it is a check-in.
- **The site sends COEP**, so cross-origin embeds break. Link to external media instead of embedding it. The site's video is linked, not embedded, for this reason.
- **Accessibility gates the deploy.** CI renders every page with pa11y (WCAG 2 AA), and an OPA policy decides pass or fail. Give images alt text. For inline SVG figures, follow `pages/article-29.html`: `role="img"` with `aria-labelledby` pointing at a `<title>` and `<desc>`.
- **Vendored libraries** (`assets/vendor/`: KaTeX, Cytoscape) each carry a `PROVENANCE.md`. Adding or upgrading one is a supply-chain change, so it is a check-in.

## Procedures

### Add an article *(small task)*

Follow `references/add-article.md`. It always touches five files: the new page, `pages/articles.html`, `feed.xml` (regenerated), `index.html` and `sitemap.xml`. It also touches the series nav when the article belongs to a series.

### Edit an article *(small task)*

- Change only what was asked.
- The entries in `pages/articles.html` deliberately differ from the pages' own titles, categories and dates (see the `scripts/build-feed.py` docstring). Don't sync them.
- If you changed an index entry, regenerate the feed: `python3 scripts/build-feed.py`.

### Retire an article or page *(small task, when the operator asked for it)*

Follow the article-23 precedent (#341). Keep the URL alive; don't delete the file.

1. Replace the page with a redirect stub: `<link rel="canonical">`, `<meta name="robots" content="noindex">`, a one-line "superseded by" link, and `<meta http-equiv="refresh">` with a **relative** URL. A root-relative URL resolves to a missing path under `file://`, which is how the accessibility scanner renders pages, and the resulting error page fails the gate. Copy `pages/article-23.html`.
2. Remove the page from `pages/articles.html` and regenerate the feed.
3. Remove it from `index.html` and `sitemap.xml`. `tests/test_sitemap.py` fails while a stub is still listed.
4. Delete assets that nothing else references.
5. Fix links to it from other articles.

### Long-form research pages

- These live in `website/research/`. `tuning-the-eigenvalue.html` and `the-plumbing.html` are redirect stubs.
- Research pages are listed in `pages/articles.html` alongside articles, so they reach the feed the same way.
- `make essay-check` runs the structural checks in `tools/essay/`: HTML balance, duplicate ids, footnote and backlink parity, broken anchors, and bibliography and citation parity. They run **locally only**; never wire them into CI.
- `tools/essay/paths.py` is the one place those tools name a file. Renaming the essay means updating it.
- Renumber footnotes with `python3 tools/essay/renumber.py`, never by hand.
- The prose tooling (`prose_stats.py`, `ed.py`, `cut.py`) was deleted on purpose. Don't reintroduce it, or anything like it, unless asked.

### Change site chrome (head, header, nav, footer)

Not small: it touches every page, so plan first.

- There is no include system. Every page carries its own copy of the header, nav and footer, so a chrome change means editing every copy in one PR.
- Before editing, count the copies (for example, `grep -l 'class="main-nav"' -r website | wc -l`). After editing, confirm the same count carries the new markup.
- Articles in a series also carry a `series-navigation` nav. Leave it alone unless asked.
- Don't introduce a templating or build system to remove the duplication unless asked. That is an architecture decision, so it is a check-in.

### Styling and scripts

- CSS: `assets/css/main.css`, plus `articles.css` on article pages. JS: `assets/js/main.js` (ES module entry), `components/` and `utils/`. `theme-init.js` loads in `<head>` to prevent a theme flash.
- No new framework, library or build step without a check-in.

## Verify

- `make check`: always. It includes the test that the feed matches `pages/articles.html`.
- `make preview`: serves `website/` at http://127.0.0.1:8000 and reloads on save. Open every page you changed, and toggle the theme once if you changed CSS.
- `make essay-check`: whenever you changed a long-form page.
- Accessibility runs in CI on deploy. To run it locally: `cd tools/a11y && npm ci && node scan.js ../../website`. It needs Chrome, and it produces facts; the policy decides pass or fail.
- In the PR's **Verified** section, list the commands you ran and the pages you opened.
