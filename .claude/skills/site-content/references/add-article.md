# Add an article: checklist

A small task (CLAUDE.md §1). Do these steps and nothing else. Copy markup from the files themselves rather than from memory, because the files are the template.

## 1. The page: `website/pages/article-N.html`

- **N** is one more than the highest existing `article-N.html`. Retired numbers stay retired (23 is a redirect stub).
- Copy the newest article that isn't a stub, then change only:
  - `<title>`: `<Title> - Sam Aydlette`
  - `.article-date`: long form, for example `September 25, 2026`
  - `.article-category`: reuse an existing category unless the operator names a new one
  - `h1.article-title`
  - the body inside `.article-content`, keeping the `.disclaimer` block first and verbatim
- Remove the template's figures and series nav unless they apply.
- Images go in `website/assets/images/` with alt text. Inline SVG follows the `article-29.html` pattern (`role="img"`, `aria-labelledby` pointing at `<title>` and `<desc>`).
- Don't change the `?v=` values you copied; CI rewrites them.

## 2. The index: `website/pages/articles.html`

- Add an `<article class="article-card">` at the **top** (newest first). Copy the first card and change:
  - `.article-date`: ISO, `YYYY-MM-DD`
  - `.article-category`, the `h3` link and title, and the one-paragraph summary `<p>`
  - the `.read-more` link. Its text is a short `snake_case.md` label, for example `the_knot.md`
- The index title, category and date may intentionally differ from the page's own; this card is what the feed uses.
- The summary is the operator's words. Draft one only if asked, and flag it in the PR.

## 3. The feed: `website/feed.xml`

- Run `python3 scripts/build-feed.py`. Never edit the generated block by hand.
- `make feed-check` (or `make check`) confirms the feed matches the index.

## 4. The homepage: `website/index.html`, "Recent Articles"

- It shows exactly three cards, newest first. The first is `article-card featured`, with an extra `div.article-content` wrapper and a `.read-more` link that has `aria-label="Read full article: <Title>"` and the text `Read Article`.
- Add the new article as the featured card. Turn the previous featured card into a regular card (drop `featured` and the wrapper), and remove the third card.
- `tests/test_homepage_recent_articles.py` fails until these match the first three index entries.

## 5. The sitemap: `website/sitemap.xml`

- Add a `<url>` above the newest article entry: `<loc>https://samaydlette.com/pages/article-N.html</loc>`, `<lastmod>` with the publish date (`YYYY-MM-DD`), `<changefreq>monthly</changefreq>`, `<priority>0.8</priority>`.
- `tests/test_sitemap.py` fails until the new page is listed.

## 6. Series (only if the article belongs to one)

- Add the article to the `series-navigation` nav on **every** article in the series, and mark the new page's own entry with `current` and `aria-current="page"`.

## 7. Verify

- `make check`
- `make preview`: open the new page, `articles.html` and the homepage.
- PR: one PR titled `content: add article N, "<Title>"`. List any AI-drafted text.
