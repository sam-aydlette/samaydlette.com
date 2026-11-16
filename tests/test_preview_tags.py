"""Every listed article carries the tags that make a shared link show a card.

Without them, a link pasted into LinkedIn, Slack or a messenger shows a bare
title or nothing. The tags are copied by hand from the previous article, so
this checks that each page's copy names that page, not the one it came from.
"""
import html
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
SITE = ROOT / 'website'
BASE = 'https://samaydlette.com'
IMAGE = BASE + '/assets/images/brand/logo.png'

CARD_LINK = re.compile(r'<article class="article-card[^"]*">.*?<h3><a href="([^"]+)"', re.S)


def listed_pages():
    index = (SITE / 'pages' / 'articles.html').read_text(encoding='utf-8')
    return CARD_LINK.findall(index)


def _attr(page, pattern):
    m = re.search(pattern, page)
    return html.unescape(m.group(1)) if m else None


def _meta(page, kind, name):
    return _attr(page, rf'<meta {kind}="{re.escape(name)}" content="([^"]*)"')


def _text(fragment):
    return ' '.join(html.unescape(re.sub(r'<[^>]+>', '', fragment)).split())


def problems(page, url):
    """What a page at `url` is missing or has wrong. Empty means it's fine."""
    found = []
    h1 = re.search(r'<h1[^>]*>(.*?)</h1>', page, re.S)
    expected = {
        ('property', 'og:type'): 'article',
        ('property', 'og:url'): url,
        ('property', 'og:image'): IMAGE,
        ('property', 'og:title'): _text(h1.group(1)) if h1 else None,
        ('name', 'twitter:card'): 'summary',
    }
    for (kind, name), want in expected.items():
        got = _meta(page, kind, name)
        if got != want:
            found.append(f'{name} is {got!r}, expected {want!r}')
    canonical = _attr(page, r'<link rel="canonical" href="([^"]*)"')
    if canonical != url:
        found.append(f'canonical is {canonical!r}, expected {url!r}')
    description = _meta(page, 'name', 'description')
    if not description:
        found.append('meta description is missing or empty')
    if _meta(page, 'property', 'og:description') != description:
        found.append('og:description differs from the meta description')
    return found


def test_every_listed_page_has_preview_tags():
    pages = listed_pages()
    assert pages, 'no article cards found in pages/articles.html'
    failures = {}
    for href in pages:
        page = (SITE / href.lstrip('/')).read_text(encoding='utf-8')
        found = problems(page, BASE + href)
        if found:
            failures[href] = found
    assert not failures, (
        f'pages with missing or wrong preview tags: {failures}. Copy the tag '
        'block from another article and point it at this page.')


def test_the_preview_image_exists():
    assert (SITE / IMAGE[len(BASE) + 1:]).is_file()


def test_a_copied_tag_block_is_caught():
    # A new article whose tags were copied from article 30 and not updated.
    page = (SITE / 'pages' / 'article-30.html').read_text(encoding='utf-8')
    page = page.replace('The Network Perimeter Is Not the Boundary</h1>', 'A New Article</h1>')
    found = problems(page, BASE + '/pages/article-31.html')
    assert any(f.startswith('og:url') for f in found)
    assert any(f.startswith('canonical') for f in found)
    assert any(f.startswith('og:title') for f in found)


def test_a_page_without_tags_is_caught():
    page = '<html><head><title>x</title></head><body><h1>x</h1></body></html>'
    assert len(problems(page, BASE + '/pages/article-99.html')) == 7
