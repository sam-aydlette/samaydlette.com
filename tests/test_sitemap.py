"""The sitemap must list every live page, and nothing else.

sitemap.xml is maintained by hand, and nothing checked it. By the time this test
was written it was missing eight live pages: four articles, the contact page
and three research pages. Article 22, linked from every article's disclaimer,
was among them. A redirect stub or a noindex page is not a live page.
"""
import pathlib
import re
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]
SITE = ROOT / 'website'
SITEMAP = SITE / 'sitemap.xml'
BASE = 'https://samaydlette.com/'
NS = {'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9'}

# Live pages deliberately left out of the sitemap, each with its reason.
NOT_LISTED = {
    '404.html': 'error page',
    'pages/success.html': 'contact-form confirmation',
    'silk-reeling-mirror.html': 'app shell behind a login',
}

STUB = re.compile(r'http-equiv="refresh"|name="robots"\s+content="noindex', re.I)


def live_pages():
    pages = set()
    for f in SITE.rglob('*.html'):
        rel = f.relative_to(SITE).as_posix()
        if rel.startswith('.well-known/'):
            continue
        if STUB.search(f.read_text(encoding='utf-8', errors='replace')):
            continue
        pages.add(rel)
    return pages


def listed_pages():
    root = ET.parse(SITEMAP).getroot()
    locs = [el.text.strip() for el in root.findall('sm:url/sm:loc', NS)]
    assert all(loc.startswith(BASE) for loc in locs), 'every <loc> is on ' + BASE
    return [loc[len(BASE):] for loc in locs]


def test_every_live_page_is_in_the_sitemap():
    missing = live_pages() - set(listed_pages()) - set(NOT_LISTED)
    assert not missing, (
        f'live pages missing from sitemap.xml: {sorted(missing)}. Add a <url> '
        'entry, or add the page to NOT_LISTED with the reason it is left out.')


def test_the_sitemap_lists_only_live_pages():
    extra = set(listed_pages()) - live_pages()
    assert not extra, f'sitemap.xml lists pages that are missing or stubs: {sorted(extra)}'


def test_no_page_is_listed_twice():
    listed = listed_pages()
    assert len(listed) == len(set(listed))


def test_every_exclusion_is_still_a_live_page():
    assert set(NOT_LISTED) <= live_pages(), 'drop stale NOT_LISTED entries'
