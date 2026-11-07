"""The homepage's "Recent Articles" must be the newest three index entries.

The homepage cards are a third hand-typed copy of the article index (after the
index itself and the feed, which is now generated). Adding an article means
updating them by hand, so this checks the copy instead of trusting it.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
HOME = ROOT / 'website' / 'index.html'
INDEX = ROOT / 'website' / 'pages' / 'articles.html'

LINK = re.compile(r'<h3><a href="([^"]+)"')
CARD = re.compile(r'<article class="([^"]*)"')


def recent_section():
    html = HOME.read_text(encoding='utf-8')
    start = html.index('Recent Articles')
    end = html.index('View All Articles', start)
    return html[start:end]


def test_homepage_shows_the_three_newest_index_entries():
    shown = LINK.findall(recent_section())
    newest = LINK.findall(INDEX.read_text(encoding='utf-8'))[:3]
    assert shown == newest, (
        f'homepage shows {shown}, but the index starts with {newest}. '
        'Update the Recent Articles cards in website/index.html.')


def test_only_the_first_card_is_featured():
    classes = CARD.findall(recent_section())
    assert len(classes) == 3
    assert 'featured' in classes[0].split()
    assert not any('featured' in c.split() for c in classes[1:])
