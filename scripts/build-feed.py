#!/usr/bin/env python3
"""Emit feed.xml from the article index.

The RSS feed was a second hand-written copy of every entry already in
pages/articles.html: same title, link, date, category and summary, typed twice
with nothing checking the two agreed. They had already drifted apart in six
fields by the time this script was written.

This is the same rule the compliance artifacts follow, applied to the site: one
source, everything else derived. The index is the source because it is what the
site actually curates. Its entries carry titles, categories and dates that
deliberately differ from the ones on the articles themselves, so the pages are
NOT the source here -- see the note in the pull request that introduced this.

    python3 scripts/build-feed.py           # rewrite feed.xml
    python3 scripts/build-feed.py --check   # fail if it has drifted
"""
import datetime
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
INDEX = ROOT / 'website/pages/articles.html'
FEED = ROOT / 'website/feed.xml'
BASE = 'https://samaydlette.com'

BEGIN = '<!-- BEGIN generated: feed items. Built by scripts/build-feed.py; do not edit by hand. -->'
END = '<!-- END generated: feed items -->'

ENTRY = re.compile(r'<article class="article-card">(.*?)</article>', re.S)

# Entities the index may carry that XML does not define. RSS descriptions and
# titles are text, so these resolve to the character rather than being passed
# through and breaking every reader's parser.
ENTITIES = {
    '&rsquo;': '’', '&lsquo;': '‘', '&ldquo;': '“', '&rdquo;': '”',
    '&mdash;': '—', '&ndash;': '–', '&hellip;': '…', '&nbsp;': ' ',
}


def text(fragment):
    """Visible text of an index fragment, with entities resolved and XML escaped.

    Markup is stripped before escaping, because the input is an HTML fragment
    from the index and its tags are markup rather than content. A consequence
    worth knowing: a literal `<` followed later by a `>` in a title or blurb
    would be read as a tag and dropped rather than escaped. No entry does that
    today, and prose that needs a real angle bracket should write &lt; in the
    index, which survives this intact.
    """
    s = re.sub(r'<[^>]+>', '', fragment)
    for ent, ch in ENTITIES.items():
        s = s.replace(ent, ch)
    s = s.replace('&amp;', '&')
    s = re.sub(r'\s+', ' ', s).strip()
    return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def one(fragment, pattern):
    m = re.search(pattern, fragment, re.S)
    return text(m.group(1)) if m else None


def entries():
    html = INDEX.read_text()
    out = []
    for frag in ENTRY.findall(html):
        url = re.search(r'<h3><a href="([^"]+)"', frag)
        if not url:
            continue
        date = one(frag, r'class="article-date"[^>]*>(.*?)<')
        out.append({
            'url': url.group(1),
            'title': one(frag, r'<h3><a[^>]*>(.*?)</a>'),
            'category': one(frag, r'class="article-category"[^>]*>(.*?)<'),
            'date': date,
            'pub': datetime.datetime.strptime(date, '%Y-%m-%d').strftime(
                '%a, %d %b %Y 00:00:00 +0000'),
            'description': one(frag, r'</h3>\s*<p>(.*?)</p>'),
        })
    return out


def render(items):
    template = (
        '    <item>\n'
        '      <title>%(title)s</title>\n'
        '      <link>' + BASE + '%(url)s</link>\n'
        '      <guid>' + BASE + '%(url)s</guid>\n'
        '      <pubDate>%(pub)s</pubDate>\n'
        '      <category>%(category)s</category>\n'
        '      <description>%(description)s</description>\n'
        '    </item>\n')
    return ''.join(template % it for it in items)


def main():
    check = '--check' in sys.argv
    items = entries()
    cur = FEED.read_text()
    i, j = cur.index(BEGIN), cur.index(END)
    new = cur[:i] + BEGIN + '\n' + render(items) + cur[j:]

    print('%d entries in the index' % len(items))
    if new == cur:
        print('feed.xml is up to date')
        return 0
    if check:
        print('DRIFT: feed.xml does not match the article index.')
        print('Run: python3 scripts/build-feed.py')
        return 1
    FEED.write_text(new)
    print('wrote website/feed.xml')
    return 0


if __name__ == '__main__':
    sys.exit(main())
