#!/usr/bin/env python3
"""Structural gate for the long-form research pages. Must stay clean through the prose pass.

Covers every file in FILES: tag balance, duplicate ids, footnote ref/backlink parity,
and anchors that point nowhere.

Anchors are checked *across* files as well as within them. The essay links into the
compliance paper's sections by fragment, and a heading renamed on one side leaves a
dead link on the other that neither file can see on its own. That has happened
twice. A cross-file link is resolved relative to the linking file, so the target
page must exist and must carry the id.
"""
import os
import re
import sys
from html.parser import HTMLParser

FILES = [
    'website/research/staying-in-the-loop.html',
    'website/research/the-plumbing.html',
    # Not long-form, but it links across the site (including to the dashboard), and
    # those edges are worth the same check.
    'website/index.html',
]
# what a leading-slash href is relative to, as the site is served
SITE_ROOT = 'website'
VOID = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta',
        'source', 'track', 'wbr'}
# href="page.html#frag" or href="page.html"
LOCAL = re.compile(r'^([A-Za-z0-9._/-]+\.html)(?:#(.+))?$')


class P(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.errs = []

    def handle_starttag(self, t, a):
        if t not in VOID:
            self.stack.append(t)

    def handle_endtag(self, t):
        if t in VOID:
            return
        if self.stack and self.stack[-1] == t:
            self.stack.pop()
        else:
            self.errs.append(t)


def ids_of(path, _cache={}):
    """Every id in a page, or None if the page is not there."""
    if path not in _cache:
        try:
            _cache[path] = set(re.findall(r'id="([^"]+)"', open(path).read()))
        except OSError:
            _cache[path] = None
    return _cache[path]


def check(path):
    """Return (summary line, [failures]) for one page."""
    h = open(path).read()
    p = P()
    p.feed(h)

    ids = re.findall(r'id="([^"]+)"', h)
    dupes = {i for i in ids if ids.count(i) > 1}
    notes = {int(x) for x in re.findall(r'id="fn(\d+)"', h)}
    refs = {int(x) for x in re.findall(r'href="#fn(\d+)"', h)}
    backs = {int(x) for x in re.findall(r'href="#fnref(\d+)"', h)}
    hrefs = set(re.findall(r'href="([^"]+)"', h))
    anchors = {a[1:] for a in hrefs if a.startswith('#')}
    broken = sorted(a for a in anchors if a not in ids)

    # Containment. Parity is not placement: a note that has drifted out of the
    # footnotes section still has its id, its reference and its backlink, so every
    # other check here passes while the note renders wherever it landed. Two of
    # them once ended up inside the footer's link list and shipped as navigation
    # bullets. Anchor at the <ol> rather than </section> so a nested </section>
    # cannot end the range early.
    stray = []
    if '<section id="footnotes"' in h:
        s = h.index('<section id="footnotes"')
        e = h.index('</ol>', s) if '</ol>' in h[s:] else len(h)
        held = {int(x) for x in re.findall(r'<li id="fn(\d+)">', h[s:e])}
        stray = sorted(n for n in notes if n not in held)
    elif notes:
        stray = sorted(notes)

    # cross-file: the target page must exist and must carry the fragment
    here = os.path.dirname(path)
    dead = []
    for href in sorted(hrefs):
        m = LOCAL.match(href)
        if not m:
            continue
        page = m.group(1)
        base = SITE_ROOT if page.startswith('/') else here
        target = os.path.normpath(os.path.join(base, page.lstrip('/')))
        tids = ids_of(target)
        if tids is None:
            dead.append(f'{href} (no such page)')
        elif m.group(2) and m.group(2) not in tids:
            dead.append(f'{href} (no such id)')

    fail = []
    if p.errs:
        fail.append(f"unbalanced end tags: {p.errs[:8]}")
    if p.stack:
        fail.append(f"unclosed tags: {p.stack[:8]}")
    if dupes:
        fail.append(f"duplicate ids: {sorted(dupes)[:8]}")
    if refs - notes:
        fail.append(f"refs with no footnote: {sorted(refs - notes)}")
    if notes - refs:
        fail.append(f"footnotes never referenced: {sorted(notes - refs)}")
    if notes - backs:
        fail.append(f"footnotes missing backlink: {sorted(notes - backs)}")
    if broken:
        fail.append(f"broken anchors: {broken[:8]}")
    if stray:
        fail.append(f"footnotes outside the footnotes section: {stray[:8]}")
    if dead:
        fail.append(f"broken cross-file links: {dead[:8]}")

    summary = (f"{os.path.basename(path):<52} tags OK | ids {len(ids):>3} | "
               f"footnotes {len(notes):>2} | refs {len(refs):>2} | "
               f"anchors {len(anchors):>3} | out {len(hrefs) - len(anchors):>2}")
    return summary, fail


def main():
    failed = False
    for path in FILES:
        summary, fail = check(path)
        print(summary)
        for f in fail:
            print("  FAIL:", f)
        failed |= bool(fail)
    print("PASS" if not failed else "FAIL")
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
