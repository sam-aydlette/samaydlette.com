#!/usr/bin/env python3
"""Structural gate for tuning-the-eigenvalue.html. Must stay clean through the prose pass."""
import re
import sys
from html.parser import HTMLParser

FILE = 'website/research/tuning-the-eigenvalue.html'
VOID = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta',
        'source', 'track', 'wbr'}


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


h = open(FILE).read()
p = P()
p.feed(h)

ids = re.findall(r'id="([^"]+)"', h)
dupes = {i for i in ids if ids.count(i) > 1}
notes = {int(x) for x in re.findall(r'id="fn(\d+)"', h)}
refs = {int(x) for x in re.findall(r'href="#fn(\d+)"', h)}
backs = {int(x) for x in re.findall(r'href="#fnref(\d+)"', h)}
anchors = {a for a in re.findall(r'href="#([^"]+)"', h)}
broken = sorted(a for a in anchors if a not in ids)

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

print(f"tags OK | ids {len(ids)} | footnotes {len(notes)} | "
      f"refs {len(refs)} | anchors {len(anchors)}")
for f in fail:
    print("  FAIL:", f)
print("PASS" if not fail else "FAIL")
sys.exit(1 if fail else 0)
