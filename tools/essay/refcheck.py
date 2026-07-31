#!/usr/bin/env python3
"""Report bibliography entries that nothing in the essay cites.

The References section opens by promising "what follows is what the argument
actually uses", so an uncited entry is a broken promise rather than a harmless
bibliography. `integrity.py` checks footnote parity and anchors; it treats the
reference list as free-standing, which no longer matches what the essay says.

An entry counts as cited if its first-author surname (or, for works with no
personal author, a distinctive title word) appears anywhere in the body or the
footnotes. That is deliberately generous: the goal is to catch entries nothing
refers to at all, not to police citation style.

    python3 tools/essay/refcheck.py
"""
import re
import sys

FILE = 'website/research/tuning-the-eigenvalue.html'
# surnames too common or too embedded in ordinary prose to match on
STOPWORDS = {'may', 'young', 'best', 'field', 'fields', 'cook', 'woods', 'green'}


def surname(entry):
    """First-author surname, or a distinctive title token for corporate authors."""
    m = re.match(r'\s*([A-Z][A-Za-zÀ-ÿ\'’-]+)\s*,\s*[A-Z]', entry)
    if m:
        return m.group(1)
    m = re.match(r'\s*([A-Z][A-Za-zÀ-ÿ\'’-]+)\s+(?:and|&)\s', entry)
    if m:
        return m.group(1)
    caps = re.findall(r'\b([A-Z][a-zÀ-ÿ]{4,})\b', entry)
    return caps[0] if caps else None


def main():
    h = open(FILE).read()
    ref0 = h.index('<h3 id="references">')
    fn0 = h.index('<section id="footnotes"')
    refs_html = h[ref0:fn0] if fn0 > ref0 else h[ref0:]
    searchable = h[:ref0] + h[fn0:]
    searchable = re.sub(r'<[^>]+>', ' ', searchable)

    groups, cur = [], None
    for chunk in re.split(r'(<h4 id="[^"]+"[^>]*>.*?</h4>)', refs_html, flags=re.S):
        m = re.match(r'<h4 id="[^"]+"[^>]*>(.*?)</h4>', chunk, re.S)
        if m:
            cur = (re.sub(r'<[^>]+>', '', m.group(1)).strip(), [])
            groups.append(cur)
        elif cur is not None:
            for p in re.findall(r'<li>(.*?)</li>', chunk, re.S):
                txt = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', '', p)).strip()
                if len(txt) > 20:
                    cur[1].append(txt)

    total = uncited = 0
    for name, entries in groups:
        misses = []
        for e in entries:
            total += 1
            s = surname(e)
            if s and s.lower() not in STOPWORDS and not re.search(r'\b%s\b' % re.escape(s), searchable):
                misses.append((s, e))
        flag = '  <-- collapsed' if len(entries) - len(misses) <= 2 else ''
        print('%-52s %2d entries, %2d uncited%s' % (name, len(entries), len(misses), flag))
        for s, e in misses:
            uncited += 1
            print('      UNCITED [%s] %s' % (s, e[:96]))

    print('\n%d entries, %d cited from nowhere' % (total, uncited))
    return 1 if uncited else 0


if __name__ == '__main__':
    sys.exit(main())
