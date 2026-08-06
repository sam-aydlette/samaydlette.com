#!/usr/bin/env python3
"""Report bibliography entries that nothing in the page cites.

The list is meant to be what the argument actually uses, so an uncited entry is a
bibliography padded with reading the page does not draw on. `integrity.py` checks
footnote parity and anchors; it treats the reference list as free-standing, which
is why this gate exists separately.

(The References section used to state that promise in a preamble. The preamble is
gone and the rule stands on its own; do not reinstate the sentence to justify it.)

Each page in FILES is checked against its own references. The essay and its method
note keep separate lists on purpose: sources moved to the note when the material
did, and a citation in one is not a licence to keep the entry in the other.

An entry counts as cited if its first-author surname (or, for works with no
personal author, a distinctive title word) appears anywhere in the body or the
footnotes of the page that lists it. That is deliberately generous: the goal is to
catch entries nothing refers to at all, not to police citation style.

KNOWN LIMITATION, and it has bitten once. This gate is one-directional: it finds
entries nothing cites, never sources cited in a footnote that never made it into
the list. Seven had accumulated that way (Osnos, Rushkoff, Bak/Tang/Wiesenfeld, the
CIC sources, and two taijiquan texts) and were found by hand, not here.

Automating the reverse was tried and rejected. Matching on DOI and URL is precise
but catches nothing, because every DOI in the footnotes is already in the list; all
it flags is author homepages and profile links, which are not citations. Matching on
title-and-year shapes is noisy, because <em> marks emphasis throughout the prose as
well as work titles. A gate that cries wolf is worse than the manual check, so the
manual check is the standing answer: when adding a footnote that cites a work, add
the entry too.

    python3 tools/essay/refcheck.py
"""
import os
import re
import sys

FILES = [
    'website/research/tuning-the-eigenvalue.html',
]
# surnames too common or too embedded in ordinary prose to match on
STOPWORDS = {'may', 'young', 'best', 'field', 'fields', 'cook', 'woods', 'green'}


def cite_tokens(entry):
    """Tokens any one of which, appearing in the page, counts the entry as cited.

    A personal author gives exactly one: the surname. A corporate author gives
    several, because the page may name the body, its short name, or the work, and
    guessing one leaves false positives. "FedRAMP Program Management Office (2025).
    FedRAMP 20x Framework" once resolved to `Program`, which appears nowhere, while
    the page says FedRAMP twice. Being generous here is the intended trade: the gate
    is for entries nothing refers to at all, not for policing citation style.
    """
    m = re.match(r'\s*([A-Z][A-Za-zÀ-ÿ\'’-]+)\s*,\s*[A-Z]', entry)
    if m:
        return [m.group(1)]
    m = re.match(r'\s*([A-Z][A-Za-zÀ-ÿ\'’-]+)\s+(?:and|&)\s', entry)
    if m:
        return [m.group(1)]
    toks = re.findall(r'\b([A-Z][A-Za-zÀ-ÿ]{3,})\b', entry)
    return [t for t in toks if t.lower() not in STOPWORDS]


def groups_of(h):
    """[(group name, [entry text])] from a page's References section."""
    ref0 = h.index('<h3 id="references">')
    fn0 = h.index('<section id="footnotes"') if '<section id="footnotes"' in h else -1
    refs_html = h[ref0:fn0] if fn0 > ref0 else h[ref0:]
    searchable = re.sub(r'<[^>]+>', ' ', h[:ref0] + (h[fn0:] if fn0 > ref0 else ''))

    out, cur = [], None
    for chunk in re.split(r'(<h4 id="[^"]+"[^>]*>.*?</h4>)', refs_html, flags=re.S):
        m = re.match(r'<h4 id="[^"]+"[^>]*>(.*?)</h4>', chunk, re.S)
        if m:
            cur = (re.sub(r'<[^>]+>', '', m.group(1)).strip(), [])
            out.append(cur)
        elif cur is not None:
            for p in re.findall(r'<li>(.*?)</li>', chunk, re.S):
                txt = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', '', p)).strip()
                if len(txt) > 20:
                    cur[1].append(txt)
    return out, searchable


def check(path):
    """Print one page's groups; return (entries, uncited)."""
    h = open(path).read()
    if '<h3 id="references">' not in h:
        print('%-52s no References section' % os.path.basename(path))
        return 0, 0

    print('%s' % os.path.basename(path))
    groups, searchable = groups_of(h)
    total = uncited = 0
    for name, entries in groups:
        misses = []
        for e in entries:
            total += 1
            toks = [t for t in cite_tokens(e) if t.lower() not in STOPWORDS]
            if toks and not any(re.search(r'\b%s\b' % re.escape(t), searchable) for t in toks):
                misses.append((toks[0], e))
        flag = '  <-- collapsed' if len(entries) - len(misses) <= 2 else ''
        print('  %-50s %2d entries, %2d uncited%s' % (name, len(entries), len(misses), flag))
        for s, e in misses:
            uncited += 1
            print('      UNCITED [%s] %s' % (s, e[:96]))
    return total, uncited


def main():
    total = uncited = 0
    for path in FILES:
        t, u = check(path)
        total += t
        uncited += u
    print('\n%d entries, %d cited from nowhere' % (total, uncited))
    return 1 if uncited else 0


if __name__ == '__main__':
    sys.exit(main())
