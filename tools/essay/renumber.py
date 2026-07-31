#!/usr/bin/env python3
"""Renumber footnotes into document order.

Cutting or reordering text leaves the numbering scattered, which the integrity
gate does not catch: parity holds perfectly well when note 14 is cited before
note 3. This maps every note to the position of its first citation in the body.

A note cited more than once carries its `id` on the first citation only, and one
backlink at the end of the definition; both conventions survive the remap.

    python3 tools/essay/renumber.py
"""
import re
import sys

FILE = 'website/research/tuning-the-eigenvalue.html'
SPLIT = '<section id="footnotes"'


def main():
    h = open(FILE).read()
    i = h.index(SPLIT)
    body, notes = h[:i], h[i:]

    order = []
    for m in re.finditer(r'<a href="#fn(\d+)"', body):
        n = int(m.group(1))
        if n not in order:
            order.append(n)

    defined = [int(x) for x in re.findall(r'<li id="fn(\d+)">', notes)]
    missing = [n for n in defined if n not in order]
    dangling = [n for n in order if n not in defined]
    if missing or dangling:
        print('refusing to renumber: uncited %s, undefined %s' % (missing, dangling))
        return 1

    remap = {old: new for new, old in enumerate(order, 1)}

    def sub_body(m):
        old = int(m.group('n'))
        new = remap[old]
        s = m.group(0)
        s = s.replace('#fn%d"' % old, '#fn%d"' % new)
        s = s.replace('id="fnref%d"' % old, 'id="fnref%d"' % new)
        s = re.sub(r'<sup>\d+</sup>', '<sup>%d</sup>' % new, s)
        return s

    body = re.sub(r'<a href="#fn(?P<n>\d+)"[^>]*>\s*<sup>\d+</sup>\s*</a>', sub_body, body)
    notes = re.sub(r'<li id="fn(\d+)">',
                   lambda m: '<li id="fn%d">' % remap[int(m.group(1))], notes)
    notes = re.sub(r'href="#fnref(\d+)"',
                   lambda m: 'href="#fnref%d"' % remap[int(m.group(1))], notes)

    # Prose cross-references ("see note 18", "notes 34, 35"). These are plain text,
    # so nothing in the markup ties them to the note they mean, and three earlier
    # renumbering passes silently scrambled all twelve of them: a sentence about
    # universality ended up pointing at ferroelectrics, and the neuronal-avalanche
    # literature at a drone safety monitor and an article about bunkers. Remap them
    # with the same table, or renumbering keeps quietly corrupting the apparatus.
    def sub_prose(m):
        head, nums = m.group(1), re.findall(r'\d+', m.group(2))
        if any(int(x) not in remap for x in nums):
            return m.group(0)
        return '%s %s' % (head, ', '.join(str(remap[int(x)]) for x in nums))
    notes = re.sub(r'(\b[Nn]otes?) ((?:\d+)(?:, ?\d+)*)', sub_prose, notes)

    # reorder the <li> blocks themselves, keeping each TYPE comment with its note
    head, _, tail = notes.partition('<ol>')
    lead = re.match(r'\s*', tail).group(0)   # whitespace after <ol> belongs before the items
    tail = tail[len(lead):]
    items = re.findall(r'(?:<!-- TYPE [A-D] -->\n)?<li id="fn\d+">.*?</li>\n', tail, re.S)
    rest = re.sub(r'(?:<!-- TYPE [A-D] -->\n)?<li id="fn\d+">.*?</li>\n', '', tail, flags=re.S)
    items.sort(key=lambda s: int(re.search(r'<li id="fn(\d+)">', s).group(1)))
    notes = head + '<ol>' + lead + ''.join(items) + rest

    open(FILE, 'w').write(body + notes)
    print('renumbered %d footnotes into document order' % len(order))
    return 0


if __name__ == '__main__':
    sys.exit(main())
