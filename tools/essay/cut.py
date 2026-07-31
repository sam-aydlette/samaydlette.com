"""Section removal that takes its orphaned footnotes with it.

Removing a section leaves its footnote definitions uncited, which fails the
integrity gate. This removes both in one operation, so the document is never
left in a state the gate rejects.

    import cut
    cut.section('theory-as-extension')
    cut.commit()
"""
import re

FILE = 'website/research/tuning-the-eigenvalue.html'
_pending = []


def section(hid):
    """Queue a whole section (its heading through the next heading) for removal."""
    _pending.append(hid)


def _span(h, hid):
    i = h.index('id="%s"' % hid)
    i = h.rindex('<h', 0, i)
    m = re.search(r'<h[345] id="', h[i + 10:])
    j = i + 10 + m.start() if m else h.index('<section id="footnotes"')
    return i, j


def commit(label=''):
    h = open(FILE).read()
    before = len(h)
    removed = []
    for hid in _pending:
        i, j = _span(h, hid)
        removed.append((hid, h[i:j]))
        h = h[:i] + h[j:]

    split = h.index('<section id="footnotes"')
    cited = {int(x) for x in re.findall(r'<a href="#fn(\d+)"', h[:split])}
    defined = {int(x) for x in re.findall(r'<li id="fn(\d+)">', h)}
    gone = sorted(defined - cited)
    for n in gone:
        m = re.search(r'(<!-- TYPE [A-D] -->\s*)?<li id="fn%d">.*?</li>\n' % n, h, re.S)
        h = h[:m.start()] + h[m.end():]

    open(FILE, 'w').write(h)

    def words(t):
        t = re.sub(r'<table.*?</table>', ' ', t, flags=re.S)
        return len(re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', t)).split())

    for hid, seg in removed:
        print('  cut %-46s %5d words' % (hid, words(seg)))
    if gone:
        print('  orphaned footnotes removed: %s' % gone)
    print('  file %d -> %d bytes  %s' % (before, len(h), label))
    _pending.clear()
    return gone


def orphans(label=''):
    """Remove footnote definitions that nothing cites any more."""
    h = open(FILE).read()
    split = h.index('<section id="footnotes"')
    cited = {int(x) for x in re.findall(r'<a href="#fn(\d+)"', h[:split])}
    defined = {int(x) for x in re.findall(r'<li id="fn(\d+)">', h)}
    gone = sorted(defined - cited)
    for n in gone:
        m = re.search(r'(<!-- TYPE [A-D] -->\s*)?<li id="fn%d">.*?</li>\n' % n, h, re.S)
        h = h[:m.start()] + h[m.end():]
    open(FILE, 'w').write(h)
    print('  orphaned footnotes removed: %s  %s' % (gone or 'none', label))
    return gone
