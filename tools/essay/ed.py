"""Exact-replacement helper for the prose pass. `~` in patterns means en-dash (U+2013).

Usage:
    import ed
    ed.add(old, new)
    ed.commit('3.5')
Nothing is written unless every pattern matched exactly once.
"""
FILE = 'website/research/tuning-the-eigenvalue.html'
ND = '–'
_edits = []


def add(a, b):
    _edits.append((a.replace('~', ND), b.replace('~', ND)))


def commit(label=''):
    h = open(FILE).read()
    for old, new in _edits:
        n = h.count(old)
        assert n == 1, ('NOT FOUND' if n == 0 else f'AMBIGUOUS x{n}') + ': ' + old[:110]
        h = h.replace(old, new)
    open(FILE, 'w').write(h)
    print(f'applied {len(_edits)} edits {label}')
    _edits.clear()
