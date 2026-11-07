"""Every repo path named in CLAUDE.md and the project skills must exist.

These files are the context Claude Code works from, and they drift like any
other copy. The previous CLAUDE.md pointed twice at docs/assessment/ground-truth.md,
which did not exist, and nothing noticed. A path that moved or was deleted gets
fixed in the same change that moved or deleted it.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTEXT_FILES = [ROOT / 'CLAUDE.md', *sorted((ROOT / '.claude' / 'skills').rglob('*.md'))]

TICKED = re.compile(r'`([^`\s]+)`')
PLACEHOLDER = re.compile(r'[*<>$]|-N\b')
TOP_LEVEL = {p.name for p in ROOT.iterdir() if p.name != '.git'}


def named_paths(md):
    """(token, resolved path) for each backticked token that names a repo path."""
    for token in TICKED.findall(md.read_text(encoding='utf-8')):
        token = token.rstrip('.,;:')
        if PLACEHOLDER.search(token):
            continue
        head = token.split('/', 1)[0]
        if head == 'references':
            yield token, md.parent / token
        elif head in TOP_LEVEL and ('/' in token or (ROOT / token).is_file()):
            yield token, ROOT / token


def test_the_scan_finds_paths():
    """Guard against a scan that silently checks nothing."""
    found = [t for md in CONTEXT_FILES for t, _ in named_paths(md)]
    assert len(found) > 30, found


def test_every_named_path_exists():
    missing = [f'{md.relative_to(ROOT)}: {token}'
               for md in CONTEXT_FILES
               for token, path in named_paths(md)
               if not path.exists()]
    assert not missing, 'paths named in agent context that do not exist:\n' + '\n'.join(missing)
