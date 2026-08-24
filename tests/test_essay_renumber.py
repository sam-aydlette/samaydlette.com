"""Renumbering must carry prose cross-references with it.

Footnotes refer to each other in plain text ("see note 18", "notes 34, 35").
Nothing in the markup ties those numerals to the note they mean, so a renumbering
pass that only rewrites ids and hrefs leaves them pointing at whatever now happens
to occupy that slot. That is not hypothetical: three earlier passes scrambled all
twelve references in the essay, leaving a sentence about universality pointing at
a paper on ferroelectrics and the neuronal-avalanche literature pointing at a
drone safety monitor and a magazine article about bunkers.
"""
import importlib.util
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
ESSAY = ROOT / 'website' / 'research' / 'staying-in-the-loop.html'


def load(tmp_file):
    """Import renumber.py with FILE pointed at a scratch document."""
    spec = importlib.util.spec_from_file_location(
        'renumber_mod', ROOT / 'tools' / 'essay' / 'renumber.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.FILE = str(tmp_file)
    return mod


def doc(citations, notes):
    """Minimal document: body citations in order, then the note list."""
    body = ' '.join(
        '<a href="#fn%d" class="footnote-ref" id="fnref%d" role="doc-noteref">'
        '<sup>%d</sup></a>' % (n, n, n) for n in citations)
    lis = '\n'.join(
        '<li id="fn%d"><p>%s<a href="#fnref%d" class="footnote-back" '
        'role="doc-backlink">back</a></p></li>' % (n, t, n) for n, t in notes)
    return ('<p>%s</p>\n<section id="footnotes" class="footnotes">\n<ol>\n%s\n</ol>\n</section>'
            % (body, lis))


def test_prose_reference_follows_the_note_it_names(tmp_path):
    # Cited in the order 3, 1, 2 -> they become 1, 2, 3. Note 3 (cited first)
    # becomes note 1, so the sentence naming it must say "note 1".
    f = tmp_path / 'e.html'
    f.write_text(doc([3, 1, 2], [(1, 'Alpha. '), (2, 'Beta, see note 3. '), (3, 'Gamma. ')]))
    assert load(f).main() == 0
    out = f.read_text()
    assert 'see note 1' in out, 'prose reference did not follow the renumbering'
    assert 'see note 3' not in out


def test_multiple_numbers_in_one_reference(tmp_path):
    f = tmp_path / 'e.html'
    f.write_text(doc([3, 1, 2], [(1, 'Alpha. '), (2, 'Beta. '), (3, 'See notes 1, 2. ')]))
    assert load(f).main() == 0
    # 1 -> 2 and 2 -> 3, and note 3 itself became note 1
    assert 'See notes 2, 3' in f.read_text()


def test_identity_renumber_changes_nothing(tmp_path):
    f = tmp_path / 'e.html'
    original = doc([1, 2, 3], [(1, 'Alpha, see note 2. '), (2, 'Beta. '), (3, 'Gamma. ')])
    f.write_text(original)
    assert load(f).main() == 0
    assert f.read_text() == original


def test_the_word_note_without_a_number_is_untouched(tmp_path):
    f = tmp_path / 'e.html'
    f.write_text(doc([2, 1], [(1, 'Note that this holds. '), (2, 'Beta. ')]))
    assert load(f).main() == 0
    assert 'Note that this holds' in f.read_text()


def _essay_has_notes():
    return ESSAY.exists() and '<section id="footnotes"' in ESSAY.read_text()


@pytest.mark.skipif(not _essay_has_notes(),
                    reason='essay absent or replaced by a placeholder while it is rewritten')
def test_every_cross_reference_in_the_essay_resolves():
    """Each 'note N' must land on a note that exists."""
    import re
    h = ESSAY.read_text()
    notes = h[h.index('<section id="footnotes"'):]
    defined = {int(x) for x in re.findall(r'<li id="fn(\d+)">', notes)}
    bad = []
    for num, body in re.findall(r'<li id="fn(\d+)">(.*?)</li>', notes, re.S):
        text = re.sub(r'<[^>]+>', '', body)
        for m in re.finditer(r'\b[Nn]otes? ((?:\d+)(?:, ?\d+)*)', text):
            for target in re.findall(r'\d+', m.group(1)):
                if int(target) not in defined:
                    bad.append('fn%s -> missing note %s' % (num, target))
    assert not bad, bad
