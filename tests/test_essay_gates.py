"""The essay gates must cover the method note, not just the essay.

`integrity.py` and `refcheck.py` were each pinned to one file by a module constant.
The essay and its method note share notation and link into each other's sections, so
a heading renamed on one side left a dead link on the other that neither file could
see alone. Both gates now take a list, and integrity resolves cross-file fragments.

The fixtures here are built in tmp_path rather than committed, because what is under
test is a relationship *between* two pages; a single broken file on disk cannot
express it.
"""
import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name, **attrs):
    spec = importlib.util.spec_from_file_location(
        name + '_mod', ROOT / 'tools' / 'essay' / (name + '.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for k, v in attrs.items():
        setattr(mod, k, v)
    return mod


def page(body='', ids=(), refs=()):
    """A page carrying the given ids, plus matched footnotes for each n in refs."""
    tags = ''.join('<h2 id="%s">x</h2>' % i for i in ids)
    cite = ''.join('<a href="#fn%d" id="fnref%d">%d</a>' % (n, n, n) for n in refs)
    notes = ''.join('<li id="fn%d"><p>n<a href="#fnref%d">b</a></p></li>' % (n, n) for n in refs)
    return ('<p>%s%s%s</p><section id="footnotes"><ol>%s</ol></section>'
            % (tags, cite, body, notes))


# --- integrity.py: cross-file anchors ---

def test_cross_file_link_to_missing_page_fails(tmp_path):
    (tmp_path / 'a.html').write_text(page('<a href="gone.html#x">n</a>'))
    mod = load('integrity', SITE_ROOT=str(tmp_path))
    _, fail = mod.check(str(tmp_path / 'a.html'))
    assert any('no such page' in f for f in fail)


def test_cross_file_link_to_missing_id_fails(tmp_path):
    (tmp_path / 'a.html').write_text(page('<a href="b.html#nope">n</a>'))
    (tmp_path / 'b.html').write_text(page(ids=['real']))
    mod = load('integrity', SITE_ROOT=str(tmp_path))
    _, fail = mod.check(str(tmp_path / 'a.html'))
    assert any('no such id' in f for f in fail)


def test_cross_file_link_that_resolves_passes(tmp_path):
    (tmp_path / 'a.html').write_text(page('<a href="b.html#real">n</a>'))
    (tmp_path / 'b.html').write_text(page(ids=['real']))
    mod = load('integrity', SITE_ROOT=str(tmp_path))
    _, fail = mod.check(str(tmp_path / 'a.html'))
    assert fail == []


def test_root_relative_link_resolves_against_the_site_root(tmp_path):
    # href="/pages/about.html" is relative to how the site is served, not to the file
    (tmp_path / 'research').mkdir()
    (tmp_path / 'pages').mkdir()
    (tmp_path / 'research' / 'a.html').write_text(page('<a href="/pages/about.html">n</a>'))
    (tmp_path / 'pages' / 'about.html').write_text(page())
    mod = load('integrity', SITE_ROOT=str(tmp_path))
    _, fail = mod.check(str(tmp_path / 'research' / 'a.html'))
    assert fail == []


def test_footnote_parity_still_enforced(tmp_path):
    # regression: the invariant the gate existed for before it took a file list
    orphan = page(refs=[1]).replace('<a href="#fn1" id="fnref1">1</a>', '')
    (tmp_path / 'a.html').write_text(orphan)
    mod = load('integrity', SITE_ROOT=str(tmp_path))
    _, fail = mod.check(str(tmp_path / 'a.html'))
    assert any('never referenced' in f for f in fail)


def test_footnote_outside_the_footnotes_section_fails(tmp_path):
    # regression: two notes drifted into the footer's link list and rendered as
    # navigation bullets. Parity held perfectly, so nothing else caught it.
    doc = page(refs=[1])
    doc = doc.replace('<li id="fn1"><p>n<a href="#fnref1">b</a></p></li>', '')
    doc += '<footer><ul><li id="fn1"><p>n<a href="#fnref1">b</a></p></li></ul></footer>'
    (tmp_path / 'a.html').write_text(doc)
    mod = load('integrity', SITE_ROOT=str(tmp_path))
    _, fail = mod.check(str(tmp_path / 'a.html'))
    assert any('outside the footnotes section' in f for f in fail)


def test_footnote_inside_the_section_passes(tmp_path):
    (tmp_path / 'a.html').write_text(page(refs=[1]))
    mod = load('integrity', SITE_ROOT=str(tmp_path))
    _, fail = mod.check(str(tmp_path / 'a.html'))
    assert fail == []


def test_both_files_are_checked_and_one_failure_fails_the_run(tmp_path, capsys):
    (tmp_path / 'ok.html').write_text(page())
    (tmp_path / 'bad.html').write_text(page('<a href="gone.html#x">n</a>'))
    mod = load('integrity', SITE_ROOT=str(tmp_path),
               FILES=[str(tmp_path / 'ok.html'), str(tmp_path / 'bad.html')])
    assert mod.main() == 1
    assert 'ok.html' in capsys.readouterr().out


# --- refcheck.py: who counts as cited ---

def refs_page(body, entries):
    lis = ''.join('<li>%s</li>' % e for e in entries)
    return ('<p>%s</p><h3 id="references">R</h3><h4 id="g">G</h4><ol>%s</ol>'
            '<section id="footnotes"><ol></ol></section>' % (body, lis))


def test_uncited_personal_author_is_flagged(tmp_path):
    f = tmp_path / 'a.html'
    f.write_text(refs_page('nothing here', [
        'Hamilton, J.D. (1994). Time Series Analysis. Princeton University Press.']))
    mod = load('refcheck', FILES=[str(f)])
    assert mod.check(str(f)) == (1, 1)


def test_cited_personal_author_is_not_flagged(tmp_path):
    f = tmp_path / 'a.html'
    f.write_text(refs_page('the estimator follows Hamilton (1994)', [
        'Hamilton, J.D. (1994). Time Series Analysis. Princeton University Press.']))
    mod = load('refcheck', FILES=[str(f)])
    assert mod.check(str(f)) == (1, 0)


def test_corporate_author_matches_on_its_short_name(tmp_path):
    # regression: this resolved to `Program`, which appears nowhere, and was reported
    # uncited while the page named FedRAMP twice
    f = tmp_path / 'a.html'
    f.write_text(refs_page('the FedRAMP 20x indicators', [
        'FedRAMP Program Management Office (2025). FedRAMP 20x Framework. fedramp.gov/20x']))
    mod = load('refcheck', FILES=[str(f)])
    assert mod.check(str(f)) == (1, 0)


def test_corporate_author_nothing_names_is_still_flagged(tmp_path):
    f = tmp_path / 'a.html'
    f.write_text(refs_page('unrelated prose', [
        'FedRAMP Program Management Office (2025). FedRAMP 20x Framework. fedramp.gov/20x']))
    mod = load('refcheck', FILES=[str(f)])
    assert mod.check(str(f)) == (1, 1)


def test_each_page_is_checked_against_its_own_list(tmp_path):
    # a citation in the essay must not keep an entry alive in the note
    a = tmp_path / 'a.html'
    b = tmp_path / 'b.html'
    a.write_text(refs_page('Granger causality', ['Granger, C.W.J. (1969). Investigating.']))
    b.write_text(refs_page('no mention', ['Granger, C.W.J. (1969). Investigating.']))
    mod = load('refcheck', FILES=[str(a), str(b)])
    assert mod.main() == 1


def test_the_real_pages_pass_both_gates(monkeypatch):
    # FILES are repo-relative, as the tools document; pin cwd so the suite is portable
    monkeypatch.chdir(ROOT)
    assert load('integrity').main() == 0
    assert load('refcheck').main() == 0
