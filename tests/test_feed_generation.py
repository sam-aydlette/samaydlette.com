"""The feed must stay derivable from the article index.

Both files carried the same title, link, date, category and summary for every
piece, typed twice. They had already drifted in five items by the time the
generator was written: four curly quotes the index had and the feed did not, and
one category correction the index received and the feed never did. None of that
is visible to a reader of either file on its own, which is why it survived.
"""
import importlib.util
import pathlib
import subprocess
import sys
import xml.dom.minidom

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'build-feed.py'
FEED = ROOT / 'website' / 'feed.xml'


def load():
    spec = importlib.util.spec_from_file_location('build_feed', SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_committed_feed_matches_the_index():
    """The gate itself: run --check against the real files."""
    r = subprocess.run([sys.executable, str(SCRIPT), '--check'],
                       capture_output=True, text=True, cwd=str(ROOT))
    assert r.returncode == 0, r.stdout + r.stderr


def test_feed_is_well_formed_xml():
    xml.dom.minidom.parse(str(FEED))


def test_every_index_entry_reaches_the_feed():
    mod = load()
    items = mod.entries()
    doc = xml.dom.minidom.parse(str(FEED))
    links = {n.firstChild.data for n in doc.getElementsByTagName('link')
             if n.parentNode.nodeName == 'item'}
    assert len(items) == len(links)
    for it in items:
        assert mod.BASE + it['url'] in links


def test_named_entities_are_resolved_not_passed_through():
    """XML defines five entities. Anything else breaks every reader's parser."""
    mod = load()
    rendered = mod.render(mod.entries())
    assert '&rsquo;' not in rendered
    assert '&mdash;' not in rendered
    assert '’' in rendered, 'curly quotes should survive as characters'


def test_ampersands_are_escaped():
    mod = load()
    out = mod.text('Hills &amp; Valleys')
    assert out == 'Hills &amp; Valleys', out


def test_check_mode_fails_when_the_feed_drifts(tmp_path, monkeypatch):
    mod = load()
    scratch = tmp_path / 'feed.xml'
    # perturb inside the generated region: the channel title above it is
    # hand-written and the generator must not care what it says
    text = FEED.read_text()
    i = text.index(mod.BEGIN)
    j = text.index('<title>', i)
    scratch.write_text(text[:j] + '<title>drifted ' + text[j + len('<title>'):])
    monkeypatch.setattr(mod, 'FEED', scratch)
    monkeypatch.setattr(sys, 'argv', ['build-feed.py', '--check'])
    assert mod.main() == 1


def test_regenerating_is_idempotent(tmp_path, monkeypatch):
    mod = load()
    scratch = tmp_path / 'feed.xml'
    scratch.write_text(FEED.read_text())
    monkeypatch.setattr(mod, 'FEED', scratch)
    monkeypatch.setattr(sys, 'argv', ['build-feed.py'])
    assert mod.main() == 0
    once = scratch.read_text()
    assert mod.main() == 0
    assert scratch.read_text() == once
