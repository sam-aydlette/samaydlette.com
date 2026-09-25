#!/usr/bin/env python3
"""Content checks on the real published pages. Local only, by design.

These run against the committed essay and homepage rather than fixtures, so they
check what the prose says, not whether the tools work. The deploy pipeline proves
compliance; it does not police article content. The tools' own unit tests stay in
tests/ and run in CI; this file lives outside tests/ so CI never collects it.

    make essay-check        # or: python3 -m pytest tools/essay
"""
import importlib.util
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from paths import ESSAY as ESSAY_REL  # noqa: E402

ESSAY = ROOT / ESSAY_REL


def load(name):
    spec = importlib.util.spec_from_file_location(name + '_mod', HERE / (name + '.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_real_pages_pass_both_gates(monkeypatch):
    # FILES are repo-relative, as the tools document; pin cwd so the check is portable
    monkeypatch.chdir(ROOT)
    assert load('integrity').main() == 0
    assert load('refcheck').main() == 0


def _essay_has_notes():
    return ESSAY.exists() and '<section id="footnotes"' in ESSAY.read_text()


@pytest.mark.skipif(not _essay_has_notes(),
                    reason='essay absent or replaced by a placeholder while it is rewritten')
def test_every_cross_reference_in_the_essay_resolves():
    """Each 'note N' must land on a note that exists."""
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
