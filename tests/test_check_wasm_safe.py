"""The Wasm-safe check fails closed on sprintf formats the opa-wasm host must not see.

POAM-035 (sprintf-js, CVE-2026-97058) is dispositioned on the condition that
every Rego sprintf format is a literal (or a concat of literals) with no
precision specifier. These tests pin that the check enforces exactly that
condition, against committed known-bad fixtures and the live policy tree.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "check-wasm-safe.py"
FIXTURES = REPO / "tests" / "fixtures" / "wasm-safe"

spec = importlib.util.spec_from_file_location("cws", SCRIPT)
assert spec and spec.loader
cws = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cws)


def run(directory: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPT), str(directory)], capture_output=True, text=True)


def test_clean_fixture_passes():
    r = run(FIXTURES / "clean")
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize(
    ("case", "phrase"),
    [
        ("nonliteral-format", "format is not a string literal"),
        ("nonliteral-format-multiline", "format is not a string literal"),
        ("concat-nonliteral", "format is not a string literal"),
        ("precision-format", "precision specifier"),
    ],
)
def test_known_bad_fixture_fails(case, phrase):
    r = run(FIXTURES / case)
    assert r.returncode == 1
    assert phrase in r.stderr
    assert "policy.rego:" in r.stderr


def test_current_policy_tree_passes():
    # The POAM-035 disposition depends on this: if a policy ever needs a
    # non-literal or precision-bearing format, the disposition must be revisited.
    r = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_policy_tree_has_sprintf_calls_to_check():
    # Guard against the check passing vacuously because it found nothing.
    calls = [c for p in sorted(cws.POLICY_DIR.rglob("*.rego")) for c in cws.sprintf_calls(p.read_text())]
    assert len(calls) >= 8


@pytest.mark.parametrize("fmt", ["%.5f", "%08.3f", "%-10.2e", "%.*f", "%+.1g", "%%%.2f", "%1$.3f", "%(n).2f", "%'x10.2f"])
def test_precision_specifiers_are_detected(fmt):
    assert cws.has_precision(fmt)


@pytest.mark.parametrize("fmt", ["%s", "%5d", "%-8s", "100%%. done", "a.b %s.%s"])
def test_non_precision_formats_are_allowed(fmt):
    assert not cws.has_precision(fmt)


def test_comment_mentions_are_ignored():
    src = '# sprintf(fmt, [x]) with "%.2f"\nx := 1 # sprintf(y, [])\n'
    assert cws.sprintf_calls(src) == []


def test_hash_inside_string_is_not_a_comment():
    src = 'x := sprintf("#%s", [y])\nz := sprintf(fmt, [w])\n'
    calls = cws.sprintf_calls(src)
    assert [c[1] for c in calls] == [["#%s"], None]
    assert calls[1][0] == 2
