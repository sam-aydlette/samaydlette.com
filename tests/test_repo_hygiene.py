"""Nothing dead is carried: every file under data/ has a reader, and every file
under scripts/ has a caller.

The CMMC, GovRAMP and TX-RAMP figures left about 13 MB of catalogs, profiles,
crosswalks and parked generators behind them, none of which anything read. These
two checks keep that from building up again.

- A file under data/ is read when a reader (a workflow, a Makefile, the
  infrastructure code, a script, a test, a tool or the site's JavaScript) names
  it: its file name, plus its directory's name when it sits in a subdirectory
  (the scripts build paths as REPO / "data" / "profiles" / name). A file listed
  by name in another data file that is read (a register listing its entries,
  such as data/fedramp-certification-reports/register.json) is read too.
- A file under scripts/ has a caller when something that runs names it: a
  workflow, a Makefile, the infrastructure code, a tool or another script. A
  test alone is not a caller: a script whose only caller is its own test is dead
  code with a test. An underscore module counts when it is imported by name.

Each check has a known-bad fixture under tests/fixtures/hygiene/ that fails for
exactly that reason.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "tests" / "fixtures" / "hygiene"

SKIP_DIRS = {".git", ".venv", "node_modules", ".terraform", "__pycache__", "_pkg", ".pytest_cache", ".mypy_cache"}
CODE_SUFFIXES = {".py", ".sh", ".js", ".mjs", ".tf", ".rego", ".yml", ".yaml"}

# Files under data/ that no code reads, on purpose. Each needs a reason.
DATA_ALLOWLIST = {
    "data/PROVENANCE.md": "documents where the vendored catalog and profiles came from; read by people",
    "data/assessor-records/README.md": "documents the directory scripts/_assessor.py reads; read by people",
}

# Files under scripts/ with no caller that runs them, on purpose. Each needs a reason.
SCRIPT_ALLOWLIST: dict[str, str] = {}


def _files(root: Path, top: str) -> list[Path]:
    base = root / top
    if not base.is_dir():
        return []
    out = []
    for p in sorted(base.rglob("*")):
        if p.is_file() and not SKIP_DIRS & set(p.relative_to(root).parts):
            out.append(p)
    return out


def _code(root: Path, include_tests: bool) -> dict[Path, str]:
    """Files whose text can name a data file or a script: things that run."""
    found: list[Path] = []
    # The gate register lists the scripts `make gates` runs (scripts/run-gates.sh stage).
    for name in ("Makefile", "package.json", "update-cache-version.js", "infrastructure/schemas/gate-modes.json"):
        if (root / name).is_file():
            found.append(root / name)
    for top in (".github", "infrastructure", "policies", "scripts", "tools", "website/assets/js"):
        found += [p for p in _files(root, top) if p.suffix in CODE_SUFFIXES or p.name == "Makefile"]
    if include_tests:
        found += [p for p in sorted((root / "tests").glob("*.py"))]
    return {p: p.read_text(errors="replace") for p in found}


def _names(text: str, path: Path, root: Path, data_dir: Path) -> bool:
    rel = path.relative_to(data_dir)
    if path.name not in text:
        return False
    return len(rel.parts) == 1 or rel.parts[-2] in text


def unread_data_files(root: Path, allowlist: dict[str, str] | None = None) -> list[str]:
    allow = DATA_ALLOWLIST if allowlist is None else allowlist
    data_dir = root / "data"
    files = _files(root, "data")
    readers = _code(root, include_tests=True)
    read = {f for f in files if any(_names(t, f, root, data_dir) for t in readers.values())}
    # One hop: a file listed by name in a data file that is read (a register).
    registers = {f: f.read_text(errors="replace") for f in read if f.suffix in {".json", ".csv"}}
    read |= {f for f in files if f not in read
             and any(_names(t, f, root, data_dir) for g, t in registers.items() if g.parent == f.parent)}
    return [str(f.relative_to(root)) for f in files
            if f not in read and str(f.relative_to(root)) not in allow]


def _called(script: Path, text: str) -> bool:
    if script.name in text:
        return True
    return script.stem.startswith("_") and re.search(rf"(?<![\w-]){re.escape(script.stem)}\b", text) is not None


def scripts_without_caller(root: Path, allowlist: dict[str, str] | None = None) -> list[str]:
    allow = SCRIPT_ALLOWLIST if allowlist is None else allowlist
    callers = _code(root, include_tests=False)
    out = []
    for s in _files(root, "scripts"):
        if s.name == "README.md":
            continue
        if not any(_called(s, text) for p, text in callers.items() if p != s):
            rel = str(s.relative_to(root))
            if rel not in allow:
                out.append(rel)
    return out


def test_every_data_file_has_a_reader():
    assert unread_data_files(REPO) == []


def test_every_script_has_a_caller():
    assert scripts_without_caller(REPO) == []


def test_the_allowlists_name_files_that_exist_and_give_reasons():
    for rel, why in {**DATA_ALLOWLIST, **SCRIPT_ALLOWLIST}.items():
        assert (REPO / rel).is_file(), rel
        assert len(why) > 20, rel


def test_known_bad_unread_data_files_fail():
    """Nothing names the orphan catalog; data/other/profile.json shares a file
    name with a file that is read, but no reader names its directory."""
    root = FIXTURES / "unread-data"
    assert unread_data_files(root, allowlist={}) == ["data/catalogs/orphan-catalog.json", "data/other/profile.json"]


def test_a_file_a_register_lists_is_read():
    root = FIXTURES / "unread-data"
    assert "data/reports/listed-report.json" not in unread_data_files(root, allowlist={})


def test_known_bad_scripts_without_a_caller_fail():
    root = FIXTURES / "uncalled-script"
    assert scripts_without_caller(root, allowlist={}) == ["scripts/_orphan_helper.py", "scripts/build-orphan.py"]


def test_the_allowlists_excuse_only_what_they_name():
    root = FIXTURES / "uncalled-script"
    assert scripts_without_caller(root, allowlist={"scripts/build-orphan.py": "x"}) == ["scripts/_orphan_helper.py"]
