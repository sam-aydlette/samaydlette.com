#!/usr/bin/env python3
"""Complete human-readable views of the published certification data, checked
for consistency with the machine-readable originals (CDS-TRC-HMR, CDS-CSO-CBF).

For each JSON (or CSV) artifact it writes `<name>.view.md`: every value in the
original, under its JSON Pointer path, grouped by top-level field. Each value
cell is the value's JSON encoding, so the view is lossless. Then it parses
every view back and fails unless it reproduces the original exactly. That
round trip is the automation that keeps the two formats consistent: a view
that dropped, changed or added a value would not reproduce its JSON, and the
build stops before anything is signed or published.

The curated Markdown twins the generators write (`<name>.md`) are summaries
from the same in-memory data in the same run; the `.view.md` is the complete
one. Both are listed per artifact in the trust manifest.

    python3 scripts/build-human-views.py ksi-signal.json boundary-map.json iiw.csv ...
"""

import csv
import json
import sys
from pathlib import Path

SUFFIX = ".view.md"
HEADER = "| Path | Value |"
RULE = "|---|---|"


def _fail(msg):
    raise SystemExit(f"::error::human views: {msg} (fail-closed)")


# --- JSON Pointer (RFC 6901) ------------------------------------------------------------

def _esc(seg):
    return str(seg).replace("~", "~0").replace("/", "~1")


def _unesc(seg):
    return seg.replace("~1", "/").replace("~0", "~")


def leaves(obj, path=""):
    """(pointer, value) for every scalar, and for every empty list or object."""
    if isinstance(obj, dict) and obj:
        for k, v in obj.items():
            yield from leaves(v, f"{path}/{_esc(k)}")
    elif isinstance(obj, list) and obj:
        for i, v in enumerate(obj):
            yield from leaves(v, f"{path}/{i}")
    else:
        yield path, obj


def _cell(v):
    return json.dumps(v, ensure_ascii=False).replace("\\", "\\\\").replace("|", "\\|")


def _uncell(s):
    out, i = [], 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s) and s[i + 1] in "\\|":
            out.append(s[i + 1])
            i += 2
        else:
            out.append(s[i])
            i += 1
    return json.loads("".join(out))


# --- render and parse -----------------------------------------------------------------------

def render(name, data, kind="json"):
    out = [f"# {name}: complete human-readable view", "",
           f"_Every value in `{name}`, under its JSON Pointer path; each value is shown in its JSON encoding. "
           "Generated from the signed original by scripts/build-human-views.py, and checked on every build to "
           "reproduce it exactly._", "", f"- **Format:** {kind}", ""]
    if kind == "csv":
        data = {"rows": data}
    groups = {}
    for ptr, v in leaves(data):
        top = ptr.split("/")[1] if ptr else ""
        groups.setdefault(top, []).append((ptr, v))
    for top, rows in groups.items():
        out += [f"## {_unesc(top) or '(document)'}", "", HEADER, RULE]
        out += [f"| `{ptr or '/'}` | {_cell(v)} |" for ptr, v in rows]
        out.append("")
    return "\n".join(out) + "\n"


def _split_row(line):
    """('ptr', 'cell') from '| `ptr` | cell |', honouring escaped pipes in the cell."""
    if not line.startswith("| `"):
        return None
    end = line.index("` | ", 3)
    return line[3:end], line[end + 4:-2]


def parse(text):
    """The value a view describes. A container whose keys are exactly 0..n-1 is
    read as a list; an object that happened to have such keys would not round
    trip, and build() fails closed on it rather than publish a wrong view."""
    kind = "csv" if "- **Format:** csv" in text else "json"
    root, whole = {}, None
    for line in text.splitlines():
        row = _split_row(line)
        if row is None:
            continue
        ptr, cell = row
        value = _uncell(cell)
        if ptr == "/":
            whole = value
            continue
        segs = [_unesc(x) for x in ptr.split("/")[1:]]
        node = root
        for seg in segs[:-1]:
            node = node.setdefault(seg, {})
        node[segs[-1]] = _Leaf(value)
    if whole is not None:
        return whole
    data = _thaw(root)
    return data.get("rows", []) if kind == "csv" else data


class _Leaf:
    __slots__ = ("value",)

    def __init__(self, value):
        self.value = value


def _thaw(node):
    if isinstance(node, _Leaf):
        return node.value
    if node and set(node) == {str(i) for i in range(len(node))}:
        return [_thaw(node[str(i)]) for i in range(len(node))]
    return {k: _thaw(v) for k, v in node.items()}


def load(path):
    p = Path(path)
    if p.suffix == ".csv":
        with p.open(newline="") as f:
            return list(csv.reader(f)), "csv"
    try:
        return json.loads(p.read_text()), "json"
    except json.JSONDecodeError as exc:
        _fail(f"{p} is not valid JSON: {exc}")


def build(path):
    p = Path(path)
    data, kind = load(p)
    text = render(p.name, data, kind)
    back = parse(text)
    if back != data:
        _fail(f"{p.name}: the human-readable view does not reproduce the machine-readable original")
    view = p.with_name(p.stem + SUFFIX)
    view.write_text(text)
    return view


def check(path, view):
    """Re-read a written view and compare it with its original (used after the
    views are written, and by verifiers on the published pair)."""
    data, _ = load(path)
    if parse(Path(view).read_text()) != data:
        _fail(f"{Path(view).name} does not match {Path(path).name}")


# Published by something other than the deploy (the runtime Lambda, the nightly
# beacon): the deploy never publishes them, so it writes no view of them; the
# trust page renders them from the live JSON.
NOT_DEPLOY_PUBLISHED = ("ksi-signal-runtime.json", "vdr-status.json")


def sources(freshness, d):
    """The JSON and CSV artifacts in the governed freshness config that this
    build has in directory d (absent optional ones are skipped)."""
    out = []
    for a in json.loads(Path(freshness).read_text())["artifacts"]:
        name = a["path"].rsplit("/", 1)[1]
        if name.endswith((".json", ".csv")) and name not in NOT_DEPLOY_PUBLISHED and (Path(d) / name).is_file():
            out.append(Path(d) / name)
    return out


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--freshness", default=None, help="take every JSON/CSV artifact it lists that is in --dir")
    ap.add_argument("--dir", default=".")
    ap.add_argument("--list", default=None, help="append each written view's name to this file")
    a = ap.parse_args(argv)
    paths = [Path(p) for p in a.paths] + (sources(a.freshness, a.dir) if a.freshness else [])
    if not paths:
        _fail("no artifacts named")
    written = []
    for p in paths:
        if not p.is_file():
            _fail(f"{p} not found")
        view = build(p)
        check(p, view)
        written.append(view.name)
        print(f"human view: {view.name} reproduces {p.name}")
    if a.list:
        with open(a.list, "a") as f:
            f.writelines(w + "\n" for w in written)
    return 0


if __name__ == "__main__":
    sys.exit(main())
