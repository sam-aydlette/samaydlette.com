#!/usr/bin/env python3
"""Ban Rego constructs known to diverge between the Go and Wasm evaluators.

One Rego source serves two enforcement points: the deploy gate (OPA CLI, Go
builtins) and the runtime Lambda (Wasm, with some builtins delegated to a
JavaScript host). The parity test (scripts/policy-parity-test.js) catches
divergence the fixture corpus exercises; this check prevents the known
offenders from entering the policy tree at all, exercised or not:

  - sprintf %q       — sprintf-js (the opa-wasm host) rejects the verb and
                       THROWS at runtime in the Lambda.
  - sprintf %v       — renders Rego sets/composites differently in the Go
                       runtime vs the JS host (found live by the parity
                       test). Format sets explicitly (concat + sort).
  - time.now_ns(     — makes evaluation host/time-dependent; the pipeline
                       supplies data.runtime.evaluated_at instead, keeping
                       Wasm evaluation deterministic.
  - sprintf format   — the FIRST argument of every sprintf call must be a
    not a literal      string literal ("..." or `...`), or concat(<literal>,
                       [<literal>, ...]) whose every element is a literal.
                       The format is handed to sprintf-js, whose
                       CVE-2026-97058 (POAM-035) is a denial of service
                       driven by the format string; a literal format keeps
                       runtime input out of it. The first argument is parsed
                       wherever it starts, including on the next line.
  - precision in a   — no format literal may carry a precision specifier
    format literal     (%.5f, %08.3f, %.*f, %1$.2f, ...): the CVE's trigger.

Comment text (from an unquoted # to end of line) is ignored, so the bans can
be documented next to the code.

Usage: check-wasm-safe.py [DIRECTORY]   (default: infrastructure/policy)
"""

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
POLICY_DIR = REPO / "infrastructure" / "policy"

BANNED = [
    (re.compile(r"%q"), "sprintf %q throws in the opa-wasm JS host"),
    (re.compile(r"%v"), "sprintf %v renders sets differently under Wasm; join explicitly"),
    (re.compile(r"time\.now_ns\s*\("), "use data.runtime.evaluated_at, not host time"),
]

SPRINTF = re.compile(r"\bsprintf\s*\(")
CONCAT = re.compile(r"concat\s*\(")
# A sprintf-js placeholder up to a precision dot: optional argument index
# (1$) or name ((key)), flags, optional custom pad ('c), width or *, then '.'.
# '%%' is matched first so an escaped percent is never read as a placeholder.
PRECISION = re.compile(r"%%|%(?:[1-9]\d*\$|\([^)]*\))?[-+ #0]*(?:'.)?-?(?:\d+|\*)?\.")

NONLITERAL = "sprintf format is not a string literal (or concat of literals); runtime data must not reach the sprintf-js format (POAM-035)"
PRECISION_WHY = "sprintf format carries a precision specifier, the CVE-2026-97058 trigger in sprintf-js (POAM-035)"


def has_precision(fmt):
    """True if a format literal contains a precision specifier."""
    return any(m.group(0) != "%%" for m in PRECISION.finditer(fmt))


def _strip_comments(src):
    """Blank out comment text (keeping offsets and newlines); return the text
    and the [start, end) spans of string literals."""
    out = list(src)
    spans = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == '"' or c == "`":
            start = i
            i += 1
            while i < n and src[i] != c:
                if c == '"' and src[i] == "\\":
                    i += 1
                elif c == '"' and src[i] == "\n":
                    break
                i += 1
            i += 1
            spans.append((start, i))
            continue
        if c == "#":
            while i < n and src[i] != "\n":
                out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out), spans


def _skip_ws(text, i):
    while i < len(text) and text[i].isspace():
        i += 1
    return i


def _literal(text, i):
    """Parse a string literal at i; return (content, next_index) or None."""
    if i >= len(text) or text[i] not in "\"`":
        return None
    quote, j = text[i], i + 1
    while j < len(text) and text[j] != quote:
        if quote == '"' and text[j] == "\\":
            j += 1
        elif quote == '"' and text[j] == "\n":
            return None
        j += 1
    if j >= len(text):
        return None
    return text[i + 1 : j], j + 1


def _format_literals(text, i):
    """Parse sprintf's first argument starting at i. Return the list of
    literal strings that make up the format, or None if it is not a literal
    or a concat whose separator and elements are all literals."""
    i = _skip_ws(text, i)
    lit = _literal(text, i)
    if lit:
        literals, i = [lit[0]], lit[1]
    else:
        m = CONCAT.match(text, i)
        if not m:
            return None
        sep = _literal(text, _skip_ws(text, m.end()))
        if not sep:
            return None
        literals, i = [sep[0]], _skip_ws(text, sep[1])
        if text[i : i + 1] != ",":
            return None
        i = _skip_ws(text, i + 1)
        if text[i : i + 1] != "[":
            return None
        i = _skip_ws(text, i + 1)
        while text[i : i + 1] != "]":
            el = _literal(text, i)
            if not el:
                return None
            literals.append(el[0])
            i = _skip_ws(text, el[1])
            if text[i : i + 1] == ",":
                i = _skip_ws(text, i + 1)
            elif text[i : i + 1] != "]":
                return None
        i = _skip_ws(text, i + 1)
        if text[i : i + 1] != ")":
            return None
        i += 1
    # The format must be the whole first argument, not the start of an expression.
    if text[_skip_ws(text, i) : _skip_ws(text, i) + 1] != ",":
        return None
    return literals


def sprintf_calls(src):
    """Return [(lineno, literals_or_None)] for every sprintf call outside
    comments and string literals."""
    text, spans = _strip_comments(src)
    calls = []
    for m in SPRINTF.finditer(text):
        if any(s <= m.start() < e for s, e in spans):
            continue
        lineno = text.count("\n", 0, m.start()) + 1
        calls.append((lineno, _format_literals(text, m.end())))
    return calls


def check_file(path, shown):
    findings = []
    src = path.read_text()
    lines = src.splitlines()
    for lineno, line in enumerate(lines, 1):
        if line.lstrip().startswith("#"):
            continue
        for pattern, why in BANNED:
            if pattern.search(line):
                findings.append(f"{shown}:{lineno}: {why}\n    {line.strip()}")
    for lineno, literals in sprintf_calls(src):
        line = lines[lineno - 1].strip()
        if literals is None:
            findings.append(f"{shown}:{lineno}: {NONLITERAL}\n    {line}")
        elif any(has_precision(s) for s in literals):
            findings.append(f"{shown}:{lineno}: {PRECISION_WHY}\n    {line}")
    return findings


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("directory", nargs="?", type=Path, default=POLICY_DIR, help="policy tree to scan (default: infrastructure/policy)")
    args = ap.parse_args(argv)
    root = args.directory.resolve()

    paths = sorted(root.rglob("*.rego")) if root.is_dir() else []
    if not paths:
        print(f"error: no .rego files under {args.directory}; refusing to pass vacuously", file=sys.stderr)
        return 2

    def shown(path):
        return path.relative_to(REPO) if path.is_relative_to(REPO) else path

    findings = []
    for path in paths:
        findings.extend(check_file(path, shown(path)))

    if findings:
        print("Wasm-unsafe constructs in the policy tree:", file=sys.stderr)
        for f in findings:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(f"OK: no Wasm-divergent builtin usage and only literal, precision-free sprintf formats in {shown(root)}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
