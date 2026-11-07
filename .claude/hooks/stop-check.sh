#!/usr/bin/env bash
# Stop hook: Claude can't end a turn while `make check` fails.
#
# - Clean working tree: nothing changed, so nothing to check. Exit 0.
# - Missing tools (no .venv tools or no opa): the gate can't run here. Exit 1,
#   a non-blocking error the operator sees as a hook notice. A missing tool is
#   not Claude's failure to fix, and blocking on it would only loop.
# - `make check` fails: exit 2. The tail of its output goes back to Claude on
#   stderr as the reason it can't stop yet.
#
# Claude Code stops honoring a Stop hook after eight consecutive blocks with no
# tool call in between, so a failure Claude can't fix does not trap the session.

cat >/dev/null  # hook input is unused; drain it

cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || exit 0
[ -z "$(git status --porcelain)" ] && exit 0

if ! tools=$(make --no-print-directory require-tools 2>&1); then
  echo "make check skipped: tools missing. $(printf '%s' "$tools" | head -1)" >&2
  exit 1
fi

if ! out=$(make --no-print-directory check 2>&1); then
  printf '%s\n' "$out" | tail -40 >&2
  echo "make check failed. Fix the cause, never the gate, test or fixture. If the failure isn't yours to fix, tell the operator what failed and why." >&2
  exit 2
fi
exit 0
