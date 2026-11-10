#!/usr/bin/env bash
# Check out an app's source at the commit pinned in data/apps.json.
#
# Usage: app-source.sh APP_ID DEST [MANIFEST]
#
# The commit is the only ref: a push to the app repository changes nothing here
# until a reviewed pull request moves the pin. The token, if any, comes from
# APP_REPO_TOKEN and is passed to git as an HTTP header through the environment,
# so it is neither on a command line nor written to DEST/.git/config.
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "usage: $0 APP_ID DEST [MANIFEST]" >&2
  exit 2
fi
app="$1"
dest="$2"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
manifest="${3:-$here/../data/apps.json}"

# Print "<repo> <commit>" for the app, or fail with the reason.
read -r repo commit < <(python3 -I - "$manifest" "$app" <<'PY'
import json, re, sys
path, app = sys.argv[1], sys.argv[2]
try:
    apps = {a["id"]: a for a in json.load(open(path, encoding="utf-8"))["apps"]}
except (OSError, ValueError, KeyError, TypeError) as e:
    sys.exit(f"app-source: cannot read {path}: {e}")
if app not in apps:
    sys.exit(f"app-source: no app {app!r} in {path}")
src = apps[app].get("source")
if not src:
    sys.exit(f"app-source: {app!r} builds from this repository; it has no source to check out")
repo, commit = src.get("repo", ""), src.get("commit", "")
if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
    sys.exit(f"app-source: {app!r} has a malformed repo {repo!r}")
if not re.fullmatch(r"[0-9a-f]{40}", commit):
    sys.exit(f"app-source: {app!r} must pin a full 40-character commit, not {commit!r}")
print(repo, commit)
PY
) || exit 1
[ -n "${commit:-}" ] || exit 1

if [ -e "$dest" ]; then
  echo "app-source: $dest already exists" >&2
  exit 1
fi

if [ -n "${APP_REPO_TOKEN:-}" ]; then
  auth=$(printf 'x-access-token:%s' "$APP_REPO_TOKEN" | base64 -w0)
  export GIT_CONFIG_COUNT=1
  export GIT_CONFIG_KEY_0="http.https://github.com/.extraheader"
  export GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $auth"
fi

git init -q -- "$dest"
git -C "$dest" fetch -q --depth 1 --end-of-options "https://github.com/$repo.git" "$commit"
git -C "$dest" -c advice.detachedHead=false checkout -q --detach FETCH_HEAD
got=$(git -C "$dest" rev-parse HEAD)
if [ "$got" != "$commit" ]; then
  echo "app-source: checked out $got, expected $commit" >&2
  exit 1
fi
echo "$app source: $repo at $commit"
