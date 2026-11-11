#!/usr/bin/env bash
# Check out an app's source at the commit pinned in data/apps.json.
#
# Usage: app-source.sh APP_ID DEST [MANIFEST]
#
# The commit is the only ref: a push to the app repository changes nothing here
# until a reviewed pull request moves the pin, and the pinned commit must be on
# the app repository's named branch. The token, if any, comes from
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

# "<repo> <branch> <commit>" from the one manifest reader, which validates it.
read -r repo branch commit < <(python3 -I "$here/_apps.py" --manifest "$manifest" source "$app") || exit 1
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

url="https://github.com/$repo.git"
git init -q -- "$dest"
git -C "$dest" fetch -q --depth 1 --end-of-options "$url" "$commit"
git -C "$dest" -c advice.detachedHead=false checkout -q --detach FETCH_HEAD
got=$(git -C "$dest" rev-parse HEAD)
if [ "$got" != "$commit" ]; then
  echo "app-source: checked out $got, expected $commit" >&2
  exit 1
fi
# GitHub serves any commit in a repository's fork network through its URL, so
# the pin alone does not prove the commit belongs to this repository. Require
# it on the named branch. The branch history is fetched without file contents.
git -C "$dest" fetch -q --filter=blob:none --end-of-options "$url" "refs/heads/$branch:refs/remotes/pin-check"
if ! git -C "$dest" merge-base --is-ancestor "$commit" refs/remotes/pin-check; then
  echo "app-source: $commit is not on $repo's $branch" >&2
  exit 1
fi
echo "$app source: $repo at $commit (on $branch)"
