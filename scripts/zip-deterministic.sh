#!/usr/bin/env bash
# Zip a directory so the same contents always give the same bytes.
#
#   scripts/zip-deterministic.sh SRC_DIR OUT_ZIP
#
# Terraform updates a Lambda whenever its package hash changes. `zip -r` records
# each file's modification time and extra attributes, and every CI run checks
# out and installs afresh, so an unchanged function got a new hash, and an
# in-place update, on every deploy. This sets every entry's time to 1980-01-01
# (the earliest a zip records), drops extra attributes (-X), and adds entries
# in byte order. Contents and permissions are kept; like `zip -r`, symlinks are
# followed. Fail-closed.
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: $0 SRC_DIR OUT_ZIP" >&2; exit 2; }
src=$1
out=$(realpath -m -- "$2")
[ -d "$src" ] || { echo "::error::zip-deterministic: $src is not a directory (fail-closed)" >&2; exit 1; }
rm -f -- "$out"
cd -- "$src"
export TZ=UTC
find . -mindepth 1 -exec touch -h -d '1980-01-01T00:00:00Z' {} +
find . -mindepth 1 -print | sed 's|^\./||' | LC_ALL=C sort | zip -q -X -@ "$out"
