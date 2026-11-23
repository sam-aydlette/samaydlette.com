#!/usr/bin/env python3
"""Unpack an app's static bundle for publishing, refusing anything unsafe.

    unpack-static-bundle.py BUNDLE.zip DEST

The bundle (data/apps.json `static`) comes from the app build, a job that ran
third-party install scripts, and its files are published to the site. So every
entry is checked before anything is written, and one bad entry refuses the whole
bundle: nothing is unpacked. Refused:

  - an absolute path, a backslash, an empty, `.` or `..` path segment, or a
    character outside a conservative set (letters, digits, - _ . / @ + ~);
  - a symbolic link, or any entry that is not a regular file or a directory;
  - two entries with the same path;
  - more than MAX_FILES files or MAX_BYTES bytes uncompressed;
  - a bundle with no index.html at its root.

DEST must not exist yet. Fail-closed: any refusal exits non-zero with the reason.
"""

import re
import stat
import sys
import zipfile
from pathlib import Path

MAX_FILES = 2000
MAX_BYTES = 50 * 1024 * 1024
_SEGMENT = re.compile(r"[A-Za-z0-9_@+~-][A-Za-z0-9_.@+~-]*")


def _refuse(msg):
    raise SystemExit(f"::error::unpack-static-bundle: {msg} (nothing unpacked)")


def check(infos):
    """The (path, ZipInfo) of each file to write, or a refusal."""
    files, seen, total = [], set(), 0
    for info in infos:
        name = info.filename
        if name.startswith("/") or "\\" in name:
            _refuse(f"{name!r} is not a relative path")
        is_dir = name.endswith("/")
        parts = name.rstrip("/").split("/")
        if not all(_SEGMENT.fullmatch(p) for p in parts):
            _refuse(f"{name!r} has an empty, '.' or '..' segment or an unexpected character")
        mode = info.external_attr >> 16
        if mode and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            _refuse(f"{name!r} is not a regular file or directory")
        key = "/".join(parts)
        if key in seen:
            _refuse(f"{name!r} appears twice")
        seen.add(key)
        if is_dir:
            continue
        total += info.file_size
        files.append((key, info))
    if len(files) > MAX_FILES:
        _refuse(f"{len(files)} files is more than {MAX_FILES}")
    if total > MAX_BYTES:
        _refuse(f"{total} bytes is more than {MAX_BYTES}")
    if "index.html" not in {k for k, _ in files}:
        _refuse("no index.html at the bundle root")
    return files


def unpack(bundle, dest):
    dest = Path(dest)
    if dest.exists() or dest.is_symlink():
        _refuse(f"{dest} already exists")
    try:
        zf = zipfile.ZipFile(bundle)
    except (OSError, zipfile.BadZipFile) as e:
        _refuse(f"cannot read {bundle}: {e}")
    with zf:
        files = check(zf.infolist())
        dest.mkdir(parents=True)
        root = dest.resolve()
        for key, info in files:
            out = (root / key).resolve()
            if root not in out.parents:  # unreachable after check(); kept as a last guard
                _refuse(f"{key!r} resolves outside {dest}")
            out.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(out, "xb") as dst:
                written = 0
                while chunk := src.read(1 << 16):
                    written += len(chunk)
                    if written > info.file_size:
                        _refuse(f"{key!r} is larger than its header says")
                    dst.write(chunk)
    return len(files)


def main(argv):
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    n = unpack(argv[1], argv[2])
    print(f"unpacked {n} files from {argv[1]} into {argv[2]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
