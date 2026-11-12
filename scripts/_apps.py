#!/usr/bin/env python3
"""The one reader of the app manifest (data/apps.json).

Every consumer goes through here, so the manifest is validated in one place:
the shell scripts call the command line below, and Python imports `load`.

    _apps.py [--manifest PATH] source APP   ->  "<repo> <branch> <commit>"
    _apps.py [--manifest PATH] trees        ->  "<dir>\t<cataloger>\t<sbom>\t<grype>" per tree
    _apps.py [--manifest PATH] grype        ->  the per-tree Grype result files, one per line
    _apps.py [--manifest PATH] builds       ->  "<app>\t<build script>\t<source dir>" per built app
    _apps.py [--manifest PATH] packages     ->  the package file each built app ships, one per line
    _apps.py [--manifest PATH] hooks KIND   ->  "<app>\t<hook script>" per app with that deploy hook

A malformed manifest exits non-zero with the reason; nothing downstream runs on
a guess.
"""

import argparse
import json
import re
import sys
from pathlib import Path

MANIFEST = Path(__file__).resolve().parent.parent / "data" / "apps.json"

_ID = re.compile(r"[a-z0-9][a-z0-9-]*")
_REPO = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*/[A-Za-z0-9_-][A-Za-z0-9_.-]*")
_BRANCH = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_./-]*")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_DIR = re.compile(r"(\.\./)?[A-Za-z0-9_-][A-Za-z0-9_./-]*")
_SBOM = re.compile(r"sbom-[a-z0-9-]+\.json")
_SRC_DIR = re.compile(r"_[a-z0-9_-]+")
_PACKAGE = re.compile(r"\./([a-z0-9][a-z0-9-]*\.zip)")
CATALOGERS = {"python", "javascript"}
# Deploy hook kinds, as app-hooks.sh names them, and each one's script name.
HOOKS = {"import": "import.sh", "runtime-check": "runtime-check.sh"}


def _fail(msg):
    raise SystemExit(f"_apps: {msg}")


def _tree(t, where):
    if not isinstance(t, dict) or set(t) - {"dir", "cataloger", "sbom", "what"}:
        _fail(f"{where}: a tree has dir, cataloger, sbom and optionally what")
    if not _DIR.fullmatch(t.get("dir", "")) or "/../" in t["dir"] or t["dir"].endswith("/.."):
        _fail(f"{where}: malformed tree dir {t.get('dir')!r}")
    if t.get("cataloger") not in CATALOGERS:
        _fail(f"{where}: cataloger must be one of {sorted(CATALOGERS)}")
    if not _SBOM.fullmatch(t.get("sbom", "")):
        _fail(f"{where}: sbom must be named sbom-<name>.json, not {t.get('sbom')!r}")


def load(path=MANIFEST):
    """The manifest, validated. Exits with the reason on anything malformed."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        _fail(f"cannot read {path}: {e}")
    if not isinstance(doc, dict) or not isinstance(doc.get("apps"), list):
        _fail(f"{path} has no apps list")
    for field in ("decided_by", "decided_on", "review_by"):
        if not doc.get(field):
            _fail(f"{path} has no {field}")
    ids = set()
    for a in doc["apps"]:
        i = a.get("id", "")
        if not _ID.fullmatch(i):
            _fail(f"malformed app id {i!r}")
        if i in ids:
            _fail(f"duplicate app id {i!r}")
        ids.add(i)
        src = a.get("source")
        if src is not None:
            if not _REPO.fullmatch(src.get("repo", "")):
                _fail(f"{i!r} has a malformed repo {src.get('repo')!r}")
            if not _BRANCH.fullmatch(src.get("branch", "")) or ".." in src["branch"]:
                _fail(f"{i!r} has a malformed branch {src.get('branch')!r}")
            if not _COMMIT.fullmatch(src.get("commit", "")):
                _fail(f"{i!r} must pin a full 40-character commit, not {src.get('commit')!r}")
        build = a.get("build")
        if build is not None:
            if not isinstance(build, dict) or set(build) != {"script", "src"}:
                _fail(f"{i!r}: a build has exactly a script and a src")
            if build["script"] != f"scripts/apps/{i}/build.sh":
                _fail(f"{i!r}: the build script must be scripts/apps/{i}/build.sh, not {build['script']!r}")
            if not isinstance(build["src"], str) or not _SRC_DIR.fullmatch(build["src"]):
                _fail(f"{i!r}: the source directory must be _<name>, not {build['src']!r}")
            if src is None:
                _fail(f"{i!r} has a build but no source to build from")
        deploy = a.get("deploy")
        if deploy is not None:
            if not isinstance(deploy, dict) or not deploy or set(deploy) - set(HOOKS):
                _fail(f"{i!r}: deploy names one or more hooks of {sorted(HOOKS)}")
            for kind, script in deploy.items():
                if script != f"scripts/apps/{i}/{HOOKS[kind]}":
                    _fail(f"{i!r}: the {kind} hook must be scripts/apps/{i}/{HOOKS[kind]}, not {script!r}")
        pkg = a.get("package_path")
        if pkg is not None and not (isinstance(pkg, str) and _PACKAGE.fullmatch(pkg)):
            _fail(f"{i!r}: package_path must be ./<name>.zip, not {pkg!r}")
        for t in a.get("sbom_trees", []):
            _tree(t, i)
    for t in doc.get("platform_sbom_trees", []):
        _tree(t, "platform")
    sboms = [t["sbom"] for t in trees(doc)]
    if len(sboms) != len(set(sboms)):
        _fail("two trees write the same SBOM file")
    return doc


def trees(doc):
    """Every tree the SCA scans: each app's, then the platform's."""
    return [t for a in doc["apps"] for t in a.get("sbom_trees", [])] + list(doc.get("platform_sbom_trees", []))


def app_sboms(doc):
    """The SBOM files of the apps' own trees, which the inventory ingests."""
    return [t["sbom"] for a in doc["apps"] for t in a.get("sbom_trees", [])]


def grype_file(tree):
    """The Grype result file for a tree: sbom-python.json -> grype-python.json."""
    return "grype-" + tree["sbom"][len("sbom-"):]


def builds(doc):
    """(app, build script, source dir) for every app the pipeline builds, in manifest order."""
    return [(a["id"], a["build"]["script"], a["build"]["src"]) for a in doc["apps"] if a.get("build")]


def packages(doc):
    """The package file (relative to infrastructure/) each built app ships."""
    return [_PACKAGE.fullmatch(a["package_path"]).group(1)
            for a in doc["apps"] if a.get("build") and a.get("package_path")]


def hooks(doc, kind):
    """(app, hook script) for every app with a deploy hook of this kind, in manifest order."""
    if kind not in HOOKS:
        _fail(f"no hook kind {kind!r}; one of {sorted(HOOKS)}")
    return [(a["id"], a["deploy"][kind]) for a in doc["apps"] if kind in (a.get("deploy") or {})]


def source(doc, app):
    """(repo, branch, commit) for an app built from another repository."""
    apps = {a["id"]: a for a in doc["apps"]}
    if app not in apps:
        _fail(f"no app {app!r} in the manifest")
    src = apps[app].get("source")
    if not src:
        _fail(f"{app!r} builds from this repository; it has no source to check out")
    return src["repo"], src["branch"], src["commit"]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", default=str(MANIFEST))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("source").add_argument("app")
    sub.add_parser("trees")
    sub.add_parser("grype")
    sub.add_parser("builds")
    sub.add_parser("packages")
    sub.add_parser("hooks").add_argument("kind", choices=sorted(HOOKS))
    args = ap.parse_args(argv)
    doc = load(args.manifest)
    if args.cmd == "source":
        print(*source(doc, args.app))
    elif args.cmd == "trees":
        for t in trees(doc):
            print(t["dir"], t["cataloger"], t["sbom"], grype_file(t), sep="\t")
    elif args.cmd == "packages":
        for pkg in packages(doc):
            print(pkg)
    elif args.cmd == "hooks":
        for h in hooks(doc, args.kind):
            print(*h, sep="\t")
    elif args.cmd == "builds":
        for b in builds(doc):
            print(*b, sep="\t")
    else:
        for t in trees(doc):
            print(grype_file(t))
    return 0


if __name__ == "__main__":
    sys.exit(main())
