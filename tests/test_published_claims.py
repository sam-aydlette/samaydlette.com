"""Published claims that were wrong (W1), each held true by a test.

- /trust/ and every other directory URL returned 404: the S3 REST origin has no
  index documents. A CloudFront Function now rewrites them at the edge.
- The CPO's logo URL was /favicon.ico, which did not exist.
- vdr-report.md printed "Total findings: 0" above "Open findings (35)".
- The policy index dated all 28 policies with the deploy date, because the
  deploy checks out one commit.
"""

import importlib.util
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FUNCTION = REPO / "infrastructure" / "cloudfront" / "directory-index.js"


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# --- directory URLs ------------------------------------------------------------

def _edge(uri, querystring=None):
    """Run the CloudFront Function under node with a viewer-request event."""
    script = (FUNCTION.read_text()
              + "\nconsole.log(JSON.stringify(handler({request: {uri: process.argv[1], "
                "querystring: JSON.parse(process.argv[2]), headers: {}}})));")
    out = subprocess.run(["node", "-e", script, uri, json.dumps(querystring or {})],
                         capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
@pytest.mark.parametrize("uri,want", [
    ("/trust/", "/trust/index.html"),
    ("/pages/", "/pages/index.html"),
    ("/trust/index.html", "/trust/index.html"),
    ("/.well-known/ksi-signal.json", "/.well-known/ksi-signal.json"),
    ("/favicon.ico", "/favicon.ico"),
    ("/", "/"),
])
def test_directory_urls_are_rewritten_to_their_index(uri, want):
    assert _edge(uri)["uri"] == want


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_a_bare_directory_redirects_so_relative_links_resolve():
    r = _edge("/trust")
    assert r["statusCode"] == 301 and r["headers"]["location"]["value"] == "/trust/"
    r = _edge("/trust", {"a": {"value": "1 2"}})
    assert r["headers"]["location"]["value"] == "/trust/?a=1%202"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
@pytest.mark.parametrize("uri", ["//evil.example", "//evil", "/\\evil", "/\\evil/x", "///evil"])
def test_no_redirect_can_leave_the_site(uri):
    """A Location of "//evil" or "/\\evil" is protocol-relative: an open redirect."""
    r = _edge(uri)
    assert "statusCode" not in r and r["uri"] == uri


def test_the_function_is_managed_and_on_the_default_behavior():
    tf = (REPO / "infrastructure" / "bootstrap" / "cloudfront.tf").read_text()
    res = re.search(r'resource "aws_cloudfront_function" "directory_index" \{(.*?)\n\}', tf, re.S).group(1)
    assert 'file("${path.module}/../cloudfront/directory-index.js")' in res
    assert "publish = true" in res and 'runtime = "cloudfront-js-2.0"' in res
    default = re.search(r"default_cache_behavior \{(.*?)\n  \}", tf, re.S).group(1)
    assert "aws_cloudfront_function.directory_index.arn" in default
    assert 'event_type   = "viewer-request"' in default


# --- the logo -------------------------------------------------------------------

def test_the_published_logo_exists_and_is_a_png():
    url = json.loads((REPO / "data" / "cds" / "offering.json").read_text())["logo_url"]
    assert url.startswith("https://samaydlette.com/")
    path = REPO / "website" / url.removeprefix("https://samaydlette.com/")
    assert path.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    assert (REPO / "website" / "favicon.ico").read_bytes()[:4] == b"\x00\x00\x01\x00"


# --- the VDR's human-readable rendering ----------------------------------------

def test_vdr_markdown_counts_agree_with_its_table():
    vdr = _load("vdr_claims", "scripts/build-vdr-report.py")
    findings = ([{"tracking_id": f"fp-{i}", "final_disposition": "false-positive"} for i in range(3)]
                + [{"tracking_id": "ra-1", "final_disposition": "risk-accepted"},
                   {"tracking_id": "op-1", "final_disposition": "open"}])
    report = {"summary": {"total_findings": 1, "risk_accepted": 3, "by_pain": {"N2": 1}},
              "findings": findings,
              "risk_accepted": [{"tracking_id": "CKV_X", "decision_id": "DEC-1"},
                                {"tracking_id": "CKV_Y", "decision_id": "DEC-2"}]}
    md = vdr.render_markdown(report)
    assert "- Findings: **5** | Open: **1** | Dispositioned: **4** (false-positive 3, risk-accepted 1)" in md
    assert "Accepted risks: **3** (1 findings below, 2 suppressed checks)" in md
    assert "## Findings (5: 1 open)" in md
    assert "## Accepted risks with suppressed checks (2)" in md
    assert "Open findings by PAIN:" in md
    assert "Total findings" not in md
    rows = [ln for ln in md.splitlines() if ln.startswith("| ") and not ln.startswith("| Tracking")
            and ln.count("|") == 10]
    assert len(rows) == 5


# --- policy dates ---------------------------------------------------------------

def test_policy_index_dates_each_policy_by_its_own_last_commit(tmp_path):
    out = tmp_path / "pi.json"
    subprocess.run(["python3", str(REPO / "scripts" / "build-policy-index.py"), "--output", str(out),
                    "--md-output", ""], check=True, capture_output=True, cwd=REPO)
    entries = json.loads(out.read_text())["entries"]
    for e in entries:
        want = subprocess.run(["git", "log", "-1", "--format=%cs %H", "--", e["file"]], cwd=REPO,
                              capture_output=True, text=True, check=True).stdout.split()
        assert [e["last_updated"], e["version"]] == [want[0], f"git:{want[1][:12]}"], e["file"]


def test_policy_index_refuses_a_shallow_clone(tmp_path):
    """The failure that published the deploy date for every policy."""
    clone = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{REPO}", str(clone)], check=True)
    # The builder under test, not the one in the cloned commit.
    shutil.copy(REPO / "scripts" / "build-policy-index.py", clone / "scripts" / "build-policy-index.py")
    r = subprocess.run(["python3", str(clone / "scripts" / "build-policy-index.py"),
                        "--output", str(tmp_path / "x.json"), "--md-output", ""],
                       capture_output=True, text=True, cwd=clone)
    assert r.returncode != 0 and "shallow clone" in r.stderr
    assert not (tmp_path / "x.json").exists()


def test_the_deploy_checks_out_full_history():
    wf = (REPO / ".github" / "workflows" / "deploy-with-opa.yml").read_text()
    deploy = wf[wf.index("\n  deploy:"):]
    checkout = deploy[deploy.index("- name: Checkout code"):][:400]
    assert "fetch-depth: 0" in checkout
