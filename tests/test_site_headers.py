"""Every CloudFront response-headers policy sends COEP (ZAP 90004-2), so the static
site embeds no cross-origin frames.

The website response-headers policy sets Cross-Origin-Embedder-Policy:
credentialless. A cross-origin frame would then need its own COEP header, which
third-party players do not send, so the site links to video instead of
embedding it, and the CSP allows no frames at all.
"""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TF = REPO / "infrastructure" / "bootstrap" / "cloudfront.tf"
FIX = REPO / "tests" / "fixtures" / "headers"


POLICY_RE = re.compile(r'resource "aws_cloudfront_response_headers_policy" "([^"]+)"')
COEP_RE = re.compile(r'header\s*=\s*"Cross-Origin-Embedder-Policy"\s*\n\s*value\s*=\s*"credentialless"')


def policy_block(name, tf=TF):
    text = tf.read_text()
    start = text.index(f'resource "aws_cloudfront_response_headers_policy" "{name}"')
    depth, i = 0, text.index("{", start)
    for j in range(i, len(text)):
        depth += {"{": 1, "}": -1}.get(text[j], 0)
        if depth == 0:
            return text[i:j + 1]
    raise AssertionError("unbalanced block")


def policies_without_coep(tf):
    return sorted(n for n in POLICY_RE.findall(tf.read_text()) if not COEP_RE.search(policy_block(n, tf)))


def framed_pages(root):
    return sorted(str(p.relative_to(root)) for p in root.rglob("*.html") if re.search(r"<iframe\b", p.read_text(), re.I))


def test_the_site_sends_coep_credentialless():
    assert COEP_RE.search(policy_block("website"))


def test_every_response_headers_policy_sends_coep():
    # Not only the static site: the Silk Reeling app has its own policy, and
    # ZAP's five-instance cap hid it the first time (90004-2 on /silk-reeling/).
    assert POLICY_RE.findall(TF.read_text()) == ["website", "silk_reeling"]
    assert policies_without_coep(TF) == []


def test_a_policy_without_coep_is_caught():
    assert policies_without_coep(FIX / "policy-without-coep.tf.fixture") == ["app"]


def test_the_site_csp_allows_no_frames():
    block = policy_block("website")
    assert "frame-src" not in block and "youtube" not in block


def test_no_page_embeds_a_frame():
    assert framed_pages(REPO / "website") == []


def test_the_known_bad_page_is_caught():
    assert framed_pages(FIX) == ["page-with-player.html"]


def test_the_video_is_linked_with_a_local_thumbnail():
    page = (REPO / "website" / "pages" / "activities.html").read_text()
    assert 'href="https://www.youtube.com/watch?v=X5_5LOFndsk"' in page
    assert (REPO / "website" / "assets" / "images" / "wild-west-fedramp-podcast.jpg").is_file()
