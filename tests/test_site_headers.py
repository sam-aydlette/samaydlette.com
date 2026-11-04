"""The static site sends COEP, so it embeds no cross-origin frames (ZAP 90004-2).

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


def policy_block(name):
    text = TF.read_text()
    start = text.index(f'resource "aws_cloudfront_response_headers_policy" "{name}"')
    depth, i = 0, text.index("{", start)
    for j in range(i, len(text)):
        depth += {"{": 1, "}": -1}.get(text[j], 0)
        if depth == 0:
            return text[i:j + 1]
    raise AssertionError("unbalanced block")


def framed_pages(root):
    return sorted(str(p.relative_to(root)) for p in root.rglob("*.html") if re.search(r"<iframe\b", p.read_text(), re.I))


def test_the_site_sends_coep_credentialless():
    block = policy_block("website")
    assert re.search(r'header\s*=\s*"Cross-Origin-Embedder-Policy"\s*\n\s*value\s*=\s*"credentialless"', block)


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
