"""FRC-CSO-JSN: the public JSON under /.well-known/ is readable by any program.

The CloudFront policy for /.well-known/* (operator-applied bootstrap) adds CORS;
the deploy checks the live headers and fails without them, before the SDR."""
import importlib.util
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "wellknown-headers"
spec = importlib.util.spec_from_file_location("wkh", REPO / "scripts" / "check-wellknown-headers.py")
wkh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wkh)

GOOD = {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "X-Content-Type-Options": "nosniff"}


def test_good_headers_pass_case_insensitively():
    assert wkh.problems(GOOD) == []
    assert wkh.problems({k.lower(): v for k, v in GOOD.items()}) == []
    assert wkh.problems(dict(GOOD, **{"Content-Type": "application/schema+json; charset=utf-8"})) == []


def test_each_missing_header_is_named():
    assert any("Access-Control-Allow-Origin" in p for p in wkh.problems({**GOOD, "Access-Control-Allow-Origin": ""}))
    assert any("Content-Type" in p for p in wkh.problems({**GOOD, "Content-Type": "text/html"}))
    nosniff = dict(GOOD)
    del nosniff["X-Content-Type-Options"]
    assert any("nosniff" in p for p in wkh.problems(nosniff))


def test_an_origin_restricted_cors_header_is_not_enough():
    assert wkh.problems({**GOOD, "Access-Control-Allow-Origin": "https://samaydlette.com"})


def test_the_known_bad_fixture_fails_for_missing_cors(capsys):
    assert wkh.main(["--fixture", str(FIX / "known-bad.json")]) == 1
    assert "Access-Control-Allow-Origin" in capsys.readouterr().err


def test_the_known_good_fixture_passes():
    assert wkh.main(["--fixture", str(FIX / "known-good.json")]) == 0


def test_a_non_https_site_is_refused():
    assert wkh.main(["--site", "http://samaydlette.com", "--fixture", str(FIX / "known-good.json")]) == 2


def _block(text, kind, name):
    start = text.index(f'resource "{kind}" "{name}"')
    depth, i = 0, text.index("{", start)
    for j in range(i, len(text)):
        depth += {"{": 1, "}": -1}.get(text[j], 0)
        if depth == 0:
            return text[start:j + 1]
    raise AssertionError("unbalanced")


def test_the_well_known_behaviour_sends_read_only_cors_and_nosniff():
    tf = (REPO / "infrastructure" / "bootstrap" / "cloudfront.tf").read_text()
    pol = _block(tf, "aws_cloudfront_response_headers_policy", "well_known")
    assert re.search(r'access_control_allow_origins\s*{\s*items\s*=\s*\["\*"\]', pol)
    assert re.search(r'access_control_allow_methods\s*{\s*items\s*=\s*\["GET", "HEAD", "OPTIONS"\]', pol)
    assert "access_control_allow_credentials = false" in pol
    assert "content_type_options" in pol
    dist = _block(tf, "aws_cloudfront_distribution", "website")
    beh = dist[dist.index('path_pattern               = "/.well-known/*"'):]
    beh = beh[:beh.index("ordered_cache_behavior") if "ordered_cache_behavior" in beh else len(beh)]
    assert "aws_cloudfront_response_headers_policy.well_known.id" in beh
    assert 'allowed_methods            = ["HEAD", "GET", "OPTIONS"]' in beh


def test_the_deploy_checks_the_headers_before_the_sdr():
    wf = (REPO / ".github" / "workflows" / "deploy-with-opa.yml").read_text()
    check = wf.index("- name: Check /.well-known/ JSON response headers (CORS, Content-Type, nosniff)")
    assert check < wf.index("- name: Build Security Decision Record")
    assert "scripts/check-wellknown-headers.py" in wf[check:check + 400]
