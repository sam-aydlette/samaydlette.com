"""PR-C: EPSS-driven Likely-Exploitable (LEV) union.

LEV = (EPSS >= governed threshold) OR (active exploitation: CISA KEV /
exploitation=active), with a severity-proxy fail-safe when EPSS is unavailable.
"""
import gzip
import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _vdr():
    spec = importlib.util.spec_from_file_location("vdr", REPO / "scripts" / "build-vdr-report.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


vdr = _vdr()
THRESH = 0.70

EPSS_CSV = (
    "#model_version:v2026.06.30,score_date:2026-06-30T00:00:00+0000\n"
    "cve,epss,percentile\n"
    "CVE-2026-HIGH,0.91234,0.990\n"
    "CVE-2026-LOWP,0.00100,0.200\n"
)


# --- ingest_epss ---------------------------------------------------------------

def test_ingest_epss_csv(tmp_path):
    p = tmp_path / "epss.csv"
    p.write_text(EPSS_CSV)
    scores = vdr.ingest_epss(str(p))
    assert scores["CVE-2026-HIGH"] == 0.91234
    assert scores["CVE-2026-LOWP"] == 0.001


def test_ingest_epss_gzip(tmp_path):
    p = tmp_path / "epss.csv.gz"
    p.write_bytes(gzip.compress(EPSS_CSV.encode()))
    scores = vdr.ingest_epss(str(p))
    assert scores["CVE-2026-HIGH"] == 0.91234


def test_ingest_epss_json(tmp_path):
    p = tmp_path / "epss.json"
    p.write_text(json.dumps({"data": [{"cve": "CVE-2026-HIGH", "epss": "0.8"}]}))
    assert vdr.ingest_epss(str(p))["CVE-2026-HIGH"] == 0.8


def test_ingest_epss_missing_returns_empty():
    assert vdr.ingest_epss(None) == {}
    assert vdr.ingest_epss("/no/such/file.csv") == {}


# --- the LEV union -------------------------------------------------------------

def test_lev_true_when_epss_at_or_above_threshold():
    f = {"cve": "CVE-2026-HIGH", "severity": "LOW"}
    assert vdr.is_likely_exploitable(f, {"CVE-2026-HIGH": 0.91}, THRESH) is True


def test_lev_false_when_epss_below_threshold_overrides_severity_proxy():
    """EPSS is present and sub-threshold: trust the real signal even though the
    finding is HIGH. This is the classifier getting more accurate, not data
    missing — so a sub-threshold HIGH is NLEV."""
    f = {"cve": "CVE-2026-LOWP", "severity": "HIGH"}
    assert vdr.is_likely_exploitable(f, {"CVE-2026-LOWP": 0.001}, THRESH) is False


def test_lev_true_for_kev_regardless_of_epss():
    f = {"cve": "CVE-2026-LOWP", "severity": "LOW"}
    assert vdr.is_likely_exploitable(f, {"CVE-2026-LOWP": 0.001}, THRESH, is_kev=True) is True


def test_lev_true_for_explicit_active_exploitation():
    f = {"cve": "CVE-2026-LOWP", "severity": "LOW", "exploitation": "active"}
    assert vdr.is_likely_exploitable(f, {"CVE-2026-LOWP": 0.001}, THRESH) is True


def test_lev_failsafe_high_when_epss_unavailable():
    """No EPSS for this CVE (or no feed): missing data must not lower the
    determination, so HIGH/CRITICAL falls back to the conservative proxy."""
    f = {"cve": "CVE-2026-NOEPSS", "severity": "HIGH"}
    assert vdr.is_likely_exploitable(f, {}, THRESH) is True


def test_lev_failsafe_medium_stays_nlev_when_epss_unavailable():
    f = {"cve": "CVE-2026-NOEPSS", "severity": "MEDIUM"}
    assert vdr.is_likely_exploitable(f, {}, THRESH) is False


def test_lev_union_is_not_a_blend():
    """Either input firing is sufficient; KEV wins even with a tiny EPSS."""
    f = {"severity": "LOW", "cve": "CVE-2026-LOWP"}
    assert vdr.is_likely_exploitable(f, {"CVE-2026-LOWP": 0.0}, THRESH, is_kev=True) is True
