#!/usr/bin/env python3
"""Prose-rules measurement for tuning-the-eigenvalue.html.

Five levers, measured against the author's own baseline (git HEAD = pre-revision):
  1 xref        cross-referential scaffolding (Section N, note N, Appendix X, Query N)
  2 essay       'this essay' / 'the essay' / 'this section' self-reference
  3 ratherthan  the corrective 'X rather than Y' frame
  4 long        sentences over 30 words
  5 short       sentences <= 8 words (punch; we want MORE, not fewer)

Usage:  python3 prose_stats.py            # per-section table for the problem region
        python3 prose_stats.py --totals   # region totals + baseline comparison only
"""
import re
import subprocess
import sys

FILE = 'website/research/tuning-the-eigenvalue.html'
START = 'id="three-things-called-criticality"'   # 2.2.1 — everything from here on
END = 'id="references"'

# The lever baseline is the author's own prose as it stood before the July 2026
# revision. Pinned by sha rather than HEAD so the comparison stays fixed as the
# restructure commits on top of it.
BASELINE_REV = '6e016a9c6453bc14b9d48ffa7c89333dac7214cf'

XREF = re.compile(r'\b(?:Section\s+\d[\d.]*|Appendix\s+[A-D](?:\.\d+)?|note\s+\d+|Query\s+\d+|Proposition\s+\d)')
ESSAY = re.compile(r'\b(?:this essay|the essay|this Part|this section)\b', re.I)
RATHER = re.compile(r'\brather than\b', re.I)


def prose(x):
    """HTML -> plain prose, minus tables/code/headings/math (those aren't voice)."""
    x = re.sub(r'<table.*?</table>', ' ', x, flags=re.S)
    x = re.sub(r'<pre.*?</pre>', ' ', x, flags=re.S)
    x = re.sub(r'<h[1-6][^>]*>.*?</h[1-6]>', ' ', x, flags=re.S)
    x = re.sub(r'\$\$.*?\$\$', ' MATH ', x, flags=re.S)
    x = re.sub(r'\$[^$]*\$', ' m ', x)
    x = re.sub(r'<[^>]+>', ' ', x)
    x = re.sub(r'&[a-z]+;|&#\d+;', ' ', x)
    return re.sub(r'\s+', ' ', x).strip()


def sentences(t):
    return [s for s in re.split(r'(?<=[.!?]) +', t) if s.strip()]


def stats(t):
    ss = sentences(t)
    w = len(t.split())
    return dict(words=w, sents=len(ss),
                xref=len(XREF.findall(t)), essay=len(ESSAY.findall(t)),
                rather=len(RATHER.findall(t)),
                long=sum(1 for s in ss if len(s.split()) > 30),
                short=sum(1 for s in ss if len(s.split()) <= 8))


def per1k(s, k):
    return s[k] / s['words'] * 1000 if s['words'] else 0.0


def load():
    cur = open(FILE).read()
    base = subprocess.run(['git', 'show', BASELINE_REV + ':' + FILE], capture_output=True,
                          text=True, check=True).stdout
    return cur, base


def main():
    cur, base = load()
    region = cur[cur.index(START):cur.index(END)]
    b = base[base.index('id="authors-note"'):base.index('id="references"')]
    B = stats(prose(b))

    # split the region into (heading, body) segments
    parts = re.split(r'(<h[1-6][^>]*id="([^"]+)"[^>]*>(.*?)</h[1-6]>)', region, flags=re.S)
    segs, i = [], 0
    # leading text before first heading belongs to 2.2.1's own heading, handled below
    heads = re.findall(r'<h[1-6][^>]*id="([^"]+)"[^>]*>(.*?)</h[1-6]>', region, flags=re.S)
    bounds = [m.start() for m in re.finditer(r'<h[1-6][^>]*id="[^"]+"', region)] + [len(region)]
    for idx, (hid, htxt) in enumerate(heads):
        body = region[bounds[idx]:bounds[idx + 1]]
        segs.append((re.sub(r'<[^>]+>', '', htxt).strip()[:46], stats(prose(body))))

    tot = stats(prose(region))
    if '--totals' not in sys.argv:
        print(f"{'section':<48}{'w':>6}{'xref':>6}{'essay':>7}{'rthan':>7}{'>30w':>6}{'<=8w':>6}  flags")
        print('-' * 96)
        for name, s in segs:
            flag = ''
            if s['words'] > 120:
                if per1k(s, 'xref') > 2.5: flag += 'X'
                if per1k(s, 'essay') > 1.5: flag += 'E'
                if per1k(s, 'rather') > 1.5: flag += 'R'
                if s['sents'] and s['long'] / s['sents'] > 0.10: flag += 'L'
            print(f"{name:<48}{s['words']:>6}{s['xref']:>6}{s['essay']:>7}"
                  f"{s['rather']:>7}{s['long']:>6}{s['short']:>6}  {flag}")
        print('-' * 96)

    print(f"\n{'corpus':<24}{'words':>7}{'sents':>7}{'xref/1k':>9}{'essay/1k':>10}"
          f"{'rthan/1k':>10}{'>30w%':>8}{'<=8w%':>8}")
    for label, s in (('BASELINE (author)', B), ('REGION 2.2.1+', tot)):
        print(f"{label:<24}{s['words']:>7}{s['sents']:>7}{per1k(s,'xref'):>9.1f}"
              f"{per1k(s,'essay'):>10.1f}{per1k(s,'rather'):>10.1f}"
              f"{s['long']/s['sents']*100:>8.1f}{s['short']/s['sents']*100:>8.1f}")

    w = tot['words'] / 1000
    print("\n=== edit sites remaining to reach baseline rates ===")
    for key, label in (('xref', 'cross-refs'), ('essay', "'this essay'"), ('rather', "'rather than'")):
        target = round(per1k(B, key) * w)
        print(f"  {label:<16}{tot[key]:>4} -> ~{target:<4} (cut ~{max(0, tot[key]-target)})")
    tl = round(B['long'] / B['sents'] * tot['sents'])
    print(f"  {'long sentences':<16}{tot['long']:>4} -> ~{tl:<4} (split ~{max(0, tot['long']-tl)})")


if __name__ == '__main__':
    main()
