#!/usr/bin/env python3
"""Prose-rules measurement for tuning-the-eigenvalue.html.

Eight levers, measured against the author's own baseline (pinned revision):
  1 xref        cross-referential scaffolding (Section N, note N, Appendix X, Query N)
  2 essay       'this essay' / 'the essay' / 'this section' self-reference
  3 ratherthan  the corrective 'X rather than Y' frame
  4 long        sentences over 30 words
  5 short       sentences <= 8 words (punch; we want MORE, not fewer)
  6 announce    announcing a speech act instead of performing it ("worth naming",
                "I want to state"). Zero in the author's prose; a machine tell.
  7 virtue      claiming a virtue instead of exhibiting it ("the honest version",
                "stating this plainly"), plus "precisely/exactly" used as a bare
                intensifier. All near-zero in the author's prose.
  8 grade       grading a point instead of making it ("a sharper problem than it
                first sounds", "and the kind matters"). Six in the body before the
                cut, zero after; the reader decides what is interesting.

Usage:  python3 prose_stats.py            # per-section table for the problem region
        python3 prose_stats.py --totals   # region totals + baseline comparison only
"""
import os
import re
import subprocess
import sys

FILE = 'website/research/tuning-the-eigenvalue.html'
# The whole body, matching the span the baseline is measured over. This was
# scoped to the problem region during the prose pass; the restructure since then
# has rewritten everything, and the front matter had never been measured at all,
# which is how "an exploration, not a proof" and a stray honesty claim survived
# four cleanup passes in the Author's Note.
START = 'id="authors-note"'
END = 'id="references"'

# TWO baselines, because they answer different questions.
#
# STRUCTURAL levers (cross-references, essay self-reference) are genre-bound: a
# memoir has no reason to say "Section 4.2". Those calibrate against the essay as
# it stood before the July 2026 revision, pinned by sha.
BASELINE_REV = '6e016a9c6453bc14b9d48ffa7c89333dac7214cf'
#
# VOICE levers (the tic families, sentence rhythm) must NOT calibrate against that
# text, because it is itself partly machine-written, so any tic present in both it
# and the revision passes silently. They calibrate against ~38k words the operator
# wrote by hand. Measured there: >30w 12.4%, <=8w 25.2%, mean 17.3 words.
# The corpus is the operator's own hand-written prose and is deliberately not
# named here: this repo is public, and the paths were local to one machine, so
# committing them disclosed a home directory and the working titles of
# unpublished drafts without making the script portable to anyone else. Only the
# measured rates are committed, because only the rates are what the gate reads.
# Point VOICE_CORPUS_DIR at a directory of hand-written prose to recompute them.
VOICE_CORPUS_DIR = os.environ.get('VOICE_CORPUS_DIR')
VOICE_LONG_PCT = 12.4   # NOT 9.3, which is what the contaminated baseline claimed
VOICE_SHORT_PCT = 25.2

XREF = re.compile(r'\b(?:Section\s+\d[\d.]*|Appendix\s+[A-D](?:\.\d+)?|note\s+\d+|Query\s+\d+|Proposition\s+\d)')
# The announce-then-do construction: telling the reader a speech act is coming
# instead of performing it. Zero instances in the author's own prose; it crept in
# during revision and is the clearest machine tell in the drafts so far.
_DISCOURSE = (r'naming|stating|noting|marking|mentioning|saying|spelling|pointing|'
              r'flagging|observing|remarking|emphasi[sz]ing|doing|making')
ANNOUNCE = re.compile(r'\bworth (?:' + _DISCOURSE + r')\b'
                      r'|\bI want to (?:be|say|state|name|mark|flag)\b'
                      r'|\bit is important to (?:note|say)\b', re.I)
# Tuned to the tic and not to the words: "honest feedback" and "honest enough"
# describe a real property, "plainly not" is an ordinary adverb, and "exactly what
# I have to do" means exactly. Only the virtue-claiming forms are flagged.
VIRTUE = re.compile(r'\bhonest(?:ly)?\b(?!\s+(?:feedback|enough))'
                    r'|\b(?:say|says|saying|said|stat\w+|put|putting)\s+(?:it\s+|this\s+|that\s+|so\s+)?plainly\b'
                    r'|\b(?:precisely|exactly)\s+(?:the|why|because|this|that)\b', re.I)
ESSAY = re.compile(r'\b(?:this essay|the essay|this Part|this section)\b', re.I)
# Grading a point instead of making it: telling the reader the coming statement is
# sharper, more interesting, or less embarrassing than they would expect. Distinct
# from ANNOUNCE, which flags a speech act; this flags a verdict on the author's own
# material. "which matters because X" is excluded: it gives a reason, not a grade.
GRADE = re.compile(
    r'\bthan (?:it|they|that|this) (?:sounds?|looks?|seems?|first \w+)'
    r'|\bmore (?:precise|interesting|serious|important|useful|subtle) than\b'
    r'|\bis the (?:interesting|useful|uncomfortable|important) part\b'
    r'|\bwhich is the (?:more|most) \w+ (?:problem|part|question|claim)\b'
    r'|\band the kind matters\b|\bis not (?:a )?(?:cosmetic|small|trivial|minor)\b', re.I)
RATHER = re.compile(r'\brather than\b', re.I)
# Measured against the hand-written corpus, not against the essay: 0.08/1k there,
# 0.61/1k here. "not A but B" is NOT included -- that one is genuinely his (0.42/1k).
NOTY = re.compile(r',\s+not\s+(?:a|an|the|its|his|her|my|only)\b|\bwhich is why\b', re.I)


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
                announce=len(ANNOUNCE.findall(t)) + len(VIRTUE.findall(t)),
                grade=len(GRADE.findall(t)),
                noty=len(NOTY.findall(t)),
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
        print(f"{'section':<48}{'w':>6}{'xref':>6}{'essay':>7}{'rthan':>7}{'annc':>7}{'>30w':>6}{'<=8w':>6}  flags")
        print('-' * 96)
        for name, s in segs:
            flag = ''
            if s['words'] > 120:
                if per1k(s, 'xref') > 2.5: flag += 'X'
                if per1k(s, 'essay') > 1.5: flag += 'E'
                if per1k(s, 'rather') > 1.5: flag += 'R'
                if s['announce'] > 0: flag += 'A'
                if s['sents'] and s['long'] / s['sents'] > 0.10: flag += 'L'
            print(f"{name:<48}{s['words']:>6}{s['xref']:>6}{s['essay']:>7}"
                  f"{s['rather']:>7}{s['announce']:>7}{s['long']:>6}{s['short']:>6}  {flag}")
        print('-' * 96)

    print(f"\n{'corpus':<24}{'words':>7}{'sents':>7}{'xref/1k':>9}{'essay/1k':>10}"
          f"{'rthan/1k':>10}{'annc':>7}{'>30w%':>8}{'<=8w%':>8}")
    for label, s in (('BASELINE (author)', B), ('CURRENT (whole body)', tot)):
        print(f"{label:<24}{s['words']:>7}{s['sents']:>7}{per1k(s,'xref'):>9.1f}"
              f"{per1k(s,'essay'):>10.1f}{per1k(s,'rather'):>10.1f}{s['announce']:>7d}"
              f"{s['long']/s['sents']*100:>8.1f}{s['short']/s['sents']*100:>8.1f}")

    w = tot['words'] / 1000
    print("\n=== edit sites remaining to reach baseline rates ===")
    print(f"  {'announce-then-do':<16}{tot['announce']:>4} -> 0    (0 in 38k hand-written words)")
    print(f"  {'self-grading':<16}{tot['grade']:>4} -> 0    (grading a point instead of making it)")
    print(f"  {'X-not-Y / why':<16}{tot['noty']:>4} -> ~{round(0.08*w):<3} (0.08/1k in the hand-written corpus)")
    print(f"  {'long sentences':<16}{tot['long']:>4} -> ~{round(VOICE_LONG_PCT/100*tot['sents']):<3} "
          f"({VOICE_LONG_PCT}% is his real rate; the old baseline said 9.3%)")
    for key, label in (('xref', 'cross-refs'), ('essay', "'this essay'"), ('rather', "'rather than'")):
        target = round(per1k(B, key) * w)
        print(f"  {label:<16}{tot[key]:>4} -> ~{target:<4} (cut ~{max(0, tot[key]-target)})")



if __name__ == '__main__':
    main()
