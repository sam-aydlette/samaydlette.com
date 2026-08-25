#!/usr/bin/env python3
"""The one place the essay tooling names a file.

Every gate and helper here used to carry its own copy of the essay's path.
Renaming the page therefore meant a seven-file sweep, and a missed copy failed
loudly in one tool and silently in another. They all read from here now, so a
rename is a one-line change.

Paths are relative to the repo root, because that is where the tools are run
from (`python3 tools/essay/integrity.py`).
"""

# The long-form essay these tools exist for.
ESSAY = 'website/research/staying-in-the-loop.html'

# Other pages the structural gate covers. The paper is long-form too; the
# homepage is not, but it links across the site and those edges are worth the
# same anchor check.
PAPER = 'website/research/the-plumbing.html'
INDEX = 'website/index.html'

# What a leading-slash href is relative to, as the site is served.
SITE_ROOT = 'website'
