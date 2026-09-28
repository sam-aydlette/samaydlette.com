# Boundary map icons

The live boundary map's data is not here: it is generated on every deploy by
`scripts/build-boundary-graph.py`, signed, and published at
`/.well-known/boundary-map.json`. This directory holds only the icons the viewer
(`assets/js/boundary-map.js`) draws, served from this origin so the page loads nothing
from a third party. `tests/test_boundary_map.py` checks that none can run script.

| Files | Origin |
|-------|--------|
| `icons/aws-*.svg` | Official **AWS Architecture Icons**, as normalised and shipped in [tap-plugin-aws-core](https://github.com/unified-systems-com/tap-plugin-aws-core) (`static/aws_core/icons/`). AWS publishes the pack for customers to use in architecture diagrams, which is this use. |
| `icons/github-*.svg` | Shipped in [tap-plugin-github-core](https://github.com/unified-systems-com/tap-plugin-github-core) (`static/github_core/icons/`), Apache-2.0 |
| `icons/rekor-log-entry.svg`, `icons/sigstore-ca.svg` | Shipped in [tap-plugin-sigstore-core](https://github.com/unified-systems-com/tap-plugin-sigstore-core), Apache-2.0 |
| `icons/ksi-signal.svg`, `icons/vdr-report.svg` | Shipped in [tap-plugin-fedramp-20x-ksi](https://github.com/unified-systems-com/tap-plugin-fedramp-20x-ksi), Apache-2.0 |
