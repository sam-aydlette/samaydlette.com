# Boundary map corroboration (local only)

`corroborate.py` checks the published boundary map against an independent
collection of the AWS account by RAMPART on TAP (The Analogy Platform). The map
is built from Terraform state; TAP reads the AWS APIs directly, so the comparison
finds what the pipeline cannot see about itself: resources created outside
Terraform, resources the map says exist but TAP did not observe, drifted
classification tags, and relationships the map does not draw.

It needs a running local TAP session with the aws_core collector configured for
this account's read-only role, so it never runs in CI.

    python3 tools/boundary-map/corroborate.py --collect

writes `docs/boundary/corroboration.json`. Commit it in a PR; the next deploy
signs it and publishes it at `/.well-known/boundary-corroboration.json`, and the
trust center reports the result and its age (it asks for a new run after 30
days). The report fails closed on any ARN, account ID or email address.
