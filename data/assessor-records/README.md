# Assessor records (REQ-ASR-1)

Signed records from an assessor go here, one JSON file per record, in the format
`infrastructure/schemas/assessor-record.schema.json`. `scripts/build-sdr.py`
verifies each against the identity pinned at
`infrastructure/keys/assessor-identity.json` and fails the build on any record
that is unsigned, altered, or signed by anyone else. The SDR carries each
record's text verbatim with its signature (T74).

There are none. No assessor has been engaged, so no identity is pinned and the
SDR states "no assessor record". Engaging one means pinning their public key in
a reviewed change (JSON: `assessor`, `key_id`, `algorithm`, `pinned_on`,
`public_key_pem`, `public_key_sha256`) before any record of theirs is added.
