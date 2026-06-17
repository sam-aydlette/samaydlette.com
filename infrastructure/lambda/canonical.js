// Deterministic JSON canonicalization for signing the runtime KSI signal
// (POAM-002). Isolated from index.js so it has no AWS-SDK dependency and can be
// exercised directly by tests and by external verifiers porting the recipe.
//
// Recipe (must be reproduced byte-for-byte by any verifier):
//   1. Remove `provenance.attestation` from the signal.
//   2. Serialize with object keys sorted lexicographically at every level,
//      arrays kept in order, and no insignificant whitespace.
//   3. The resulting UTF-8 bytes are what gets SHA-256'd and signed.
//
// This matches Python `json.dumps(obj, sort_keys=True, separators=(',', ':'),
// ensure_ascii=False)` for the ASCII-only content of the signal.
function canonicalize(value) {
    if (Array.isArray(value)) {
        return '[' + value.map(canonicalize).join(',') + ']';
    }
    if (value && typeof value === 'object') {
        const keys = Object.keys(value).sort();
        return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
    }
    return JSON.stringify(value);
}

module.exports = { canonicalize };
