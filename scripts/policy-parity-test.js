#!/usr/bin/env node
// =============================================================================
// DEPLOY-TIME / RUNTIME POLICY PARITY TEST
// =============================================================================
// One Rego source serves two enforcement points: the deploy gate evaluates it
// with the OPA CLI, the runtime Lambda executes it compiled to Wasm under
// @open-policy-agent/opa-wasm. Same source does not automatically mean same
// behavior: the Wasm host implements some builtins in JavaScript (e.g.
// sprintf via sprintf-js, which rejects the %q verb the Go implementation
// accepts), so an expression can work in CI and throw in the Lambda.
//
// This test runs the entire fixture corpus through BOTH evaluators and diffs
// the full compliance_report values. Any divergence — verdict, violation
// content, or a Wasm-side builtin error — fails the build.
//
// Usage:
//   node scripts/policy-parity-test.js \
//     --wasm <policy.wasm> --data <bundle-data.json> \
//     [--opa opa] [--policy infrastructure/policy]
//
// Run from the repo root. Requires the Lambda's node_modules for opa-wasm
// (NODE_PATH=infrastructure/lambda/node_modules works in CI).
// =============================================================================

'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { loadPolicy } = require('@open-policy-agent/opa-wasm');

const REPO = path.resolve(__dirname, '..');

function arg(name, fallback) {
    const i = process.argv.indexOf(`--${name}`);
    return i === -1 ? fallback : process.argv[i + 1];
}

const WASM = arg('wasm');
const DATA = arg('data');
const OPA = arg('opa', 'opa');
const POLICY = arg('policy', path.join(REPO, 'infrastructure', 'policy'));

if (!WASM || !DATA) {
    console.error('usage: policy-parity-test.js --wasm policy.wasm --data data.json');
    process.exit(2);
}

function corpus() {
    const inputs = [];
    for (const dir of ['plans', 'resources', 'a11y']) {
        const d = path.join(REPO, 'tests', 'fixtures', dir);
        for (const f of fs.readdirSync(d).filter((x) => x.endsWith('.json')).sort()) {
            const doc = JSON.parse(fs.readFileSync(path.join(d, f)));
            delete doc._fixture;
            inputs.push({ name: `${dir}/${f}`, doc });
        }
    }
    return inputs;
}

function cliEval(inputDoc) {
    const tmp = path.join(REPO, '.parity-input.json');
    fs.writeFileSync(tmp, JSON.stringify(inputDoc));
    try {
        const out = execFileSync(OPA, [
            'eval', '--strict-builtin-errors',
            '-d', POLICY,
            '-i', tmp,
            'data.terraform.compliance.compliance_report',
        ], { encoding: 'utf8' });
        return JSON.parse(out).result[0].expressions[0].value;
    } finally {
        fs.unlinkSync(tmp);
    }
}

// Stable deep-canonicalization: Rego sets serialize in nondeterministic
// order across evaluators; sort arrays of objects by their JSON form.
function canonical(x) {
    if (Array.isArray(x)) {
        const items = x.map(canonical);
        return items.slice().sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
    }
    if (x && typeof x === 'object') {
        return Object.fromEntries(Object.keys(x).sort().map((k) => [k, canonical(x[k])]));
    }
    return x;
}

async function main() {
    const wasmPolicy = await loadPolicy(fs.readFileSync(WASM));
    wasmPolicy.setData(JSON.parse(fs.readFileSync(DATA)));

    let failures = 0;
    for (const { name, doc } of corpus()) {
        let cli;
        let wasm;
        try {
            cli = canonical(cliEval(doc));
        } catch (e) {
            console.error(`FAIL ${name}: CLI eval error: ${e.message.split('\n')[0]}`);
            failures += 1;
            continue;
        }
        try {
            wasm = canonical(wasmPolicy.evaluate(doc)[0].result);
        } catch (e) {
            console.error(`FAIL ${name}: Wasm eval error (Lambda would throw): ${e.message.split('\n')[0]}`);
            failures += 1;
            continue;
        }
        if (JSON.stringify(cli) !== JSON.stringify(wasm)) {
            failures += 1;
            console.error(`FAIL ${name}: CLI and Wasm reports differ`);
            console.error(`  cli:  ${JSON.stringify(cli).slice(0, 300)}`);
            console.error(`  wasm: ${JSON.stringify(wasm).slice(0, 300)}`);
        } else {
            console.log(`ok ${name} (compliant=${cli.compliant})`);
        }
    }

    if (failures) {
        console.error(`\n${failures} parity failure(s): deploy-time and runtime enforcement have drifted.`);
        process.exit(1);
    }
    console.log('\nParity: CLI and Wasm evaluation agree on the full corpus.');
}

main().catch((e) => {
    console.error(`parity test could not run: ${e.message}`);
    process.exit(1);
});
