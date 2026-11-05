'use strict';
// Drives infrastructure/lambda/describers.js with a fake AWS adapter built
// from a JSON fixture, for tests/test_runtime_readers.py. Plain node, no SDK.
//
//   node harness.js <components.json> <responses.json>
//
// responses.json maps "<service>.<method>" to {"<first argument>": value};
// a missing key, or a value {"$error": "Name"}, makes the call throw an error
// with that name (AccessDenied by default), as the SDK would. Prints the
// validations and every policy input the readers produced.
const fs = require('fs');
const path = require('path');
const { validateComponents, READERS } = require(path.join(__dirname, '..', '..', '..', 'infrastructure', 'lambda', 'describers.js'));

const [componentsPath, responsesPath] = process.argv.slice(2);
const components = JSON.parse(fs.readFileSync(componentsPath));
const responses = JSON.parse(fs.readFileSync(responsesPath));

function call(service, method) {
    return async (...args) => {
        const table = responses[`${service}.${method}`] || {};
        const key = args.join('|');
        const value = table[key];
        if (value === undefined || (value && value.$error)) {
            const err = new Error('denied');
            err.name = (value && value.$error) || 'AccessDenied';
            throw err;
        }
        return value;
    };
}

const aws = new Proxy({}, {
    get: (_, service) => new Proxy({}, { get: (__, method) => call(service, method) }),
});

(async () => {
    const tags = new Map(Object.entries(responses.tags || {}));
    const ctx = {
        aws, region: 'us-east-2', account: '123456789012', tags, components,
        taggableTypes: JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', '..', 'infrastructure', 'policy', 'config', 'data.json'))).gate.taggable_types,
        now: () => Date.parse('2026-11-05T00:00:00Z'),
    };
    const inputs = [];
    let n = 0;
    const evaluate = async (input) => { inputs.push(input); return { compliant: true, violations: [] }; };
    const validations = await validateComponents(ctx, components, evaluate, 'terraform.compliance', 'test', () => `r-${n++}`);
    process.stdout.write(JSON.stringify({ readers: Object.keys(READERS), validations, inputs }));
})().catch((e) => { console.error(e); process.exit(1); });
