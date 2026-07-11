#!/usr/bin/env node
// =============================================================================
// ACCESSIBILITY FACT PRODUCER
// =============================================================================
// Runs pa11y (WCAG 2 AA via HTML_CodeSniffer, in headless Chromium) over every
// HTML file under the given directory and writes ONE JSON facts document to
// stdout (or --out FILE).
//
// The pattern this file exists to demonstrate: SCANNERS PRODUCE FACTS, OPA
// DECIDES. This script renders pages in a real browser engine and reports
// what it saw — it contains no pass/fail logic. The decision (which issue
// types fail the gate, exceptions, severity mapping) lives in
// infrastructure/policy/accessibility.rego against data.config, where it is
// reviewable, testable, and versioned like every other policy decision.
//
// Output shape (the policy's `accessibility_scan` input):
//   {
//     "accessibility_scan": {
//       "scanner": {"name": "pa11y", "version": "9.1.1", "standard": "WCAG2AA"},
//       "pages": [{
//         "file_name": "index.html",
//         "file_path": "../website/index.html",   // as given on the CLI
//         "issues": [{"code", "type", "message", "selector", "context"}]
//       }]
//     }
//   }
//
// Chromium resolution: set A11Y_CHROME to a browser binary (CI uses the
// runner's system Chrome with PUPPETEER_SKIP_DOWNLOAD=1); otherwise pa11y
// uses puppeteer's own download. A11Y_NO_SANDBOX=1 adds --no-sandbox for
// container environments.
// =============================================================================

'use strict';

const fs = require('fs');
const path = require('path');
const pa11y = require('pa11y');

function findHtmlFiles(dir) {
    const out = [];
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, entry.name);
        if (entry.isDirectory()) out.push(...findHtmlFiles(p));
        else if (entry.isFile() && entry.name.endsWith('.html')) out.push(p);
    }
    return out.sort();
}

async function main() {
    const args = process.argv.slice(2);
    let outFile = null;
    const outIdx = args.indexOf('--out');
    if (outIdx !== -1) {
        outFile = args[outIdx + 1];
        args.splice(outIdx, 2);
    }
    const targetDir = args[0];
    if (!targetDir || !fs.existsSync(targetDir)) {
        console.error('usage: node scan.js <html-dir> [--out facts.json]');
        process.exit(2);
    }

    const chromeArgs = [];
    if (process.env.A11Y_NO_SANDBOX === '1') chromeArgs.push('--no-sandbox');
    const chromeLaunchConfig = { args: chromeArgs };
    if (process.env.A11Y_CHROME) chromeLaunchConfig.executablePath = process.env.A11Y_CHROME;

    const files = findHtmlFiles(targetDir);
    const pages = [];
    for (const file of files) {
        const result = await pa11y(`file://${path.resolve(file)}`, {
            standard: 'WCAG2AA',
            includeWarnings: false, // warnings/notices are advisory; the gate decides on errors
            timeout: 60000,
            chromeLaunchConfig,
        });
        pages.push({
            file_name: path.basename(file),
            file_path: file,
            issues: result.issues.map((i) => ({
                code: i.code,
                type: i.type,
                message: i.message,
                selector: i.selector,
                context: i.context,
            })),
        });
        console.error(`scanned ${file}: ${result.issues.length} issue(s)`);
    }

    const facts = {
        accessibility_scan: {
            scanner: {
                name: 'pa11y',
                version: require('pa11y/package.json').version,
                standard: 'WCAG2AA',
            },
            pages,
        },
    };
    const json = JSON.stringify(facts, null, 2);
    if (outFile) fs.writeFileSync(outFile, json);
    else process.stdout.write(json + '\n');
}

main().catch((err) => {
    // A scanner that cannot run must not look like a clean scan: exit
    // non-zero so the calling gate fails closed.
    console.error(`scan failed: ${err.message}`);
    process.exit(1);
});
