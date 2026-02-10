#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// Generate version based on current timestamp
const version = Date.now();

console.log(`\nUpdating cache-busting version to: ${version}\n`);

// Patterns to match CSS and JS file references
const cssPattern = /(href=["'])(\/assets\/css\/[^"'?]+\.css)(\?v=\d+)?(["'])/g;
const jsPattern = /(src=["'])(\/assets\/js\/[^"'?]+\.js)(\?v=\d+)?(["'])/g;

// Find all HTML files
function findHtmlFiles(dir) {
    const files = [];
    const items = fs.readdirSync(dir, { withFileTypes: true });

    for (const item of items) {
        const fullPath = path.join(dir, item.name);
        if (item.isDirectory()) {
            files.push(...findHtmlFiles(fullPath));
        } else if (item.isFile() && item.name.endsWith('.html')) {
            files.push(fullPath);
        }
    }

    return files;
}

// Update version in file content
function updateFileVersions(content) {
    // Update CSS references
    content = content.replace(cssPattern, (match, prefix, file, oldVersion, suffix) => {
        return `${prefix}${file}?v=${version}${suffix}`;
    });

    // Update JS references
    content = content.replace(jsPattern, (match, prefix, file, oldVersion, suffix) => {
        return `${prefix}${file}?v=${version}${suffix}`;
    });

    return content;
}

// Main execution
const websiteDir = path.join(__dirname, 'website');
const htmlFiles = findHtmlFiles(websiteDir);

let updatedCount = 0;

htmlFiles.forEach(filePath => {
    const content = fs.readFileSync(filePath, 'utf8');
    const updatedContent = updateFileVersions(content);

    if (content !== updatedContent) {
        fs.writeFileSync(filePath, updatedContent, 'utf8');
        console.log(`✓ Updated: ${path.relative(websiteDir, filePath)}`);
        updatedCount++;
    }
});

console.log(`\n${updatedCount} file(s) updated with version ${version}\n`);
