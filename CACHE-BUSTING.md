# Cache Busting Guide

## What is Cache Busting?

Cache busting ensures that visitors to your website always get the latest version of your CSS and JavaScript files, rather than loading outdated versions from their browser cache.

## How It Works

All CSS and JavaScript files in your HTML files now include a version query parameter (e.g., `main.css?v=1766154770906`). When you update this version number, browsers will treat the file as new and download the latest version.

## Usage

### Automatic (CI)

The deploy workflow (`.github/workflows/deploy-with-opa.yml`) runs `node update-cache-version.js` immediately before the S3 sync step. Every deploy ships a fresh `?v=<timestamp>` on all CSS/JS references — no manual step required.

### Manual (local dev)

Run the script yourself when you want to preview the rewritten HTML locally:

```bash
npm run cache-bust
# or: node update-cache-version.js
```

You generally do not need to commit the rewritten `?v=` values; CI overwrites them on the next deploy.

### What Happens

The script will:
1. Generate a new version number based on the current timestamp
2. Find all HTML files in the `website/` directory
3. Update all CSS and JS file references with the new version number
4. Display a summary of updated files

### Example Output

```
Updating cache-busting version to: 1766154770906

✓ Updated: index.html
✓ Updated: pages/article-21.html
...

28 file(s) updated with version 1766154770906
```

## Technical Details

The cache-busting script (`update-cache-version.js`):
- Uses timestamp-based versioning for uniqueness
- Automatically finds and updates all HTML files
- Preserves existing file structure and formatting
- Only modifies version query parameters on asset URLs
