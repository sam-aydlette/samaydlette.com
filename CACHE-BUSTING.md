# Cache Busting Guide

## What is Cache Busting?

Cache busting ensures that visitors to your website always get the latest version of your CSS and JavaScript files, rather than loading outdated versions from their browser cache.

## How It Works

All CSS and JavaScript files in your HTML files now include a version query parameter (e.g., `main.css?v=1766154770906`). When you update this version number, browsers will treat the file as new and download the latest version.

## Usage

### When to Run Cache Busting

Run the cache-busting script **every time** you:
- Update any CSS files
- Update any JavaScript files
- Make changes that need to be immediately visible to all visitors

### How to Run

You have two options:

**Option 1: Using npm**
```bash
npm run cache-bust
```

**Option 2: Using node directly**
```bash
node update-cache-version.js
```

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

## Before Deployment

**Important:** Always run the cache-busting script before deploying your website to ensure visitors get the latest version of all assets.

### Recommended Workflow

1. Make your changes to CSS/JS files
2. Run `npm run cache-bust`
3. Test your changes locally
4. Commit all changes (including updated HTML files)
5. Deploy to production

## Technical Details

The cache-busting script (`update-cache-version.js`):
- Uses timestamp-based versioning for uniqueness
- Automatically finds and updates all HTML files
- Preserves existing file structure and formatting
- Only modifies version query parameters on asset URLs
