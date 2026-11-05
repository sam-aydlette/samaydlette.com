# Site mark

`logo.svg` is the source. It reduces the header's `> Sam Aydlette` to its two
parts, in the header's own colours: the blue prompt and an amber block cursor,
on the dark theme's terminal background. A green baseline sits under them, the
signed evidence the prompt stands on. In the SVG the cursor blinks, unless the
viewer has asked for reduced motion.

The raster copies are rendered from it, never edited by hand:

- `logo.png` (512 px), the logo the CPO publishes (`data/cds/offering.json`).
- `apple-touch-icon.png` (180 px).
- `/favicon.ico` (16, 32, 48 and 64 px), at the site root, where browsers ask for it.

To re-render after changing the SVG: wrap it in a page that sizes an `<img>` to
the viewport, screenshot that page with headless Chromium at 512x512
(`--default-background-color=00000000 --force-prefers-reduced-motion`, so the
cursor is caught lit), then resize it with Pillow (LANCZOS) for the other sizes.
