# Site mark

`logo.svg` is the source: "SA" in JetBrains Mono Bold, the site's monospace
face, in light text on the dark theme's background. The letters are outlines,
not text, so the mark renders the same without the font.

The raster copies are rendered from it, never edited by hand:

- `logo.png` (512 px), the logo the CPO publishes (`data/cds/offering.json`).
- `apple-touch-icon.png` (180 px).
- `/favicon.ico` (16, 32, 48 and 64 px), at the site root, where browsers ask for it.

To change the letters, instance the variable font at weight 700 with fontTools
(`varLib.instancer`), draw the glyphs with `SVGPathPen` and centre their ink box
in the tile. To re-render the rasters, wrap the SVG in a page that sizes an
`<img>` to the viewport, screenshot that page with headless Chromium at 512x512
(`--default-background-color=00000000`), then resize it with Pillow (LANCZOS)
for the other sizes.
