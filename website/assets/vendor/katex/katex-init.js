// Self-hosted KaTeX auto-render initialization.
//
// Loaded as the third deferred script after katex.min.js and auto-render.min.js.
// Because all three are `defer`, they execute in document order after the DOM is
// fully parsed, so `renderMathInElement` is defined and `document.body` exists by
// the time this runs. Kept in an external file (rather than an inline `onload=`
// handler) so the page renders math under a strict `script-src 'self'` CSP with no
// inline-script allowance.
renderMathInElement(document.body, {
  delimiters: [
    { left: "$$", right: "$$", display: true },
    { left: "$", right: "$", display: false },
  ],
});
