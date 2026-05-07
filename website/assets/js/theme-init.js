// Apply the user's preferred theme before first paint to avoid a flash of
// light content. Lives in an external file so the page CSP can drop
// 'unsafe-inline' from script-src.
(function () {
    var savedTheme = localStorage.getItem('theme');
    var prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    var theme = savedTheme || (prefersDark ? 'dark' : 'light');
    if (theme === 'dark') {
        document.documentElement.setAttribute('data-theme', 'dark');
    }
})();
