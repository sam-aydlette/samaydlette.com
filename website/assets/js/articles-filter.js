// Article search + category filtering for pages/articles.html.
// Externalized from inline handlers (onkeyup / onclick) so the page works under
// a strict `script-src 'self'` CSP. Buttons declare their filter value via a
// `data-category` attribute; this binds delegated listeners on load.
(function () {
    function filterArticles() {
        const query = document.getElementById('searchInput').value.toLowerCase();
        document.querySelectorAll('article.article-card').forEach(article => {
            const title = article.querySelector('h3').textContent.toLowerCase();
            const content = article.querySelector('p').textContent.toLowerCase();
            article.style.display =
                (title.includes(query) || content.includes(query)) ? 'block' : 'none';
        });
    }

    function filterByCategory(category, clickedBtn) {
        document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
        if (clickedBtn) clickedBtn.classList.add('active');

        const search = document.getElementById('searchInput');
        if (search) search.value = '';

        document.querySelectorAll('article.article-card').forEach(article => {
            const articleCategory = article.querySelector('.article-category').textContent.trim();
            article.style.display =
                (category === 'all' || articleCategory === category) ? 'block' : 'none';
        });
    }

    document.addEventListener('DOMContentLoaded', function () {
        const search = document.getElementById('searchInput');
        if (search) search.addEventListener('input', filterArticles);

        document.querySelectorAll('.category-filters .filter-btn').forEach(btn => {
            btn.addEventListener('click', function () {
                filterByCategory(btn.dataset.category, btn);
            });
        });
    });
})();
