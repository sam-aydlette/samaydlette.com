export function setupScrollObserver() {
  if ('IntersectionObserver' in window) {
    const options = {
      root: null,
      rootMargin: '0px',
      threshold: 0.1
    };

    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('revealed');
          observer.unobserve(entry.target);
        }
      });
    }, options);

    // Observe all sections and cards
    document.querySelectorAll('.book-card, .article-card, section').forEach(el => {
      el.classList.add('reveal-on-scroll');
      observer.observe(el);
    });
  }}
