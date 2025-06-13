export function setupScrollObserver() {
  if ('IntersectionObserver' in window) {
    const options = {
      root: null,
      rootMargin: '0px',
      threshold: 0.1
    };

    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        // Add this check
        if (!entry.target.classList.contains('revealed')) {
          entry.target.classList.add('reveal-on-scroll');
        }
        
        if (entry.isIntersecting) {
          // Small delay to ensure initial state is set
          requestAnimationFrame(() => {
            entry.target.classList.add('revealed');
          });
          observer.unobserve(entry.target);
        }
      });
    }, options);

    // Modify the selector to be more specific
    document.querySelectorAll('.article-card:not(.revealed)').forEach(el => {
      observer.observe(el);
    });
  } else {
    // Fallback for browsers without IntersectionObserver
    document.querySelectorAll('.article-card').forEach(el => {
      el.classList.add('revealed');
    });
  }
}
