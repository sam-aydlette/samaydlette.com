export class Navigation {
  constructor() {
    this.sidebar = document.querySelector('.sidebar');
    // Support both .site-header (modern pages) and .header (article pages)
    this.header = document.querySelector('.site-header') || document.querySelector('.header');
    this.mobileThreshold = 768;
    this.init();
  }

  init() {
    this.setupMobileNav();
    this.initStickyHeader();
    window.addEventListener('resize', () => this.setupMobileNav(), { passive: true });
  }

  setupMobileNav() {
    const isMobile = window.innerWidth < this.mobileThreshold;

    // Handle dropdown menus
    const dropdowns = document.querySelectorAll('.dropdown');
    dropdowns.forEach(dropdown => {
      if (isMobile) {
        dropdown.style.position = 'static';
        dropdown.style.width = '100%';
      } else {
        dropdown.style.position = 'absolute';
        dropdown.style.width = '200px';
      }
    });
  }

  initStickyHeader() {
    // Add scroll behavior for sticky header
    if (!this.header) return;

    let lastScroll = 0;

    window.addEventListener('scroll', () => {
      const currentScroll = window.pageYOffset;

      // Add 'scrolled' class when scrolled past 100px
      if (currentScroll > 100) {
        this.header.classList.add('scrolled');
      } else {
        this.header.classList.remove('scrolled');
      }

      lastScroll = currentScroll;
    }, { passive: true });
  }
}
