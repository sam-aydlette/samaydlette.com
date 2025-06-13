export class Navigation {
  constructor() {
    this.sidebar = document.querySelector('.sidebar');
    this.mobileThreshold = 768;
    this.init();
  }

  init() {
    this.setupMobileNav();
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
}
