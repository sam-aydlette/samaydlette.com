// Updated mobile-menu.js for Option 1 Design
export class MobileMenu {
    constructor() {
        this.init();
    }

    init() {
        // Create and insert hamburger menu button if it doesn't exist
        // Support both .site-header (modern pages) and .header (article pages)
        const header = document.querySelector('.site-header') || document.querySelector('.header');

        if (header && !header.querySelector('.menu-toggle')) {
            const menuToggle = document.createElement('button');
            menuToggle.className = 'menu-toggle';
            menuToggle.setAttribute('aria-label', 'Toggle menu');
            menuToggle.innerHTML = `
                <span></span>
                <span></span>
                <span></span>
            `;
            header.appendChild(menuToggle);
        }

        // Setup event listeners (whether button was created or already exists)
        const menuToggle = document.querySelector('.menu-toggle');
        // Support both .main-nav (modern pages) and .navbar (article pages)
        const navbar = document.querySelector('.main-nav') || document.querySelector('.navbar');
        let isMenuOpen = false;

        if (menuToggle && navbar) {
            // Toggle menu when hamburger is clicked
            menuToggle.addEventListener('click', (e) => {
                e.stopPropagation();
                isMenuOpen = !isMenuOpen;
                menuToggle.classList.toggle('active');
                navbar.classList.toggle('active');
            });

            // Close menu when clicking outside
            document.addEventListener('click', (e) => {
                if (isMenuOpen && !navbar.contains(e.target) && !menuToggle.contains(e.target)) {
                    isMenuOpen = false;
                    menuToggle.classList.remove('active');
                    navbar.classList.remove('active');
                }
            });

            // Close menu when pressing escape key
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape' && isMenuOpen) {
                    isMenuOpen = false;
                    menuToggle.classList.remove('active');
                    navbar.classList.remove('active');
                }
            });

            // Close menu when resizing to desktop view
            window.addEventListener('resize', () => {
                if (window.innerWidth > 768 && isMenuOpen) {
                    isMenuOpen = false;
                    menuToggle.classList.remove('active');
                    navbar.classList.remove('active');
                }
            });

            // Close menu when clicking on nav links (mobile)
            // Support both .nav-link (modern pages) and .nav-button (article pages)
            const navLinks = navbar.querySelectorAll('.nav-link, .nav-button');
            navLinks.forEach(link => {
                link.addEventListener('click', () => {
                    if (window.innerWidth <= 768 && isMenuOpen) {
                        isMenuOpen = false;
                        menuToggle.classList.remove('active');
                        navbar.classList.remove('active');
                    }
                });
            });
        }
    }
}