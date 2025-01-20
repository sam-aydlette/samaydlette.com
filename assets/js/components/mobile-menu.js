// mobile-menu.js
export class MobileMenu {
    constructor() {
        this.init();
    }

    init() {
        // Create and insert hamburger menu button
        const header = document.querySelector('.header');
        if (!header.querySelector('.menu-toggle')) {
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

        // Setup event listeners
        const menuToggle = document.querySelector('.menu-toggle');
        const navbar = document.querySelector('.navbar');
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
        }
    }
}