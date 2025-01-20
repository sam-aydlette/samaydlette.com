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

        if (menuToggle && navbar) {
            menuToggle.addEventListener('click', () => {
                menuToggle.classList.toggle('active');
                navbar.classList.toggle('active');
            });

            // Close menu when clicking outside
            document.addEventListener('click', (e) => {
                if (!navbar.contains(e.target) && !menuToggle.contains(e.target)) {
                    menuToggle.classList.remove('active');
                    navbar.classList.remove('active');
                }
            });
        }
    }
}