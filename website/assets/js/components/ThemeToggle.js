// Updated ThemeToggle.js for Option 1 Design
export class ThemeToggle {
    constructor() {
        // Always default to dark mode unless user has explicitly chosen light
        this.currentTheme = localStorage.getItem('theme') || 'dark';
        
        // Force dark mode as default (ignore system preferences)
        if (!localStorage.getItem('theme')) {
            this.currentTheme = 'dark';
        }
        
        this.init();
    }

    init() {
        // Wait for stylesheets to load before applying theme
        this.waitForCSS(() => {
            // Apply initial theme without transition to prevent flash
            this.applyTheme(this.currentTheme, true);
            
            // Create toggle element
            this.createToggleElement();
            
            // Setup event listeners
            this.setupEventListeners();
            
            console.log('Theme system initialized - default: dark, current:', this.currentTheme);
        });
    }

    waitForCSS(callback) {
        if (document.readyState === 'complete') {
            callback();
        } else {
            window.addEventListener('load', callback);
        }
    }

    applyTheme(theme, skipTransition = false) {
        if (skipTransition) {
            // Disable transitions temporarily to prevent flash
            document.documentElement.style.transition = 'none';
        }
        
        // Always apply dark mode first, then light if needed
        if (theme === 'light') {
            document.documentElement.removeAttribute('data-theme');
        } else {
            // Explicitly set dark
            document.documentElement.setAttribute('data-theme', 'dark');
        }
        
        this.currentTheme = theme;
        this.updateToggleState();
        
        if (skipTransition) {
            // Re-enable transitions after a frame
            requestAnimationFrame(() => {
                document.documentElement.style.transition = '';
            });
        }
    }

    createToggleElement() {
        // Check if toggle already exists
        if (document.querySelector('.theme-toggle')) {
            this.toggleElement = document.querySelector('.theme-toggle');
            this.updateToggleState();
            return;
        }

        const toggle = document.createElement('div');
        toggle.className = 'theme-toggle';
        toggle.innerHTML = `
            <span class="toggle-label">${this.currentTheme}</span>
            <div class="toggle-button"></div>
        `;
        
        // Make focusable
        toggle.setAttribute('tabindex', '0');
        toggle.setAttribute('role', 'button');
        toggle.setAttribute('aria-label', 'Toggle between light and dark themes');
        
        document.body.appendChild(toggle);
        this.toggleElement = toggle;
        this.updateToggleState();
    }

    updateToggleState() {
        if (!this.toggleElement) return;
        
        const label = this.toggleElement.querySelector('.toggle-label');
        
        if (label) {
            label.textContent = this.currentTheme;
        }
    }

    setupEventListeners() {
        if (!this.toggleElement) return;

        // Click handler
        this.toggleElement.addEventListener('click', () => {
            this.toggleTheme();
        });

        // Keyboard handler
        this.toggleElement.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                this.toggleTheme();
            }
        });
    }

    toggleTheme() {
        const newTheme = this.currentTheme === 'dark' ? 'light' : 'dark';
        this.applyTheme(newTheme);
        // Only save to localStorage when user manually toggles
        localStorage.setItem('theme', newTheme);
        console.log('User toggled to:', newTheme);
        
        // Dispatch custom event for other components that might need to know
        window.dispatchEvent(new CustomEvent('themeChanged', {
            detail: { theme: newTheme }
        }));
    }

    // Public method to programmatically set theme
    setTheme(theme) {
        if (theme === 'light' || theme === 'dark') {
            this.applyTheme(theme);
            localStorage.setItem('theme', theme);
        }
    }

    // Public method to get current theme
    getTheme() {
        return this.currentTheme;
    }
}