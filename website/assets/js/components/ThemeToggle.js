// ThemeToggle.js - Theme switching component

export class ThemeToggle {
    constructor() {
        this.currentTheme = this.getStoredTheme() || this.getPreferredTheme();
        this.init();
    }

    init() {
        // Apply initial theme
        this.applyTheme(this.currentTheme);
        
        // Create toggle element if it doesn't exist
        this.createToggleElement();
        
        // Setup event listeners
        this.setupEventListeners();
        
        // Listen for system theme changes
        this.watchSystemTheme();
    }

    getStoredTheme() {
        try {
            return localStorage.getItem('theme');
        } catch (e) {
            // localStorage might not be available
            return null;
        }
    }

    getPreferredTheme() {
        // Default to dark theme to match existing site
        if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
            return 'light';
        }
        return 'dark';
    }

    storeTheme(theme) {
        try {
            localStorage.setItem('theme', theme);
        } catch (e) {
            // localStorage might not be available, silently fail
        }
    }

    applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        this.currentTheme = theme;
        this.updateToggleState();
    }

    createToggleElement() {
        // Check if toggle already exists
        if (document.querySelector('.theme-toggle')) {
            return;
        }

        const toggle = document.createElement('div');
        toggle.className = 'theme-toggle';
        toggle.setAttribute('role', 'button');
        toggle.setAttribute('tabindex', '0');
        toggle.setAttribute('aria-label', 'Toggle between light and dark themes');
        
        toggle.innerHTML = `
            <span class="toggle-label">${this.currentTheme}</span>
            <div class="toggle-button"></div>
        `;

        document.body.appendChild(toggle);
        this.toggleElement = toggle;
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
        this.storeTheme(newTheme);
        
        // Dispatch custom event for other components that might need to know
        window.dispatchEvent(new CustomEvent('themeChanged', {
            detail: { theme: newTheme }
        }));
    }

    watchSystemTheme() {
        if (!window.matchMedia) return;

        const mediaQuery = window.matchMedia('(prefers-color-scheme: light)');
        
        // Only auto-switch if user hasn't manually set a preference
        const handleSystemThemeChange = (e) => {
            const storedTheme = this.getStoredTheme();
            if (!storedTheme) {
                // No stored preference, follow system
                const systemTheme = e.matches ? 'light' : 'dark';
                this.applyTheme(systemTheme);
            }
        };

        // Modern browsers
        if (mediaQuery.addEventListener) {
            mediaQuery.addEventListener('change', handleSystemThemeChange);
        } else {
            // Fallback for older browsers
            mediaQuery.addListener(handleSystemThemeChange);
        }
    }

    // Public method to programmatically set theme
    setTheme(theme) {
        if (theme === 'light' || theme === 'dark') {
            this.applyTheme(theme);
            this.storeTheme(theme);
        }
    }

    // Public method to get current theme
    getTheme() {
        return this.currentTheme;
    }
}