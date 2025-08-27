// Updated ThemeToggle.js - Light Mode Default, No Flash
export class ThemeToggle {
    constructor() {
        // Default to light mode unless user has explicitly chosen dark
        this.currentTheme = localStorage.getItem('theme') || 'dark';
                
        // Apply theme IMMEDIATELY to prevent flash
        this.applyThemeImmediate(this.currentTheme);
        
        this.init();
    }

    applyThemeImmediate(theme) {
        // Apply theme synchronously without waiting for CSS load
        if (theme === 'dark') {
            document.documentElement.setAttribute('data-theme', 'dark');
        } else {
            document.documentElement.removeAttribute('data-theme');
        }
        this.currentTheme = theme;
    }

    init() {
        // Wait for DOM to be ready for UI elements
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
                this.createToggleElement();
                this.setupEventListeners();
            });
        } else {
            this.createToggleElement();
            this.setupEventListeners();
        }
        
        console.log('Theme system initialized - default: dark, current:', this.currentTheme);
    }

    applyTheme(theme, skipTransition = false) {
        if (skipTransition) {
            // Disable transitions temporarily to prevent flash
            document.documentElement.style.transition = 'none';
        }
        
        // Apply theme
        if (theme === 'dark') {
            document.documentElement.setAttribute('data-theme', 'dark');
        } else {
            document.documentElement.removeAttribute('data-theme');
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
        const newTheme = this.currentTheme === 'light' ? 'dark' : 'light';
        this.applyTheme(newTheme);
        // Save user preference
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