// Theme toggle that always defaults to dark mode
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
            document.documentElement.setAttribute('data-theme', 'light');
        } else {
            // Remove the attribute to use default dark styles
            document.documentElement.removeAttribute('data-theme');
            // Or explicitly set dark
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
            return;
        }

        const toggle = document.createElement('div');
        toggle.className = 'theme-toggle';
        toggle.innerHTML = `
            <span class="label">${this.currentTheme}</span>
            <div class="button">
                <div class="slider"></div>
            </div>
        `;
        
        // Apply styles directly
        Object.assign(toggle.style, {
            position: 'fixed',
            top: '20px',
            right: '20px',
            zIndex: '9999',
            background: this.currentTheme === 'dark' ? '#252525' : '#ffffff',
            border: '1px solid ' + (this.currentTheme === 'dark' ? '#404040' : '#dee2e6'),
            borderRadius: '20px',
            padding: '8px',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            cursor: 'pointer',
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: '12px',
            transition: 'all 0.3s ease'
        });
        
        const button = toggle.querySelector('.button');
        const slider = toggle.querySelector('.slider');
        
        Object.assign(button.style, {
            width: '40px',
            height: '20px',
            background: this.currentTheme === 'dark' ? '#555555' : '#007a6b',
            borderRadius: '10px',
            position: 'relative',
            transition: 'all 0.3s ease'
        });
        
        Object.assign(slider.style, {
            position: 'absolute',
            width: '16px',
            height: '16px',
            background: this.currentTheme === 'dark' ? '#252525' : '#ffffff',
            borderRadius: '50%',
            top: '2px',
            left: this.currentTheme === 'dark' ? '2px' : '22px',
            transition: 'left 0.3s ease',
            boxShadow: '0 1px 3px rgba(0, 0, 0, 0.2)'
        });
        
        // Make focusable
        toggle.setAttribute('tabindex', '0');
        toggle.setAttribute('role', 'button');
        toggle.setAttribute('aria-label', 'Toggle between light and dark themes');
        
        document.body.appendChild(toggle);
        this.toggleElement = toggle;
    }

    updateToggleState() {
        if (!this.toggleElement) return;
        
        const isDark = this.currentTheme === 'dark';
        const label = this.toggleElement.querySelector('.label');
        const button = this.toggleElement.querySelector('.button');
        const slider = this.toggleElement.querySelector('.slider');
        
        if (label) {
            label.textContent = this.currentTheme;
            label.style.color = isDark ? '#888888' : '#6c757d';
        }
        
        this.toggleElement.style.background = isDark ? '#252525' : '#ffffff';
        this.toggleElement.style.borderColor = isDark ? '#404040' : '#dee2e6';
        
        if (button) {
            button.style.background = isDark ? '#555555' : '#007a6b';
        }
        
        if (slider) {
            slider.style.background = isDark ? '#252525' : '#ffffff';
            slider.style.left = isDark ? '2px' : '22px';
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