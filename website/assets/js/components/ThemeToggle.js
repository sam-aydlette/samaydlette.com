// Updated ThemeToggle.js with explicit positioning
export class ThemeToggle {
    constructor() {
        this.currentTheme = this.getStoredTheme() || this.getPreferredTheme();
        this.init();
    }

    init() {
        // Apply initial theme
        this.applyTheme(this.currentTheme);
        
        // Create toggle element
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
            return null;
        }
    }

    getPreferredTheme() {
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
        
        // Use explicit inline styles to ensure positioning works
        const isDark = this.currentTheme === 'dark';
        const bgColor = isDark ? '#252525' : '#ffffff';
        const textColor = isDark ? '#888888' : '#6c757d';
        const borderColor = isDark ? '#404040' : '#dee2e6';
        
        toggle.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
            background: ${bgColor};
            border: 1px solid ${borderColor};
            border-radius: 20px;
            padding: 8px;
            display: flex;
            align-items: center;
            gap: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            cursor: pointer;
            user-select: none;
            transition: all 0.3s ease;
            font-family: 'JetBrains Mono', monospace;
        `;
        
        toggle.setAttribute('role', 'button');
        toggle.setAttribute('tabindex', '0');
        toggle.setAttribute('aria-label', 'Toggle between light and dark themes');
        
        const toggleButton = document.createElement('div');
        toggleButton.className = 'toggle-button';
        toggleButton.style.cssText = `
            width: 40px;
            height: 20px;
            background: ${isDark ? '#555555' : '#007a6b'};
            border-radius: 10px;
            position: relative;
            transition: all 0.3s ease;
        `;
        
        const toggleSlider = document.createElement('div');
        toggleSlider.className = 'toggle-slider';
        toggleSlider.style.cssText = `
            position: absolute;
            width: 16px;
            height: 16px;
            background: ${bgColor};
            border-radius: 50%;
            top: 2px;
            left: ${isDark ? '2px' : '22px'};
            transition: all 0.3s ease;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.2);
        `;
        
        const label = document.createElement('span');
        label.className = 'toggle-label';
        label.textContent = this.currentTheme;
        label.style.cssText = `
            font-size: 0.8rem;
            color: ${textColor};
            min-width: 30px;
            text-align: center;
        `;
        
        toggleButton.appendChild(toggleSlider);
        toggle.appendChild(label);
        toggle.appendChild(toggleButton);
        
        document.body.appendChild(toggle);
        this.toggleElement = toggle;
        
        console.log('Theme toggle created and positioned at top right');
    }

    updateToggleState() {
        if (!this.toggleElement) return;
        
        const isDark = this.currentTheme === 'dark';
        const bgColor = isDark ? '#252525' : '#ffffff';
        const textColor = isDark ? '#888888' : '#6c757d';
        const borderColor = isDark ? '#404040' : '#dee2e6';
        
        // Update toggle background and border
        this.toggleElement.style.background = bgColor;
        this.toggleElement.style.borderColor = borderColor;
        
        // Update label
        const label = this.toggleElement.querySelector('.toggle-label');
        if (label) {
            label.textContent = this.currentTheme;
            label.style.color = textColor;
        }
        
        // Update button
        const button = this.toggleElement.querySelector('.toggle-button');
        if (button) {
            button.style.background = isDark ? '#555555' : '#007a6b';
        }
        
        // Update slider position
        const slider = this.toggleElement.querySelector('.toggle-slider');
        if (slider) {
            slider.style.left = isDark ? '2px' : '22px';
            slider.style.background = bgColor;
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
        
        // Dispatch custom event
        window.dispatchEvent(new CustomEvent('themeChanged', {
            detail: { theme: newTheme }
        }));
        
        console.log('Theme switched to:', newTheme);
    }

    watchSystemTheme() {
        if (!window.matchMedia) return;

        const mediaQuery = window.matchMedia('(prefers-color-scheme: light)');
        
        const handleSystemThemeChange = (e) => {
            const storedTheme = this.getStoredTheme();
            if (!storedTheme) {
                const systemTheme = e.matches ? 'light' : 'dark';
                this.applyTheme(systemTheme);
            }
        };

        if (mediaQuery.addEventListener) {
            mediaQuery.addEventListener('change', handleSystemThemeChange);
        } else {
            mediaQuery.addListener(handleSystemThemeChange);
        }
    }

    // Public methods
    setTheme(theme) {
        if (theme === 'light' || theme === 'dark') {
            this.applyTheme(theme);
            this.storeTheme(theme);
        }
    }

    getTheme() {
        return this.currentTheme;
    }
}