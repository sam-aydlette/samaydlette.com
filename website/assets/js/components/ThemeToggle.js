export class ThemeToggle {
  constructor() {
    this.toggleButton = document.querySelector('.theme-toggle');
    this.currentTheme = this.getTheme();
    this.init();
  }

  init() {
    // Set initial theme
    this.applyTheme(this.currentTheme);

    // Listen for toggle clicks
    if (this.toggleButton) {
      this.toggleButton.addEventListener('click', () => this.toggle());
      console.log('Theme toggle initialized:', this.currentTheme);
    } else {
      console.warn('Theme toggle button not found');
    }
  }

  getTheme() {
    // Check localStorage first
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
      return savedTheme;
    }

    // Check system preference
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      return 'dark';
    }

    return 'light';
  }

  applyTheme(theme) {
    console.log('Applying theme:', theme);

    // Apply theme to document
    if (theme === 'dark') {
      document.documentElement.setAttribute('data-theme', 'dark');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }

    // Update button text
    if (this.toggleButton) {
      const textSpan = this.toggleButton.querySelector('.theme-toggle-text');
      if (textSpan) {
        textSpan.textContent = theme === 'dark' ? 'light' : 'dark';
      }
    }

    // Save to localStorage
    localStorage.setItem('theme', theme);
    this.currentTheme = theme;
  }

  toggle() {
    const newTheme = this.currentTheme === 'light' ? 'dark' : 'light';
    console.log('Toggling theme from', this.currentTheme, 'to', newTheme);
    this.applyTheme(newTheme);
  }
}
