// Theme toggle that always defaults to dark mode
document.addEventListener('DOMContentLoaded', function() {
    // Always default to dark mode unless user has explicitly chosen light
    let currentTheme = localStorage.getItem('theme') || 'dark';
    
    // Force dark mode as default (ignore system preferences)
    if (!localStorage.getItem('theme')) {
        currentTheme = 'dark';
    }
    
    // Wait for stylesheets to load before applying theme
    function waitForCSS(callback) {
        if (document.readyState === 'complete') {
            callback();
        } else {
            window.addEventListener('load', callback);
        }
    }
    
    // Apply theme function
    function applyTheme(theme, skipTransition = false) {
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
        
        currentTheme = theme;
        updateToggle();
        
        if (skipTransition) {
            // Re-enable transitions after a frame
            requestAnimationFrame(() => {
                document.documentElement.style.transition = '';
            });
        }
    }
    
    // Create toggle with explicit positioning
    const toggle = document.createElement('div');
    toggle.innerHTML = `
        <span class="label">${currentTheme}</span>
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
        background: currentTheme === 'dark' ? '#252525' : '#ffffff',
        border: '1px solid ' + (currentTheme === 'dark' ? '#404040' : '#dee2e6'),
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
    
    const label = toggle.querySelector('.label');
    const button = toggle.querySelector('.button');
    const slider = toggle.querySelector('.slider');
    
    Object.assign(button.style, {
        width: '40px',
        height: '20px',
        background: currentTheme === 'dark' ? '#555555' : '#007a6b',
        borderRadius: '10px',
        position: 'relative',
        transition: 'all 0.3s ease'
    });
    
    Object.assign(slider.style, {
        position: 'absolute',
        width: '16px',
        height: '16px',
        background: currentTheme === 'dark' ? '#252525' : '#ffffff',
        borderRadius: '50%',
        top: '2px',
        left: currentTheme === 'dark' ? '2px' : '22px',
        transition: 'left 0.3s ease',
        boxShadow: '0 1px 3px rgba(0, 0, 0, 0.2)'
    });
    
    // Update toggle appearance
    function updateToggle() {
        const isDark = currentTheme === 'dark';
        label.textContent = currentTheme;
        label.style.color = isDark ? '#888888' : '#6c757d';
        toggle.style.background = isDark ? '#252525' : '#ffffff';
        toggle.style.borderColor = isDark ? '#404040' : '#dee2e6';
        button.style.background = isDark ? '#555555' : '#007a6b';
        slider.style.background = isDark ? '#252525' : '#ffffff';
        slider.style.left = isDark ? '2px' : '22px';
    }
    
    // Toggle function
    toggle.onclick = function() {
        currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
        applyTheme(currentTheme);
        // Only save to localStorage when user manually toggles
        localStorage.setItem('theme', currentTheme);
        console.log('User toggled to:', currentTheme);
    };
    
    // Add keyboard support
    toggle.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            toggle.click();
        }
    });
    
    // Make focusable
    toggle.setAttribute('tabindex', '0');
    toggle.setAttribute('role', 'button');
    toggle.setAttribute('aria-label', 'Toggle between light and dark themes');
    
    // Initialize after CSS is loaded
    waitForCSS(() => {
        // Apply initial theme without transition to prevent flash
        applyTheme(currentTheme, true);
        document.body.appendChild(toggle);
        console.log('Theme system initialized - default: dark, current:', currentTheme);
    });
});