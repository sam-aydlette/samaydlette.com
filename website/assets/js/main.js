import { Navigation } from './components/Navigation.js';
import { ImageHandler } from './components/ImageHandler.js';
import { FormHandler } from './components/FormHandler.js';
import { MobileMenu } from './components/mobile-menu.js';
import { ThemeToggle } from './components/ThemeToggle.js';
import { setupScrollObserver } from './utils/observers.js';

document.addEventListener('DOMContentLoaded', () => {
  new Navigation();
  new ImageHandler();
  new FormHandler();
  new MobileMenu();
  new ThemeToggle();
  setupScrollObserver();
});