import { Navigation } from './components/Navigation.js';
import { ImageHandler } from './components/ImageHandler.js';
import { FormHandler } from './components/FormHandler.js';
import { MobileMenu } from './components/mobile-menu.js';
import { setupScrollObserver } from './utils/observers.js';

document.addEventListener('DOMContentLoaded', () => {
  new Navigation();
  new ImageHandler();
  new FormHandler();
  new MobileMenu();
  //setupScrollObserver();
});