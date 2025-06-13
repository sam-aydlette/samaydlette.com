export class FormHandler {
  constructor() {
    this.form = document.querySelector('.contact-form');
    if (this.form) {
      this.init();
    }
  }

  init() {
    this.form.addEventListener('submit', this.handleSubmit.bind(this));
    this.setupFieldValidation();
  }

  setupFieldValidation() {
    const fields = this.form.querySelectorAll('input, textarea');
    fields.forEach(field => {
      field.addEventListener('blur', () => this.validateField(field));
      field.addEventListener('input', () => this.clearError(field));
    });
  }

  validateField(field) {
    if (field.checkValidity()) {
      this.clearError(field);
    } else {
      this.showError(field);
    }
  }

  showError(field) {
    this.clearError(field);
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-message';
    errorDiv.textContent = field.validationMessage;
    field.parentNode.insertBefore(errorDiv, field.nextSibling);
    field.classList.add('invalid');
  }

  clearError(field) {
    const errorDiv = field.parentNode.querySelector('.error-message');
    if (errorDiv) {
      errorDiv.remove();
      field.classList.remove('invalid');
    }
  }

  async handleSubmit(event) {
    event.preventDefault();
    if (!this.form.checkValidity()) {
      return;
    }

    const submitBtn = this.form.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.textContent = 'Sending...';

    try {
      // Simulate form submission (replace with actual endpoint)
      await new Promise(resolve => setTimeout(resolve, 1000));
      this.showMessage('Message sent successfully!', 'success');
      this.form.reset();
    } catch (error) {
      this.showMessage('Failed to send message. Please try again.', 'error');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Send Message';
    }
  }

  showMessage(text, type) {
    const message = document.createElement('div');
    message.className = `form-message ${type}`;
    message.textContent = text;
    this.form.insertAdjacentElement('beforebegin', message);
    setTimeout(() => message.remove(), 5000);
  }}
