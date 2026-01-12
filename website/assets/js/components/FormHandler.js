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
    const originalText = submitBtn.textContent;
    submitBtn.disabled = true;
    submitBtn.textContent = 'sending...';

    const formData = new FormData(this.form);

    /* =============================================================================
       FORM SUBMISSION CONFIGURATION
       =============================================================================
       Choose ONE of the following options for form submission:

       OPTION 1: Formspree (Easiest - Recommended for most users)
       ---------------------------------------------------------
       1. Sign up at https://formspree.io (free for 50 submissions/month)
       2. Create a new form and get your form ID
       3. Replace 'YOUR_FORM_ID' below with your actual form ID
       4. Uncomment the Formspree code block

       OPTION 2: Netlify Forms (If deployed on Netlify)
       -------------------------------------------------
       1. Add these attributes to the form tag in contact.html:
          netlify netlify-honeypot="bot-field"
       2. Add hidden input: <input type="hidden" name="form-name" value="contact" />
       3. Uncomment the Netlify code block

       OPTION 3: Custom Backend (AWS Lambda, API Gateway, etc.)
       ---------------------------------------------------------
       1. Set up your backend endpoint
       2. Replace the fetch URL with your endpoint
       3. Uncomment the Custom Backend code block
       ============================================================================= */

    try {
      // Formspree submission
      const response = await fetch('https://formspree.io/f/xeoqwbdz', {
        method: 'POST',
        body: formData,
        headers: {
          'Accept': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error('Form submission failed');
      }

      // Success handling
      this.showMessage('message_sent_successfully', 'success');
      this.form.reset();

      // Redirect to success page after 2 seconds
      setTimeout(() => {
        window.location.href = '/pages/success.html';
      }, 2000);

    } catch (error) {
      this.showMessage('failed_to_send_please_try_again', 'error');
      console.error('Form submission error:', error);
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = originalText;
    }
  }

  showMessage(text, type) {
    const message = document.createElement('div');
    message.className = `form-message ${type}`;
    message.textContent = text;
    this.form.insertAdjacentElement('beforebegin', message);
    setTimeout(() => message.remove(), 5000);
  }
}
