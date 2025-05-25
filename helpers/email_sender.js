const nodemailer = require('nodemailer');

/**
 * Email sender functions for your application
 */

/**
 * Create a nodemailer transporter
 * 
 * @returns {object} configured nodemailer transporter
 */
const createTransporter = () => {
  // For Gmail:
  return nodemailer.createTransport({
    service: 'gmail',
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
      user: process.env.EMAIL_USER, 
      pass: process.env.EMAIL_PASS,
    },
    tls: {
      rejectUnauthorized: false // Fix for self-signed certificate error
    }
  });
};

/**
 * Create a consistent email template
 * @param {string} title Email title/heading
 * @param {string} content Main email content (HTML)
 * @param {object} options Template customization options
 * @returns {string} Complete HTML email template
 */
const createEmailTemplate = (title, content, options = {}) => {
  const {
    headerBgColor = '#f8f9fa',
    headerTextColor = '#5c6ac4',
    contentBgColor = '#ffffff',
    footerBgColor = '#f8f9fa',
    footerTextColor = '#666666',
    storeName = 'Your Store Name',
    storeLogo = '', // Optional logo URL
    year = new Date().getFullYear(),
    additionalFooterText = ''
  } = options;
  
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${title}</title>
    </head>
    <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; color: #333333; background-color: #f4f4f4;">
      <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,0.1);">
        <!-- Header Section -->
        <div style="background-color: ${headerBgColor}; padding: 20px; text-align: center;">
          ${storeLogo ? `<img src="${storeLogo}" alt="${storeName}" style="max-height: 60px; margin-bottom: 10px;">` : ''}
          <h1 style="color: ${headerTextColor}; margin: 0; font-size: 24px;">${title}</h1>
        </div>
        
        <!-- Content Section -->
        <div style="background-color: ${contentBgColor}; padding: 20px;">
          ${content}
        </div>
        
        <!-- Footer Section -->
        <div style="background-color: ${footerBgColor}; padding: 20px; text-align: center; font-size: 12px; color: ${footerTextColor};">
          <p>&copy; ${year} ${storeName}. All rights reserved.</p>
          ${additionalFooterText ? `<p>${additionalFooterText}</p>` : ''}
        </div>
      </div>
    </body>
    </html>
  `;
};

/**
 * Send an email with the standard template
 * 
 * @param {string} to - Recipient's email address
 * @param {string} subject - Email subject
 * @param {string} title - Email title/heading
 * @param {string} content - Email content (HTML)
 * @param {object} templateOptions - Template customization options
 * @returns {Promise<string>} Result message
 */
exports.sendTemplatedEmail = async (to, subject, title, content, templateOptions = {}) => {
  try {
    // Apply the template to the content
    const htmlMessage = createEmailTemplate(title, content, templateOptions);
    
    // Send the email with the templated content
    return await exports.sendMail(to, subject, htmlMessage);
  } catch (error) {
    console.error('Error sending templated email:', error);
    return `Failed to send email: ${error.message}`;
  }
};

/**
 * Send an email (low-level function, prefer using sendTemplatedEmail)
 * 
 * @param {string} to - Recipient's email address
 * @param {string} subject - Email subject
 * @param {string} htmlMessage - Email body in HTML format
 * @returns {Promise<string>} Result message
 */
exports.sendMail = async (to, subject, htmlMessage) => {
  try {
    console.log('Creating email transporter...');
    const transporter = createTransporter();
    
    console.log('Setting up email options...');
    const mailOptions = {
      from: 'khadijahouda70@gmail.com',
      to: to,
      subject: subject,
      html: htmlMessage
    };

    console.log('Sending email...');
    const info = await transporter.sendMail(mailOptions);
    
    console.log('Email sent successfully:', info.response);
    return 'Email sent successfully';
  } catch (error) {
    console.error('Error sending email:', error);
    return `Failed to send email: ${error.message}`;
  }
};

/**
 * Send a contact form email
 * 
 * @param {object} contactData - Contact form data
 * @returns {Promise<string>} Result message
 */
exports.sendContactEmail = async (contactData) => {
  const { fName, lName, phone, email, message } = contactData;

  // Input validation
  if (!fName || !lName || !phone || !email || !message) {
    throw new Error('All contact form fields are required');
  }

  try {
    // Create content for contact form submission
    const content = `
      <p><strong>First Name:</strong> ${fName}</p>
      <p><strong>Last Name:</strong> ${lName}</p>
      <p><strong>Phone:</strong> ${phone}</p>
      <p><strong>Email:</strong> ${email}</p>
      <div style="margin-top: 15px; padding: 15px; background-color: #f9f9f9; border-radius: 4px;">
        <p><strong>Message:</strong></p>
        <p style="white-space: pre-line;">${message}</p>
      </div>
    `;
    
    return exports.sendTemplatedEmail(
      'your-recipient-email@example.com', // Change this to your actual recipient
      'New Contact Form Submission',
      'New Contact Form Submission', 
      content,
      { headerTextColor: '#333333' }
    );
  } catch (error) {
    console.error('Error sending contact email:', error);
    throw new Error('Error sending contact form');
  }
};

/**
 * Send a password reset OTP
 * 
 * @param {string} to - User's email
 * @param {string} otp - One-time password
 * @returns {Promise<string>} Result message
 */
exports.sendPasswordResetOTP = async (to, otp) => {
  // Create content for password reset
  const content = `
    <div style="text-align: center; padding: 20px; background-color: #f9f9f9; border-radius: 8px; margin-bottom: 20px;">
      <p style="font-size: 16px; margin-bottom: 15px;">You requested a password reset for your account.</p>
      <div style="background-color: #ffffff; display: inline-block; padding: 12px 24px; border-radius: 4px; border: 1px solid #ddd; margin: 10px 0;">
        <span style="font-size: 24px; font-weight: bold; letter-spacing: 2px; color: #d9534f;">${otp}</span>
      </div>
      <p style="font-size: 14px; color: #666; margin-top: 15px;">This code will expire in 10 minutes</p>
    </div>
    
    <p>If you didn't request this reset, please ignore this email or contact our support team if you believe this is suspicious activity.</p>
    
    <div style="margin-top: 25px; padding-top: 15px; border-top: 1px solid #eee;">
      <p style="font-size: 12px; color: #777;">For security reasons, never share this code with anyone.</p>
    </div>
  `;
  
  return exports.sendTemplatedEmail(
    to,
    'Password Reset OTP',
    'Password Reset Request',
    content,
    { 
      headerBgColor: '#d9534f',  // Red background
      headerTextColor: '#ffffff', // White text
      additionalFooterText: 'If you did not request this password reset, please disregard this email.'
    }
  );
};




/**
 * Mock email sender for development
 */
exports.mockSendMail = async (to, subject, htmlMessage) => {
  console.log('========== MOCK EMAIL ==========');
  console.log('To:', to);
  console.log('Subject:', subject);
  console.log('HTML Message:', htmlMessage);
  console.log('================================');
  
  return 'Mock email logged (not actually sent)';
};