const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const authController = require('../controllers/authController');

/**
 * Authentication Routes
 */

// User registration
router.post('/register', [
  body('name').trim().notEmpty().withMessage('Name is required'),
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
], authController.register);

// User login
router.post('/login', [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').notEmpty().withMessage('Password is required')
], authController.login);

// Refresh token
router.post('/refresh-token', authController.refreshToken);

// Logout
router.post('/logout', authController.logout);

// Check auth status
router.get('/status', authController.checkAuthStatus);

// Verify token
router.get('/verify-token',  authController.verifyToken);

// Forgot password - initiates the email reset flow
router.post('/forgot-password', [
  body('email').isEmail().withMessage('Please provide a valid email')
], authController.forgotPassword);

// Verify password reset token - validates the token from the email link
router.post('/verify-reset-token', [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('token').notEmpty().withMessage('Reset token is required')
], authController.verifyPasswordResetToken);

// Reset password - sets the new password after token verification
router.post('/reset-password', [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('newPassword').isLength({ min: 8 }).withMessage('New password must be at least 8 characters long'),
], authController.resetPassword);

module.exports = router;