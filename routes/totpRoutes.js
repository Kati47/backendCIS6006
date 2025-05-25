const express = require('express');
const router = express.Router();
const totpController = require('../controllers/totpController');

/**
 * TOTP (Time-based One-Time Password) Routes
 * These routes handle multi-factor authentication functionality
 */

// Setup TOTP (generates secret and QR code)
router.post('/setup',totpController.setupTOTP);

// Verify TOTP during setup process
router.post('/verify', totpController.verifyTOTP);

// Enable TOTP after verification
router.post('/enable',totpController.enableTOTP);

// Verify TOTP during login (doesn't require authentication)
router.post('/verify-login', totpController.verifyLoginTOTP);

// Disable TOTP
router.post('/disable', totpController.disableTOTP);

// Regenerate backup codes
router.post('/backup-codes', totpController.regenerateBackupCodes);

module.exports = router;