const { User } = require('../models/user');
const { MFA } = require('../models/mfa');
const { BackupCode } = require('../models/backupCode');
const totpService = require('../services/totpService');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

/**
 * Controller for handling TOTP-based multi-factor authentication
 */
exports.setupTOTP = async (req, res) => {
  try {
    const {userId} = req.body;
    
    // Find user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Check if MFA is already setup
    const existingMfa = await MFA.findOne({ userId: user._id });
    if (existingMfa && existingMfa.enabled) {
      return res.status(400).json({ message: 'MFA is already enabled for this account' });
    }
    
    // Generate a new secret
    const result = await totpService.generateSecret(user.email);
    
    // Create or update MFA record
    if (existingMfa) {
      existingMfa.secret = result.secret;
      existingMfa.enabled = false;
      existingMfa.verifiedAt = null;
      await existingMfa.save();
    } else {
      // Create new MFA record
      await MFA.create({
        userId: user._id,
        secret: result.secret,
        enabled: false,
        method: 'totp'
      });
    }
    
    // Return the QR code to the client
    return res.status(200).json({
      qrCode: result.qrCode
    });
  } catch (error) {
    console.error('Error setting up TOTP:', error);
    return res.status(500).json({ message: error.message });
  }
};

/**
 * Verify a TOTP code during setup to confirm it's working
 */
exports.verifyTOTP = async (req, res) => {
  try {
    const {userId} = req.body;
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({ message: 'Verification code is required' });
    }
    
    // Find user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Find MFA record
    const mfa = await MFA.findOne({ userId: user._id });
    if (!mfa || !mfa.secret) {
      return res.status(400).json({ message: 'TOTP setup not initiated' });
    }
    
    // Verify the token
    const isValid = totpService.verifyToken(token, mfa.secret);
    
    if (!isValid) {
      return res.status(400).json({ message: 'Invalid verification code' });
    }
    
    return res.status(200).json({ 
      valid: true,
      message: 'Verification successful'
    });
  } catch (error) {
    console.error('Error verifying TOTP:', error);
    return res.status(500).json({ message: error.message });
  }
};

/**
 * Enable TOTP for a user after successful verification
 */
exports.enableTOTP = async (req, res) => {
  try {
    const {userId} = req.body;
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({ message: 'Verification code is required' });
    }
    
    // Find user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Find MFA record
    const mfa = await MFA.findOne({ userId: user._id });
    if (!mfa || !mfa.secret) {
      return res.status(400).json({ message: 'TOTP setup not initiated' });
    }
    
    // Verify the token again
    const isValid = totpService.verifyToken(token, mfa.secret);
    
    if (!isValid) {
      return res.status(400).json({ message: 'Invalid verification code' });
    }
    
    // Generate backup codes
    const backupCodesResult = totpService.generateBackupCodes();
    
    // Save backup codes to database
    const backupCodes = backupCodesResult.hashedCodes.map(code => ({
      userId: user._id,
      code: code,
      used: false
    }));
    
    // Create backup codes in database
    await BackupCode.create(backupCodes);
    
    // Update MFA record
    mfa.enabled = true;
    mfa.verifiedAt = new Date();
    await mfa.save();
    
    // Update user
    user.mfaEnabled = true;
    await user.save();
    
    return res.status(200).json({
      success: true,
      message: 'MFA enabled successfully',
      backupCodes: backupCodesResult.plainCodes // Show only once
    });
  } catch (error) {
    console.error('Error enabling TOTP:', error);
    return res.status(500).json({ message: error.message });
  }
};

/**
 * Verify TOTP during login
 */
exports.verifyLoginTOTP = async (req, res) => {
  try {
    const { email, token, backupCode } = req.body;
    
    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }
    
    if (!token && !backupCode) {
      return res.status(400).json({ message: 'Verification code or backup code is required' });
    }
    
    // Find user
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    
    // Check if MFA is enabled
    if (!user.mfaEnabled) {
      return res.status(400).json({ message: 'MFA is not enabled for this user' });
    }
    
    // Find MFA record
    const mfa = await MFA.findOne({ userId: user._id, enabled: true });
    if (!mfa) {
      return res.status(400).json({ message: 'MFA configuration not found' });
    }
    
    let isValid = false;
    
    if (backupCode) {
      // Find unused backup codes
      const backupCodes = await BackupCode.find({ 
        userId: user._id,
        used: false
      });
      
      // Verify backup code
      const backupResult = totpService.verifyBackupCode(backupCode, backupCodes.map(bc => bc.code));
      isValid = backupResult.valid;
      
      // If valid, mark the backup code as used
      if (isValid && backupResult.index >= 0 && backupResult.index < backupCodes.length) {
        const usedCode = backupCodes[backupResult.index];
        usedCode.used = true;
        usedCode.usedAt = new Date();
        await usedCode.save();
      }
    } else {
      // Verify TOTP token
      isValid = totpService.verifyToken(token, mfa.secret);
      
      // Update last used timestamp
      if (isValid) {
        mfa.lastUsedAt = new Date();
        await mfa.save();
      }
    }
    
    if (!isValid) {
      return res.status(400).json({ message: 'Invalid verification code' });
    }
    
    // Generate authentication token
    const authToken = generateAuthToken(user);
    
    return res.status(200).json({
      token: authToken,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    console.error('Error verifying login TOTP:', error);
    return res.status(500).json({ message: error.message });
  }
};

/**
 * Generate authentication token for user
 * @private
 */
function generateAuthToken(user) {
  
  return "generated-auth-token";
}

/**
 * Disable TOTP for a user
 */
exports.disableTOTP = async (req, res) => {
  try {
    const {userId} = req.body;
    const { password } = req.body;
    
    if (!password) {
      return res.status(400).json({ message: 'Password is required to disable MFA' });
    }
    
    // Find user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Verify password
    const passwordValid = await verifyPassword(password, user.passwordHash, user.passwordSalt);
    if (!passwordValid) {
      return res.status(400).json({ message: 'Invalid password' });
    }
    
    // Find and update MFA record
    await MFA.updateOne(
      { userId: user._id },
      { $set: { enabled: false } }
    );
    
    // Delete all backup codes
    await BackupCode.deleteMany({ userId: user._id });
    
    // Update user
    user.mfaEnabled = false;
    await user.save();
    
    return res.status(200).json({
      success: true,
      message: 'MFA disabled successfully'
    });
  } catch (error) {
    console.error('Error disabling TOTP:', error);
    return res.status(500).json({ message: error.message });
  }
};

/**
 * Generate new backup codes
 */
exports.regenerateBackupCodes = async (req, res) => {
  try {
    const {userId} = req.body;
    const { password } = req.body;
    
    if (!password) {
      return res.status(400).json({ message: 'Password is required to regenerate backup codes' });
    }
    
    // Find user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Verify password
    const passwordValid = await verifyPassword(password, user.passwordHash, user.passwordSalt);
    if (!passwordValid) {
      return res.status(400).json({ message: 'Invalid password' });
    }
    
    // Check if MFA is enabled
    if (!user.mfaEnabled) {
      return res.status(400).json({ message: 'MFA is not enabled for this user' });
    }
    
    // Generate new backup codes
    const backupCodesResult = totpService.generateBackupCodes();
    
    // Delete existing backup codes
    await BackupCode.deleteMany({ userId: user._id });
    
    // Save new backup codes
    const backupCodes = backupCodesResult.hashedCodes.map(code => ({
      userId: user._id,
      code: code,
      used: false
    }));
    
    // Create backup codes in database
    await BackupCode.create(backupCodes);
    
    return res.status(200).json({
      success: true,
      message: 'Backup codes regenerated successfully',
      backupCodes: backupCodesResult.plainCodes // Show only once
    });
  } catch (error) {
    console.error('Error regenerating backup codes:', error);
    return res.status(500).json({ message: error.message });
  }
};

/**
 * Verify a password against stored hash and salt
 * @private
 */
async function verifyPassword(password, hash, salt) {
  try {
    // Import the custom hash utility
    const customHash = require('../utils/crypto/hash');
    
    // Verify the password using the provided hash and salt
    const isValid = customHash.verifyPassword(password, hash, salt);
    
    return isValid;
  } catch (error) {
    console.error('Password verification error:', error);
    // Return false on any error to prevent security bypasses
    return false;
  }
}