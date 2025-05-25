const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const customEncrypt = require('../utils/crypto/encrypt');

/**
 * Service for managing Time-based One-Time Password (TOTP) operations
 * with secure handling of secrets and improved debugging
 */
class TOTPService {
  constructor() {
    // Set default time offset to 0 (use actual system time)
    this._timeOffset = 0;
    
    // Load time offset from environment if available
    if (process.env.TOTP_TIME_OFFSET) {
      try {
        this._timeOffset = parseInt(process.env.TOTP_TIME_OFFSET, 10);
        this._debug(`Loaded time offset from environment: ${this._timeOffset} seconds`);
      } catch (error) {
        this._error('Error parsing TOTP_TIME_OFFSET from environment:', error);
      }
    }
    
    
  }

  /**
   * Debug logger with context
   * @private
   */
  _debug(message, data = null) {
    const logMessage = `[TOTP] ${message}`;
    if (data) {
      console.log(logMessage, data);
    } else {
      console.log(logMessage);
    }
  }

  /**
   * Error logger with context
   * @private
   */
  _error(message, error = null) {
    const logMessage = `[TOTP] ERROR: ${message}`;
    if (error) {
      console.error(logMessage, error);
    } else {
      console.error(logMessage);
    }
  }

  /**
   * Validate input is not null or undefined
   * @private
   */
  _validateInput(input, name) {
    if (input === null || input === undefined) {
      const error = new Error(`${name} cannot be null or undefined`);
      this._error(`Invalid input: ${name}`, error);
      throw error;
    }
    return true;
  }

  /**
   * Get current time with any configured offset applied
   * @private
   */
  _getCurrentTime() {
    return new Date(Date.now() + (this._timeOffset * 1000));
  }

  /**
   * Get current Unix timestamp with offset applied
   * @private
   */
  _getCurrentTimestamp() {
    return Math.floor((Date.now() + (this._timeOffset * 1000)) / 1000);
  }

  /**
   * Generate a new TOTP secret for a user
   * @param {string} userEmail - The user's email for labeling in authenticator apps
   * @returns {Object} Object containing secret and QR code data
   */
  async generateSecret(userEmail) {
    this._validateInput(userEmail, 'userEmail');
    this._debug(`Generating new secret for user: ${userEmail}`);
    
    try {
      // Generate a secret using Speakeasy
      const secret = speakeasy.generateSecret({
        name: `CryptographyBackend:${userEmail}`,
        length: 20  // Standard length for TOTP
      });
      
      // Log only a hash of the secret for audit purposes without exposing it
      const secretHash = crypto.createHash('sha256').update(secret.base32).digest('hex').substring(0, 8);
      this._debug(`Secret generated successfully with hash: ${secretHash}...`);
      
      // Make sure we can verify a code with this secret immediately (sanity check)
      const testToken = speakeasy.totp({
        secret: secret.base32,
        encoding: 'base32',
        time: this._getCurrentTimestamp()
      });
      
      this._debug(`Test token generated (verification check)`);
      
      // Encrypt the secret before storing it
      this._debug('Encrypting secret...');
      const encryptedSecret = this.encryptSecret(secret.base32);
      
      // Generate QR code for easy scanning
      const qrCodeUrl = secret.otpauth_url;
      this._debug(`QR code URL generated`);
      const qrCodeImage = await QRCode.toDataURL(qrCodeUrl);
      
      return {
        secret: encryptedSecret,
        qrCode: qrCodeImage
      };
    } catch (error) {
      this._error('Error generating secret:', error);
      throw new Error(`Failed to generate TOTP secret: ${error.message}`);
    }
  }
  
  /**
   * Verify a TOTP token against a user's secret
   * @param {string} token - The token provided by the user
   * @param {string} encryptedSecret - The encrypted secret from the database
   * @returns {boolean} Whether the token is valid
   */
  verifyToken(token, encryptedSecret) {
    this._debug('===== Starting token verification =====');
    this._debug(`Token provided: ${token ? 'Valid format' : 'Invalid'}`);
    
    // Basic validation
    if (!token || typeof token !== 'string') {
      this._error('Invalid token format');
      return false;
    }
    
    if (!encryptedSecret) {
      this._error('No encrypted secret provided');
      return false;
    }
    
    try {
      // Step 1: Decrypt the secret
      this._debug('Decrypting secret...');
      const decryptedSecret = this.decryptSecret(encryptedSecret);
      
      if (!decryptedSecret) {
        this._error('Failed to decrypt secret');
        return false;
      }
      
      const secretHash = crypto.createHash('sha256').update(decryptedSecret).digest('hex').substring(0, 8);
      this._debug(`Secret decrypted successfully with hash: ${secretHash}...`);
      
      // Step 2: Verify the token 

      const verified = speakeasy.totp.verify({
        secret: decryptedSecret,
        encoding: 'base32',
        token: token,
        window: 2, 
        time: this._getCurrentTimestamp()
      });
      
      if (verified) {
        this._debug('✅ Token verified successfully!');
      } else {
        this._debug('❌ Token verification failed');
        
        // For debugging, log info about the expected token
        const currentTimeStep = Math.floor(this._getCurrentTimestamp() / 30);
        this._debug(`Current time step: ${currentTimeStep}`);
      }
      
      return verified;
    } catch (error) {
      this._error('Error verifying token:', error);
      return false;
    }
  }
  
  /**
   * Encrypt a TOTP secret before storing in database
   * @param {string} secret - The secret to encrypt
   * @returns {string} Encrypted secret
   */
  encryptSecret(secret) {
    this._validateInput(secret, 'secret');
    
    try {
      // Use our custom encryption utility
      const encryptionResult = customEncrypt.encrypt(secret);
      
      if (!encryptionResult || !encryptionResult.ciphertext || 
          !encryptionResult.iv || !encryptionResult.key) {
        this._error('Encryption failed - invalid result:', encryptionResult);
        throw new Error('Encryption failed - invalid result');
      }
      
      // Format: ciphertext.iv.key
      const encryptedSecret = `${encryptionResult.ciphertext}.${encryptionResult.iv}.${encryptionResult.key}`;
      
      this._debug('Secret encrypted successfully');
      
      return encryptedSecret;
    } catch (error) {
      this._error('Error encrypting secret:', error);
      throw error;
    }
  }
  
  /**
   * Decrypt a TOTP secret from the database
   * @param {string} encryptedSecret - The encrypted secret
   * @returns {string} Original secret
   */
  decryptSecret(encryptedSecret) {
    this._debug('Decrypting secret...');
    this._validateInput(encryptedSecret, 'encryptedSecret');
    
    if (typeof encryptedSecret !== 'string') {
      const error = new Error(`Encrypted secret must be a string, got ${typeof encryptedSecret}`);
      this._error(error.message);
      throw error;
    }
    
    // Check for correct format (with delimiters)
    if (!encryptedSecret.includes('.')) {
      this._debug('Encrypted secret does not contain delimiters, may be plain text');
      return encryptedSecret;
    }
    
    try {
      // Split the encrypted secret into components
      const parts = encryptedSecret.split('.');
      
      if (parts.length !== 3) {
        const error = new Error(`Invalid encrypted secret format: expected 3 parts, got ${parts.length}`);
        this._error(error.message);
        throw error;
      }
      
      const [ciphertext, iv, key] = parts;
      
      // Decrypt the secret using the components
      const secret = customEncrypt.decrypt(ciphertext, key, iv);
      
      if (!secret) {
        const error = new Error('Decryption failed - empty result');
        this._error(error.message);
        throw error;
      }
      
      this._debug(`Decryption successful, secret length: ${secret.length}`);
      
      return secret;
    } catch (error) {
      this._error('Error decrypting secret:', error);
      throw error;
    }
  }
  
  /**
   * Get detailed time and TOTP information for debugging
   */
  getTimeInfo() {
    const systemTime = new Date();
    const correctedTime = this._getCurrentTime();
    
    // Calculate time zone information
    const offsetMinutes = systemTime.getTimezoneOffset();
    
    // Get Morocco time accurately with DST consideration
    const moroccoInfo = this._getMoroccoTimeInfo();
    
    // Generate sample tokens
    const sampleTokens = this._generateSampleTokens();
    
    return {
      systemTime: systemTime.toISOString(),
      correctedTime: correctedTime.toISOString(),
      timeOffset: this._timeOffset,
      systemTimeStep: Math.floor(Date.now() / 30000),
      correctedTimeStep: Math.floor((Date.now() + (this._timeOffset * 1000)) / 30000),
      systemTimezone: `UTC${offsetMinutes <= 0 ? '+' : '-'}${Math.abs(offsetMinutes / 60)}`,
      morocco: moroccoInfo,
      sampleTokens: sampleTokens
    };
  }

  /**
   * Get accurate Morocco time information including DST status
   * @private
   */
  _getMoroccoTimeInfo() {
    // Get current date
    const now = new Date();
    
    // More accurate DST detection for Morocco
    // Morocco typically changes to summer time on last Sunday of March
    // and back to standard time on last Sunday of October
    const year = now.getFullYear();
    
    // Find last Sunday in March
    const marchStart = new Date(year, 2, 31); // Start with March 31
    while (marchStart.getDay() !== 0) { // 0 = Sunday
      marchStart.setDate(marchStart.getDate() - 1);
    }
    
    // Find last Sunday in October
    const octoberStart = new Date(year, 9, 31); // Start with October 31
    while (octoberStart.getDay() !== 0) { // 0 = Sunday
      octoberStart.setDate(octoberStart.getDate() - 1);
    }
    
    // Check if current date is in DST range
    const isMoroccoSummerTime = now >= marchStart && now < octoberStart;
    const moroccoOffsetHours = isMoroccoSummerTime ? 1 : 0;
    
    return {
      timezoneName: `Morocco (UTC+${moroccoOffsetHours})`,
      isDST: isMoroccoSummerTime,
      dstStartDate: marchStart.toISOString(),
      dstEndDate: octoberStart.toISOString()
    };
  }
  
  /**
   * Generate sample tokens for debugging
   * @private
   */
  _generateSampleTokens() {
    // Use a standard test secret (public test secret for demo purposes only)
    const testSecret = 'JBSWY3DPEHPK3PXP';
    const tokens = [];
    
    // Generate tokens for different time offsets
    const now = this._getCurrentTimestamp();
    
    for (let i = -2; i <= 2; i++) {
      const timeOffset = i * 30;
      const timestamp = now + timeOffset;
      
      const token = speakeasy.totp({
        secret: testSecret,
        encoding: 'base32',
        time: timestamp
      });
      
      tokens.push({
        offset: timeOffset,
        time: new Date(timestamp * 1000).toISOString(),
        token: token
      });
    }
    
    return {
      testSecret: testSecret,
      tokens: tokens
    };
  }
  
  /**
   * Generate backup codes for account recovery
   * @param {number} count - Number of backup codes to generate
   * @param {number} length - Length of each backup code
   * @returns {Object} Object with plaintext and hashed backup codes
   */
  generateBackupCodes(count = 8, length = 10) {
    this._debug(`Generating ${count} backup codes...`);
    
    // Input validation
    if (typeof count !== 'number' || count < 1 || count > 20) {
      const error = new Error('Invalid backup code count (must be between 1-20)');
      this._error(error.message);
      throw error;
    }
    
    if (typeof length !== 'number' || length < 6 || length > 20) {
      const error = new Error('Invalid backup code length (must be between 6-20)');
      this._error(error.message);
      throw error;
    }
    
    const backupCodes = [];
    const hashedCodes = [];
    
    try {
      for (let i = 0; i < count; i++) {
        // Generate random code with sufficient entropy
        const code = crypto.randomBytes(Math.ceil(length * 0.75))
          .toString('hex')
          .substring(0, length)
          .toUpperCase();
        
        // Format for readability (e.g., XXXX-XXXX-XX)
        const formattedCode = this._formatBackupCode(code);
        
        // Hash for storage
        const hashResult = customEncrypt.hashBackupCode(formattedCode);
        
        backupCodes.push(formattedCode);
        hashedCodes.push(hashResult);
      }
      
      this._debug(`Generated ${backupCodes.length} backup codes successfully`);
      
      return {
        plainCodes: backupCodes, // Only shown to user once
        hashedCodes: hashedCodes  // Stored in database
      };
    } catch (error) {
      this._error('Error generating backup codes:', error);
      throw new Error(`Failed to generate backup codes: ${error.message}`);
    }
  }
  
  /**
   * Format a backup code with dashes for readability
   * @private
   * @param {string} code - Raw backup code
   * @returns {string} Formatted backup code
   */
  _formatBackupCode(code) {
    if (!code || code.length < 4) {
      return code; // Can't format if too short
    }
    
    // Format with dashes every 4 characters
    return code.replace(/(.{4})/g, '$1-').replace(/-$/, '');
  }
  
  /**
   * Verify a backup code
   * @param {string} providedCode - The code provided by the user
   * @param {Array} hashedCodes - Array of hashed backup codes
   * @returns {Object} Object with verification result and index
   */
  verifyBackupCode(providedCode, hashedCodes) {
    this._debug('Verifying backup code...');
    
    if (!providedCode) {
      this._error('No backup code provided');
      return { valid: false, index: -1 };
    }
    
    if (!hashedCodes || !Array.isArray(hashedCodes) || hashedCodes.length === 0) {
      this._error('No valid backup codes available for verification');
      return { valid: false, index: -1 };
    }
    
    try {
      // Normalize code format by removing non-alphanumeric characters and converting to uppercase
      const normalizedCode = providedCode.toUpperCase().replace(/[^A-Z0-9]/g, '');
      
      // Format normalized code for verification
      const formattedCode = this._formatBackupCode(normalizedCode);
      
      if (normalizedCode.length < 6) {
        this._error('Backup code too short');
        return { valid: false, index: -1, error: 'Code too short' };
      }
      
      this._debug('Formatted backup code for verification');
      
      // Check against all stored hashed codes
      for (let i = 0; i < hashedCodes.length; i++) {
        if (!hashedCodes[i]) {
          this._debug(`Invalid backup code hash at index ${i}`);
          continue;
        }
        
        const isValid = customEncrypt.verifyBackupCode(formattedCode, hashedCodes[i]);
        
        if (isValid) {
          this._debug(`✅ Backup code verified successfully at index ${i}`);
          return { valid: true, index: i };
        }
      }
      
      this._debug('❌ No matching backup code found');
      return { valid: false, index: -1 };
    } catch (error) {
      this._error('Error verifying backup code:', error);
      return { valid: false, index: -1, error: error.message };
    }
  }
  
  /**
   * Set a new time offset (for debugging/testing)
   * @param {number} offsetSeconds - New time offset in seconds
   */
  setTimeOffset(offsetSeconds) {
    if (typeof offsetSeconds !== 'number') {
      const error = new Error('Time offset must be a number');
      this._error(error.message);
      throw error;
    }
    
    this._debug(`Changing time offset from ${this._timeOffset} to ${offsetSeconds} seconds`);
    this._timeOffset = offsetSeconds;
    
    // Show the impact of this change
    const before = new Date();
    const after = this._getCurrentTime();
    this._debug(`System time: ${before.toISOString()}`);
    this._debug(`Adjusted time: ${after.toISOString()}`);
    
    return {
      success: true,
      message: `Time offset updated to ${offsetSeconds} seconds`,
      systemTime: before.toISOString(),
      adjustedTime: after.toISOString()
    };
  }
}

// Export a singleton instance
module.exports = new TOTPService();