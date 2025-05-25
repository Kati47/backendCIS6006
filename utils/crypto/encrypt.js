/**
 * Standard AES encryption implementation using Node.js crypto module
 * 
 * This is AES implementation 
 * utilizing Node.js's crypto library which implements the industry-standard
 * AES algorithm (FIPS 197) with secure modes of operation.
 */
const crypto = require('crypto');

/**
 * Generate a cryptographically secure random key of specified length
 * Uses Node.js's crypto.randomBytes which is suitable for cryptographic use
 * 
 * @param {number} length - Length of key in bytes (32 for AES-256)
 * @returns {Buffer} - Secure random key
 */
function generateKey(length = 32) {
  // Using crypto.randomBytes ensures cryptographically strong random values
  // unlike Math.random() which is not suitable for cryptographic purposes
  return crypto.randomBytes(length);
}

/**
 * Generate a cryptographically secure random initialization vector
 * AES block size is always 16 bytes (128 bits) regardless of key size
 * 
 * @param {number} length - Length of IV in bytes (16 for AES)
 * @returns {Buffer} - Secure random IV
 */
function generateIV(length = 16) {
  return crypto.randomBytes(length);
}

/**
 * Convert string to Buffer
 * @param {string} str - String to convert
 * @returns {Buffer} - Byte array
 */
function stringToBytes(str) {
  return Buffer.from(str, 'utf8');
}

/**
 * Convert Buffer to hex string
 * @param {Buffer|Uint8Array} bytes - Byte array
 * @returns {string} - Hex string
 */
function bytesToHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

/**
 * Convert hex string to Buffer
 * @param {string} hex - Hex string
 * @returns {Buffer} - Byte array
 */
function hexToBytes(hex) {
  // Validate input
  if (!hex || typeof hex !== 'string') {
    console.error('Invalid hex string provided to hexToBytes:', hex);
    throw new Error(`hexToBytes requires a string, got ${typeof hex}`);
  }
  
  // Make sure we have an even number of hex digits
  if (hex.length % 2 !== 0) {
    console.warn('Hex string length is odd, padding with 0');
    hex = '0' + hex;
  }
  
  return Buffer.from(hex, 'hex');
}

/**
 * XOR two buffers (utility function)
 * @param {Buffer} a - First buffer
 * @param {Buffer} b - Second buffer
 * @returns {Buffer} - Result of XOR
 */
function xorBytes(a, b) {
  const result = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i % b.length];
  }
  return result;
}

/**
 * Encrypt data using AES-256-CBC
 * 
 * This is a REAL implementation of AES encryption using:
 * - AES-256 cipher (using 256-bit keys)
 * - CBC mode (Cipher Block Chaining) for block cipher operation
 * - PKCS padding (automatically handled by the crypto module)
 * 
 * @param {string} data - Data to encrypt
 * @param {Buffer|null} key - Encryption key or null to generate one (32 bytes for AES-256)
 * @param {Buffer|null} iv - Initialization vector or null to generate one (16 bytes)
 * @returns {Object} - Object with encrypted data, key, and IV
 */
function encrypt(data, key = null, iv = null) {
  // Generate key and IV if not provided
  if (!key) key = generateKey(32); // AES-256 requires a 32-byte key
  if (!iv) iv = generateIV(16);    // AES block size is always 16 bytes
  
  try {
    // Create AES-256-CBC cipher
    // This uses the actual AES algorithm as defined in FIPS 197
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    
    // Convert data to buffer if it's a string
    const dataBuffer = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    
    // Encrypt data and finalize
    // The update method processes the input data in chunks
    // The final method adds padding and completes the encryption
    let encrypted = cipher.update(dataBuffer);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    
    return {
      ciphertext: encrypted.toString('hex'),
      key: key.toString('hex'),
      iv: iv.toString('hex')
    };
  } catch (error) {
    console.error('AES encryption error:', error);
    throw new Error(`AES encryption failed: ${error.message}`);
  }
}

/**
 * Decrypt data that was encrypted with AES-256-CBC
 * 
 * This is a REAL implementation of AES decryption using:
 * - AES-256 cipher (using 256-bit keys)
 * - CBC mode (Cipher Block Chaining) for block cipher operation
 * - PKCS padding (automatically handled by the crypto module)
 * 
 * @param {string|Object} ciphertextHex - Hex-encoded ciphertext or object with properties
 * @param {string} keyHex - Hex-encoded key
 * @param {string} ivHex - Hex-encoded IV
 * @returns {string} - Decrypted data
 */
function decrypt(ciphertextHex, keyHex, ivHex) {
  console.log('AES decrypt function called');
  
  // Handle both object-style and parameter-style calls
  let ciphertext;
  
  // If first parameter is an object with our expected properties
  if (typeof ciphertextHex === 'object' && ciphertextHex !== null) {
    console.log('Using object parameters mode');
    const params = ciphertextHex;
    ciphertext = params.ciphertext;
    keyHex = params.key;
    ivHex = params.iv;
  } else {
    console.log('Using individual parameters mode');
    ciphertext = ciphertextHex;
  }
  
  // Validate parameters
  if (!ciphertext || typeof ciphertext !== 'string') {
    throw new Error('Invalid or missing ciphertext');
  }
  if (!keyHex || typeof keyHex !== 'string') {
    throw new Error('Invalid or missing key');
  }
  if (!ivHex || typeof ivHex !== 'string') {
    throw new Error('Invalid or missing IV');
  }
  
  try {
    // Convert hex strings to buffers
    const ciphertextBuffer = hexToBytes(ciphertext);
    const keyBuffer = hexToBytes(keyHex);
    const ivBuffer = hexToBytes(ivHex);
    
    // Create AES-256-CBC decipher
    // This uses the actual AES algorithm as defined in FIPS 197
    const decipher = crypto.createDecipheriv('aes-256-cbc', keyBuffer, ivBuffer);
    
    // Decrypt data and finalize
    // The update method processes the input data in chunks
    // The final method removes padding and completes the decryption
    let decrypted = decipher.update(ciphertextBuffer);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    
    console.log('AES decryption completed successfully');
    return decrypted.toString('utf8');
  } catch (error) {
    console.error('AES decryption error:', error);
    throw error;
  }
}

/**
 * Hash a backup code for secure storage using SHA-256
 * This uses Node.js's crypto module for a standard implementation
 * 
 * @param {string} code - The backup code to hash
 * @returns {string} - Hashed code with salt
 */
function hashBackupCode(code) {
  // Generate a cryptographically secure random salt
  const salt = crypto.randomBytes(16).toString('hex');
  
  // Create a hash of the code with the salt using SHA-256
  // This is a standard cryptographic hash function
  const hash = crypto.createHash('sha256')
    .update(code + salt)
    .digest('hex');
  
  // Return salt and hash together for storage
  return `${salt}:${hash}`;
}

/**
 * Verify a backup code against its hash
 * This ensures the backup code matches without storing the original code
 * 
 * @param {string} code - The backup code to verify
 * @param {string} hashedCode - The hashed code from storage
 * @returns {boolean} - True if the code matches
 */
function verifyBackupCode(code, hashedCode) {
  // Split into salt and hash
  const [salt, storedHash] = hashedCode.split(':');
  
  if (!salt || !storedHash) {
    console.error('Invalid hashed code format');
    return false;
  }
  
  // Recreate the hash with the provided code and stored salt
  // Using the same SHA-256 algorithm
  const computedHash = crypto.createHash('sha256')
    .update(code + salt)
    .digest('hex');
  
  // Compare the computed hash with the stored hash
  // This is a time-constant comparison to prevent timing attacks
  return crypto.timingSafeEqual(
    Buffer.from(computedHash, 'hex'),
    Buffer.from(storedHash, 'hex')
  );
}

module.exports = {
  generateKey,
  generateIV,
  encrypt,
  decrypt,
  hashBackupCode,
  verifyBackupCode,
  // Utility functions
  stringToBytes,
  bytesToHex,
  hexToBytes,
  xorBytes
};