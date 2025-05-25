// Custom hashing implementation using pure JavaScript

/**
 * SHA-256 implementation in pure JavaScript
 * @param {string} message - The message to hash
 * @returns {string} - The hash in hex format
 */
function sha256(message) {
  // Constants used in SHA-256
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  // Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
  let H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];

  // Pre-processing: Padding the message
  function preProcess(message) {
    // Convert message to binary array
    let binary = [];
    for (let i = 0; i < message.length; i++) {
      let value = message.charCodeAt(i);
      binary.push((value >> 8) & 0xFF); // High byte
      binary.push(value & 0xFF);        // Low byte
    }

    // Get message length in bits
    const originalLength = binary.length * 8;
    
    // Append the bit '1'
    binary.push(0x80);
    
    // Append '0' bits until message length is congruent to 448 mod 512
    while ((binary.length * 8) % 512 !== 448) {
      binary.push(0);
    }
    
    // Append original length as 64-bit big-endian integer
    const lengthBuffer = new ArrayBuffer(8);
    const lengthView = new DataView(lengthBuffer);
    lengthView.setUint32(0, Math.floor(originalLength / 0x100000000), false);
    lengthView.setUint32(4, originalLength & 0xFFFFFFFF, false);
    
    for (let i = 0; i < 8; i++) {
      binary.push(lengthBuffer[i]);
    }
    
    return binary;
  }

  // Helper functions
  function ROTR(x, n) {
    return (x >>> n) | (x << (32 - n));
  }

  function Ch(x, y, z) {
    return (x & y) ^ (~x & z);
  }

  function Maj(x, y, z) {
    return (x & y) ^ (x & z) ^ (y & z);
  }

  function Sigma0(x) {
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
  }

  function Sigma1(x) {
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
  }

  function sigma0(x) {
    return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >>> 3);
  }

  function sigma1(x) {
    return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >>> 10);
  }

  // Main hash computation
  const binary = preProcess(message);
  
  // Process the message in successive 512-bit chunks
  for (let i = 0; i < binary.length; i += 64) {
    // Create 16 32-bit words
    const words = new Array(64).fill(0);
    
    // Copy chunk into first 16 words
    for (let j = 0; j < 16; j++) {
      words[j] = ((binary[i + j*4] << 24) | (binary[i + j*4 + 1] << 16) | 
                 (binary[i + j*4 + 2] << 8) | (binary[i + j*4 + 3]));
    }
    
    // Extend the first 16 words into the remaining 48 words
    for (let j = 16; j < 64; j++) {
      words[j] = words[j-16] + sigma0(words[j-15]) + words[j-7] + sigma1(words[j-2]);
    }
    
    // Initialize working variables to current hash value
    let [a, b, c, d, e, f, g, h] = H;
    
    // Compression function main loop
    for (let j = 0; j < 64; j++) {
      const T1 = h + Sigma1(e) + Ch(e, f, g) + K[j] + words[j];
      const T2 = Sigma0(a) + Maj(a, b, c);
      h = g;
      g = f;
      f = e;
      e = (d + T1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (T1 + T2) >>> 0;
    }
    
    // Add the compressed chunk to the current hash value
    H[0] = (H[0] + a) >>> 0;
    H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0;
    H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0;
    H[5] = (H[5] + f) >>> 0;
    H[6] = (H[6] + g) >>> 0;
    H[7] = (H[7] + h) >>> 0;
  }
  
  // Convert the hash value to a hex string
  return H.map(h => h.toString(16).padStart(8, '0')).join('');
}

/**
 * Custom password hashing with salt
 * @param {string} password - The password to hash
 * @param {string} [salt] - Optional salt, generated if not provided
 * @returns {Object} - Object containing the hashed password and salt
 */
function hashPassword(password, salt = null) {
  if (!salt) {
    // Generate a random 16-byte salt
    salt = Array.from({ length: 16 }, () => Math.floor(Math.random() * 256))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
  
  // Combine password and salt, then hash multiple times
  let hash = password + salt;
  for (let i = 0; i < 1000; i++) {
    hash = sha256(hash);
  }
  
  return {
    hash,
    salt
  };
}

/**
 * Verify a password against a stored hash
 * @param {string} password - The password to verify
 * @param {string} storedHash - The stored hash
 * @param {string} salt - The salt used to create the hash
 * @returns {boolean} - True if the password matches
 */
function verifyPassword(password, storedHash, salt) {
  const result = hashPassword(password, salt);
  return result.hash === storedHash;
}

module.exports = {
  sha256,
  hashPassword,
  verifyPassword
};