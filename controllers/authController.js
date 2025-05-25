const { validationResult } = require('express-validator');
const { User } = require('../models/user');
const { EncryptionKey } = require('../models/encryptionKey');
const { EncryptedData } = require('../models/encryptedData');
const mailSender = require('../helpers/email_sender');
const customHash = require('../utils/crypto/hash');
const customEncrypt = require('../utils/crypto/encrypt');
const { Token } = require('../models/token');
const crypto = require('crypto');

/**
 * User Registration with encrypted sensitive data
 * This function handles user registration by validating input,
 * encrypting sensitive data, and storing it securely in separate models.
 */
exports.register = async function (req, res) {
    console.log('Register function called with body:', req.body);
    
    // Check if there are validation errors
    console.log('Running validation...');
    const errors = validationResult(req);
    console.log('Validation result:', errors);
    
    if (!errors.isEmpty()) {
        console.log('Validation errors detected:', errors.array());
        return res.status(400).json({ errors: errors.array().map(error => {
            console.log('Mapping error:', error);
            return {
                field: error.path, // Field where the error occurred
                message: error.msg, // Error message
            };
        })});
    }
    console.log('Validation passed, continuing with registration');

    try {
        // Extract data from request
        const { email, password, name, phone, company, title, ...otherData } = req.body;
        
        console.log('Creating new user with basic data');
        console.log('Hashing password with custom implementation...');
        
        // Using our custom hash implementation for password
        const hashResult = customHash.hashPassword(password);
        console.log('Password hashed successfully');
        
        // Create a new user instance with basic non-sensitive data
        console.log('Creating user instance with basic data...');
        let user = new User({
            name:name,
            email: email.toLowerCase(),
            passwordHash: hashResult.hash,
            passwordSalt: hashResult.salt,
            isAdmin: false // Default value
        });
        
        // Save the user to get an ID
        console.log('Saving basic user to database...');
        user = await user.save();
        console.log('User saved with ID:', user._id);

        if (!user) {
            console.log('Failed to create user - no user returned');
            return res.status(500).json({ type: 'Internal Server Error', message: 'Could not create a new user' });
        }

        // Create encryption keys for user data
        console.log('Creating encryption keys for user data...');
        const userDataKey = await createEncryptionKey(user._id, 'user-data');
        console.log('User data encryption key created:', userDataKey._id);
        
        // Prepare sensitive data for encryption
        const sensitiveData = {
            name,
            phone,
            company,
            title,
            ...otherData
        };
        
        console.log('Encrypting sensitive user data...');
        // Encrypt the personal data JSON
        const encryptedPersonalData = encryptData(
            JSON.stringify(sensitiveData),
            userDataKey.key,
            userDataKey.iv
        );
        
        // Create encrypted data record
        console.log('Creating encrypted data record...');
        const personalDataRecord = new EncryptedData({
            userId: user._id,
            dataType: 'personal',
            ciphertext: encryptedPersonalData.ciphertext,
            keyId: userDataKey._id
        });
        
        await personalDataRecord.save();
        console.log('Encrypted data saved successfully');

        console.log('User created successfully with encrypted data');
        console.log('Sending response with status 201...');
        
        // Return user without sensitive data
        return res.status(201).json({
            id: user._id,
            email: user.email,
            message: 'User registered successfully'
        });
    } catch (error) {
        console.error('Error during user creation:', error);
        
        // Handle duplicate email error
        if (error.code === 11000) {
            console.log('Duplicate email error detected');
            return res.status(400).json({ type: 'Validation Error', message: 'Email already exists' });
        }
        
        // Check for validation errors from Mongoose
        if (error.name === 'ValidationError') {
            console.log('Mongoose validation error:', error.errors);
            console.log('Extracting validation error fields...');
            const validationErrors = Object.keys(error.errors).map(field => {
                console.log(`Processing field ${field} error: ${error.errors[field].message}`);
                return {
                    field,
                    message: error.errors[field].message
                };
            });
            console.log('Formatted validation errors:', validationErrors);
            return res.status(400).json({ errors: validationErrors });
        }
        
        console.log('Returning generic error response');
        return res.status(500).json({ type: error.name, message: error.message });
    }
};

/**
 * Helper function to create an encryption key
 */
async function createEncryptionKey(userId, purpose) {
    // Generate random key and IV
    const keyBuffer = customEncrypt.generateKey();
    const ivBuffer = customEncrypt.generateIV();
    
    // Create key document
    const encryptionKey = new EncryptionKey({
        userId,
        purpose,
        key: keyBuffer.toString('hex'),
        iv: ivBuffer.toString('hex'),
        algorithm: 'aes-256-cbc',
        isActive: true
    });
    
    return await encryptionKey.save();
}

/**
 * Helper function to encrypt data
 */
function encryptData(data, keyHex, ivHex) {
    const keyBuffer = Buffer.from(keyHex, 'hex');
    const ivBuffer = Buffer.from(ivHex, 'hex');
    
    return customEncrypt.encrypt(data, keyBuffer, ivBuffer);
}

/**
 * Helper function to decrypt data
 */
function decryptData(ciphertext, keyHex, ivHex) {
    return customEncrypt.decrypt(ciphertext, keyHex, ivHex);
}

/**
 * User Login - Modified for MFA support and to include decrypted user data
 * This function verifies user credentials and either completes login or requires MFA
 */
exports.login = async (req, res) => {
    try {
        console.log('login function called with body:', { 
            email: req.body.email, 
            password: req.body.password ? '[HIDDEN]' : undefined 
        });
        
        // Validate input
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }
        
        // Find user by email
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        
        // Verify password with custom implementation
        console.log('Verifying password with custom hash implementation...');
        const isPasswordValid = customHash.verifyPassword(
            password,
            user.passwordHash,
            user.passwordSalt
        );
        
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        
        // Check if MFA is enabled for this user
        if (user.mfaEnabled) {
            console.log('MFA is enabled for this user, returning MFA required response');
            return res.status(200).json({ 
                mfaRequired: true, 
                message: 'Please provide MFA verification code',
                email: user.email // Return email for the MFA verification step
            });
        }
        
        // If MFA is not enabled, continue with the regular login flow
        return await completeLoginProcess(req, res, user);
    } catch (error) {
        console.error('Error in login:', error);
        return res.status(500).json({ message: error.message });
    }
};

/**
 * Complete login process after successful authentication
 * Creates tokens and returns user data including decrypted sensitive info
 */
async function completeLoginProcess(req, res, user) {
    try {
        // Generate token payload
        const tokenPayload = {
            userId: user._id.toString(),
            isAdmin: user.isAdmin,
            exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 7) // 7 days expiry
        };
        
        // Convert payload to string for encryption
        const payloadString = JSON.stringify(tokenPayload);
        
        // Generate a custom token using our encryption
        console.log('Generating custom token for user:', user._id);
        const tokenResult = customEncrypt.encrypt(payloadString);
        
        // Combine components into a single token string
        const tokenString = `${tokenResult.ciphertext}.${tokenResult.iv}.${tokenResult.key}`;
        
        // Generate refresh token with longer expiry
        console.log('Generating refresh token...');
        const refreshTokenPayload = {
            userId: user._id.toString(),
            isAdmin: user.isAdmin,
            exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 30) // 30 days expiry
        };
        
        const refreshPayloadString = JSON.stringify(refreshTokenPayload);
        const refreshTokenResult = customEncrypt.encrypt(refreshPayloadString);
        const refreshTokenString = `${refreshTokenResult.ciphertext}.${refreshTokenResult.iv}.${refreshTokenResult.key}`;
        
        // Save tokens to database
        console.log('Saving tokens to the database...');
        const tokenDocument = new Token({
            userId: user._id,
            token: tokenString,
            refreshToken: refreshTokenString,
            encryptedData: tokenResult.ciphertext,
            iv: tokenResult.iv,
            key: tokenResult.key,
            expiresAt: new Date(tokenPayload.exp * 1000)
        });
        
        await tokenDocument.save();
        console.log('Tokens saved successfully');
        
        // Set refresh token as HTTP-only cookie
        res.cookie('refreshToken', refreshTokenString, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
        });
        
        // Get encrypted user data
        const encryptedData = await EncryptedData.findOne({
            userId: user._id,
            dataType: 'personal'
        });
        
        let userData = {
            id: user._id,
            email: user.email,
            isAdmin: user.isAdmin,
            mfaEnabled: user.mfaEnabled
        };
        
        // If we have encrypted data, decrypt and include it
        if (encryptedData) {
            console.log('Found encrypted user data, decrypting...');
            
            // Get encryption key
            const encryptionKey = await EncryptionKey.findById(encryptedData.keyId);
            
            if (encryptionKey) {
                // Decrypt data
                const decrypted = decryptData(
                    encryptedData.ciphertext,
                    encryptionKey.key,
                    encryptionKey.iv
                );
                
                // Parse and add to user data
                const personalData = JSON.parse(decrypted);
                userData = {
                    ...userData,
                    ...personalData
                };
                
                console.log('User data decrypted and added to response');
            }
        }
        
        // Return success response with user data
        console.log('Login successful for user ID:', user._id);
        return res.status(200).json({
            user: userData,
            token: tokenString
        });
    } catch (error) {
        console.error('Error in completeLoginProcess:', error);
        throw error;
    }
}

/**
 * Complete login with MFA verification
 * This function should be called after verifying the MFA token
 */
exports.completeLogin = async function (req, res) {
    try {
        console.log('completeLogin function called');
        
        const { email, verificationToken } = req.body;
        
        if (!email || !verificationToken) {
            return res.status(400).json({ message: 'Email and verification token are required' });
        }
        
        // Find user
        const user = await User.findOne({ email: email.toLowerCase() });
        
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        
        // Split and verify the token
        const [ciphertext, iv, key] = verificationToken.split('.');
        
        if (!ciphertext || !iv || !key) {
            return res.status(400).json({ message: 'Invalid verification token format' });
        }
        
        try {
            // Decrypt and verify the token
            const decrypted = customEncrypt.decrypt(ciphertext, key, iv);
            
            // Parse the payload
            const payload = JSON.parse(decrypted);
            
            // Check if token is valid
            if (!payload || !payload.mfaVerified || !payload.userId || 
                payload.userId !== user._id.toString() ||
                payload.exp < Math.floor(Date.now() / 1000)) {
                return res.status(400).json({ message: 'Invalid or expired verification token' });
            }
            
            // Complete the login process
            return await completeLoginProcess(req, res, user);
        } catch (error) {
            console.error('Error verifying MFA token:', error);
            return res.status(400).json({ message: 'Invalid verification token' });
        }
    } catch (error) {
        console.error('Error in completeLogin:', error);
        return res.status(500).json({ message: error.message });
    }
};

/**
 * Get User Profile
 * Retrieves user data including decrypted sensitive information
 */
exports.getUserProfile = async function (req, res) {
    try {
        console.log('getUserProfile function called');
        
        // Get user ID from token verification middleware
        const userId = req.user.id;
        
        if (!userId) {
            return res.status(401).json({ message: 'Authentication required' });
        }
        
        // Get basic user data
        const user = await User.findById(userId);
        
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        // Prepare response with basic user info
        let userData = {
            id: user._id,
            email: user.email,
            isAdmin: user.isAdmin,
            mfaEnabled: user.mfaEnabled,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt
        };
        
        // Get encrypted user data
        const encryptedData = await EncryptedData.findOne({
            userId: user._id,
            dataType: 'personal'
        });
        
        // If we have encrypted data, decrypt and include it
        if (encryptedData) {
            console.log('Found encrypted user data, decrypting...');
            
            // Get encryption key
            const encryptionKey = await EncryptionKey.findById(encryptedData.keyId);
            
            if (encryptionKey) {
                // Decrypt data
                const decrypted = decryptData(
                    encryptedData.ciphertext,
                    encryptionKey.key,
                    encryptionKey.iv
                );
                
                // Parse and add to user data
                const personalData = JSON.parse(decrypted);
                userData = {
                    ...userData,
                    ...personalData
                };
                
                console.log('User data decrypted and added to response');
            }
        }
        
        return res.status(200).json(userData);
    } catch (error) {
        console.error('Error in getUserProfile:', error);
        return res.status(500).json({ message: error.message });
    }
};

/**
 * Update User Profile
 * Updates user data, encrypting sensitive information
 */
exports.updateUserProfile = async function (req, res) {
    try {
        console.log('updateUserProfile function called');
        
        // Get user ID from token verification middleware
        const userId = req.user.id;
        
        if (!userId) {
            return res.status(401).json({ message: 'Authentication required' });
        }
        
        // Extract basic and sensitive data
        const { email, name, phone, company, title, ...otherData } = req.body;
        
        // Get user
        const user = await User.findById(userId);
        
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        // Update basic data if provided
        if (email) {
            user.email = email.toLowerCase();
        }
        
        // Save basic user data
        await user.save();
        
        // Get or create encryption key
        let encryptionKey = await EncryptionKey.findOne({
            userId: user._id,
            purpose: 'user-data',
            isActive: true
        });
        
        if (!encryptionKey) {
            console.log('Creating new encryption key for user data...');
            encryptionKey = await createEncryptionKey(user._id, 'user-data');
        }
        
        // Prepare sensitive data for encryption
        const sensitiveData = {
            name,
            phone,
            company,
            title,
            ...otherData
        };
        
        // Filter out undefined values
        Object.keys(sensitiveData).forEach(key => {
            if (sensitiveData[key] === undefined) {
                delete sensitiveData[key];
            }
        });
        
        // Get existing encrypted data
        let encryptedData = await EncryptedData.findOne({
            userId: user._id,
            dataType: 'personal'
        });
        
        // If we have existing data, merge with new data
        if (encryptedData) {
            console.log('Found existing encrypted data, merging with new data...');
            
            // Get the old encryption key
            const oldKey = await EncryptionKey.findById(encryptedData.keyId);
            
            if (oldKey) {
                // Decrypt old data
                const decrypted = decryptData(
                    encryptedData.ciphertext,
                    oldKey.key,
                    oldKey.iv
                );
                
                // Parse and merge with new data
                const oldData = JSON.parse(decrypted);
                
                // Only update fields that were provided
                Object.keys(sensitiveData).forEach(key => {
                    if (sensitiveData[key] !== undefined) {
                        oldData[key] = sensitiveData[key];
                    }
                });
                
                // Use merged data
                sensitiveData = oldData;
            }
        }
        
        // Encrypt the merged/new data
        console.log('Encrypting sensitive user data...');
        const encryptedPersonalData = encryptData(
            JSON.stringify(sensitiveData),
            encryptionKey.key,
            encryptionKey.iv
        );
        
        // Update or create encrypted data record
        if (encryptedData) {
            encryptedData.ciphertext = encryptedPersonalData.ciphertext;
            encryptedData.keyId = encryptionKey._id;
            encryptedData.updatedAt = new Date();
            await encryptedData.save();
        } else {
            encryptedData = new EncryptedData({
                userId: user._id,
                dataType: 'personal',
                ciphertext: encryptedPersonalData.ciphertext,
                keyId: encryptionKey._id
            });
            await encryptedData.save();
        }
        
        console.log('User profile updated successfully');
        return res.status(200).json({ message: 'Profile updated successfully' });
    } catch (error) {
        console.error('Error in updateUserProfile:', error);
        return res.status(500).json({ message: error.message });
    }
};

/**
 * Verify a custom token
 * Helper function to verify our custom token format
 */
const verifyCustomToken = async (tokenString) => {
    try {
        // Split token into components
        const parts = tokenString.split('.');
        
        if (parts.length !== 3) {
            return { valid: false, error: 'Invalid token format' };
        }
        
        const [ciphertext, iv, key] = parts;
        
        // Decrypt the token
        const decrypted = customEncrypt.decrypt(ciphertext, key, iv);
        
        // Parse payload
        const payload = JSON.parse(decrypted);
        
        // Check expiration
        if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) {
            return { valid: false, error: 'Token expired' };
        }
        
        return { valid: true, payload };
    } catch (error) {
        return { valid: false, error: error.message };
    }
};

/**
 * Refresh Access Token
 * Uses the refresh token stored in a secure cookie to generate a new access token
 */
exports.refreshToken = async function(req, res) {
    console.log('refreshToken function called');
    
    try {
        // Get refresh token from cookie
        console.log('Getting refresh token from cookie...');
        const refreshToken = req.cookies.refreshToken;
        console.log('Refresh token from cookie:', refreshToken ? 'exists' : 'missing');
        
        if (!refreshToken) {
            console.log('No refresh token provided in cookie');
            return res.status(401).json({ message: 'Refresh token required' });
        }
        
        // Find token in database
        console.log('Finding token in database by refresh token...');
        const tokenDoc = await Token.findOne({ refreshToken });
        console.log('Token document found:', tokenDoc ? 'Yes' : 'No');
        
        if (!tokenDoc) {
            console.log('Token not found in database, clearing cookie');
            res.clearCookie('refreshToken', {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                path: '/api/v1/refresh-token'
            });
            return res.status(401).json({ message: 'Invalid refresh token' });
        }
        
        // Verify refresh token using our custom implementation
        console.log('Verifying refresh token...');
        const verifyResult = await verifyCustomToken(refreshToken);
        
        if (!verifyResult.valid) {
            console.log('Token verification failed:', verifyResult.error);
            console.log('Clearing refresh token cookie...');
            res.clearCookie('refreshToken', {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                path: '/api/v1/refresh-token'
            });
            console.log('Deleting token from database...');
            await Token.findByIdAndDelete(tokenDoc._id);
            return res.status(401).json({ message: 'Invalid or expired refresh token' });
        }
        
        // Get user
        console.log('Finding user by ID:', verifyResult.payload.userId);
        const user = await User.findById(verifyResult.payload.userId);
        console.log('User found:', user ? 'Yes' : 'No');
        
        if (!user) {
            console.log('User not found, clearing cookie and deleting token');
            res.clearCookie('refreshToken', {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                path: '/api/v1/refresh-token'
            });
            await Token.findByIdAndDelete(tokenDoc._id);
            return res.status(401).json({ message: 'User not found' });
        }
        
        // Generate new access token
        console.log('Generating new access token...');
        const tokenPayload = {
            userId: user._id.toString(),
            isAdmin: user.isAdmin,
            exp: Math.floor(Date.now() / 1000) + (60 * 15) // 15 minutes
        };
        
        const payloadString = JSON.stringify(tokenPayload);
        const tokenResult = customEncrypt.encrypt(payloadString);
        const tokenString = `${tokenResult.ciphertext}.${tokenResult.iv}.${tokenResult.key}`;
        
        // Update token in database
        console.log('Updating access token in database...');
        tokenDoc.token = tokenString;
        await tokenDoc.save();
        console.log('Access token updated in database');
        
        console.log('Refresh successful, returning new access token');
        return res.json({
            message: 'Token refreshed successfully',
            token: tokenString
        });
    } catch (error) {
        console.error('Error in refreshToken:', error);
        return res.status(500).json({ 
            type: error.name,
            message: error.message
        });
    }
};

/**
 * Logout User
 * Clears the refresh token cookie and removes the token from database
 */
exports.logout = async function(req, res) {
    console.log('logout function called');
    
    try {
        // Get refresh token from cookie
        console.log('Getting refresh token from cookie...');
        const refreshToken = req.cookies.refreshToken;
        console.log('Refresh token from cookie:', refreshToken ? 'exists' : 'missing');
        
        // Clear cookie regardless of token validity
        console.log('Clearing refresh token cookie...');
        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            path: '/'
        });
        
        // If we have a token, remove it from database
        if (refreshToken) {
            console.log('Removing token from database...');
            const result = await Token.findOneAndDelete({ refreshToken });
            console.log('Token removed from database:', result ? 'Yes' : 'No');
        }
        
        console.log('Logout completed successfully');
        return res.json({ message: 'Logout successful' });
    } catch (error) {
        console.error('Error in logout:', error);
        return res.status(500).json({ 
            type: error.name,
            message: error.message 
        });
    }
};

/**
 * Check Auth Status
 * Verifies if user is logged in by checking access token
 */
exports.checkAuthStatus = async function(req, res) {
    console.log('checkAuthStatus function called');
    console.log('Headers received:', req.headers);
    
    try {
        // Check for authorization header
        console.log('Getting authorization header...');
        const authHeader = req.headers.authorization;
        console.log('Authorization header:', authHeader ? 'exists' : 'missing');
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            console.log('Invalid or missing authorization header');
            return res.json({ isLoggedIn: false });
        }
        
        // Extract token
        const accessToken = authHeader.split(' ')[1];
        console.log('Access token extracted:', accessToken ? 'exists' : 'missing');
        
        if (!accessToken) {
            console.log('No token after Bearer prefix');
            return res.json({ isLoggedIn: false });
        }
        
        // Try to verify token with our custom implementation
        console.log('Verifying access token...');
        const verifyResult = await verifyCustomToken(accessToken);
        
        if (!verifyResult.valid) {
            console.log('Token verification failed:', verifyResult.error);
            
            // If token is expired, check if we have a refresh token cookie
            if (verifyResult.error.includes('expired') && req.cookies.refreshToken) {
                console.log('Access token expired but refresh token exists');
                return res.json({ 
                    isLoggedIn: false, 
                    tokenExpired: true,
                    hasRefreshToken: true 
                });
            }
            
            return res.json({ isLoggedIn: false });
        }
        
        // Check if token exists in database for extra security
        console.log('Checking if token exists in database...');
        const tokenExists = await Token.findOne({ 
            token: accessToken,
            userId: verifyResult.payload.userId
        });
        console.log('Token found in database:', tokenExists ? 'Yes' : 'No');
        
        if (!tokenExists) {
            console.log('Token not found in database');
            return res.json({ isLoggedIn: false });
        }
        
        // Token is valid and exists in database
        console.log('User is authenticated');
        return res.json({ 
            isLoggedIn: true,
            userId: verifyResult.payload.userId,
            isAdmin: verifyResult.payload.isAdmin
        });
    } catch (error) {
        console.error('Error in checkAuthStatus:', error);
        return res.status(500).json({ 
            type: error.name,
            message: error.message
        });
    }
};

/**
 * Token Verification
 * This function checks if the provided access token is valid.
 */
exports.verifyToken = async function (req, res) {
    console.log('verifyToken function called');
    console.log('Headers received:', req.headers);
    try {
        console.log('Getting authorization header...');
        const authHeader = req.headers.authorization || '';
        console.log('Authorization header:', authHeader);
        
        console.log('Checking if authorization header is valid...');
        if (!authHeader) {
            console.log('Missing authorization header');
            return res.json(false);
        }
        
        console.log('Checking if header starts with Bearer...');
        if (!authHeader.startsWith('Bearer ')) {
            console.log('Invalid authorization format - must start with Bearer');
            return res.json(false);
        }

        console.log('Extracting token from header...');
        const accessToken = authHeader.split('Bearer ')[1];
        console.log('Extracted token:', accessToken ? '(token present)' : '(empty token)');
        
        console.log('Checking if token exists after extraction...');
        if (!accessToken) {
            console.log('No token after Bearer prefix');
            return res.json(false);
        }
        
        console.log('Looking for token in database...');
        try {
            const token = await Token.findOne({ token: accessToken });
            console.log('Database query completed');
            console.log('Token found in database:', token ? 'Yes' : 'No');
            
            if (!token) {
                console.log('Token not found in database, returning false');
                return res.json(false);
            }

            console.log('Verifying token with custom implementation...');
            const verifyResult = await verifyCustomToken(accessToken);
            
            if (!verifyResult.valid) {
                console.log('Token verification failed:', verifyResult.error);
                return res.json(false);
            }
            
            console.log('Finding user by ID:', verifyResult.payload.userId);
            const user = await User.findById(verifyResult.payload.userId);
            console.log('User find query completed');
            console.log('User found:', user ? 'Yes' : 'No');
            
            if (!user) {
                console.log('User not found, returning false');
                return res.json(false);
            }
            
            console.log('Token is valid, sending response: true');
            return res.json(true);
        } catch (dbError) {
            console.error('Database error during token verification:', dbError);
            return res.status(500).json({ type: 'DatabaseError', message: dbError.message });
        }
    } catch (error) {
        console.error('Token verification error:', error);
        return res.status(500).json({ type: error.name, message: error.message });
    }
};

/**
 * Forgot Password
 * Generates and sends a secure reset link to the user's email for password reset.
 */
exports.forgotPassword = async function (req, res) {
   console.log('forgotPassword function called with body:', req.body);
   try {
       console.log('Extracting email from request...');
       const { email } = req.body;
       
       if (!email) {
           console.log('No email provided');
           return res.status(400).json({ 
               success: false,
               message: 'Email is required' 
           });
       }
       
       console.log('Finding user with email:', email);
       const user = await User.findOne({ email: email.toLowerCase() });
       console.log('User found:', user ? 'Yes' : 'No');
       
       if (!user) {
           // For security, don't reveal if email exists or not
           console.log('User not found, but returning success response for security');
           return res.json({ 
               success: true,
               message: 'If your email is registered with us, you will receive a password reset link' 
           });
       }

       // Generate secure reset token - no need to hash it
       console.log('Generating secure reset token...');
       const resetToken = generateSecureToken(48); // Generate 48-character token
       console.log('Generated reset token');
       
       // Set expiration time (1 hour)
       const resetTokenExpires = Date.now() + 60 * 60 * 1000;
       console.log('Token expires at:', new Date(resetTokenExpires));
       
       // IMPORTANT: Store the token directly (not hashed) since we need to compare it later
       user.resetPasswordToken = resetToken;
       user.resetPasswordOtpExpires = resetTokenExpires;
       
       console.log('Saving user with reset token...');
       await user.save();
       console.log('User saved with reset token');

       // Create reset URL - adjust baseUrl to match your frontend URL
       const baseUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
       
       // Create the reset URL without any target="_blank"
       const resetUrl = `${baseUrl}/reset-password?token=${resetToken}&email=${encodeURIComponent(email)}`;
       console.log('Reset URL created (not showing for security)');

       // Construct email body ensuring links open in same window (no target="_blank")
       const emailBody = `
       <h1>Password Reset</h1>
       <p>You requested a password reset for your account.</p>
       <p>Click the link below to reset your password. This link will expire in 1 hour.</p>
       
       <a href="${resetUrl}" style="display: inline-block; padding: 12px 24px; background-color: #4a5568; color: white; text-decoration: none; border-radius: 4px; font-weight: bold;">Reset Password</a>
       
       <p>If the button doesn't work, copy and paste this URL into your browser:</p>
       <p>${resetUrl}</p>
       
       <p>This link will expire in 1 hour.</p>
       <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>
       `;

       // Send link via email
       console.log('Sending reset link via email...');
       try {
           const response = await mailSender.sendMail(
               email,
               'Password Reset',
               emailBody,
               true // Set to true for HTML email
           );
           console.log('Email sending response:', response);
           
           console.log('Returning success response');
           return res.json({ 
               success: true,
               message: 'Password reset link sent to your email',
               // Include this in development only, remove for production
               dev_url: process.env.NODE_ENV === 'development' ? resetUrl : undefined
           });
       } catch (emailError) {
           console.error('Error sending email:', emailError);
           // Even if email fails, don't reveal this to potential attackers
           return res.json({ 
               success: true,
               message: 'If your email is registered with us, you will receive a password reset link',
               // Include this in development only, remove for production
               dev_url: process.env.NODE_ENV === 'development' ? resetUrl : undefined,
               dev_error: process.env.NODE_ENV === 'development' ? emailError.message : undefined
           });
       }
   } catch (error) {
       console.error('Error in forgotPassword:', error);
       return res.status(500).json({ 
           success: false,
           message: 'An error occurred while processing your request'
       });
   }
};

/**
 * Verify Password Reset Token
 * This function validates the token from the password reset link.
 */
exports.verifyPasswordResetToken = async function (req, res) {
   console.log('verifyPasswordResetToken function called with body:', req.body);
   try {
       console.log('Extracting email and token from request...');
       const { email, token } = req.body;
       
       // Validate inputs
       if (!email || !token) {
           console.log('Missing required fields');
           return res.status(400).json({ 
               success: false,
               message: 'Email and token are required' 
           });
       }
       
       console.log('Finding user with email:', email);
       const user = await User.findOne({ email: email.toLowerCase() });
       console.log('User found:', user ? 'Yes' : 'No');
       
       if (!user) {
           console.log('User not found, returning 404');
           return res.status(404).json({ 
               success: false,
               message: 'Invalid reset link' 
           });
       }

       console.log('Checking if reset token exists and is not expired');
       if (!user.resetPasswordToken || !user.resetPasswordOtpExpires) {
           console.log('No reset token found or token field missing');
           return res.status(401).json({ 
               success: false,
               message: 'Invalid or expired reset link' 
           });
       }
       
       if (Date.now() > user.resetPasswordOtpExpires) {
           console.log('Reset token expired');
           return res.status(401).json({ 
               success: false,
               message: 'This reset link has expired. Please request a new one.' 
           });
       }
       
       // Direct comparison of tokens
       console.log('Comparing tokens directly...');
       if (user.resetPasswordToken !== token) {
           console.log('Invalid token provided');
           return res.status(401).json({ 
               success: false,
               message: 'Invalid reset link' 
           });
       }
       
       // Special flag to indicate token was verified
       console.log('Setting special flag to mark token as verified...');
       user.resetPasswordToken = 'VERIFIED'; // Special marker
       user.resetPasswordOtpExpires = Date.now() + 30 * 60 * 1000; // 30 minutes to reset password
       
       console.log('Saving user with verified status...');
       await user.save();
       console.log('User saved with verified status');
       
       console.log('Returning success response');
       return res.json({ 
           success: true,
           message: 'Reset link verified. Please set your new password within 30 minutes.' 
       });
   } catch (error) {
       console.error('Error in verifyPasswordResetToken:', error);
       return res.status(500).json({ 
           success: false,
           message: 'An error occurred while verifying the reset link' 
       });
   }
};

/**
 * Reset Password
 * This function allows users to set a new password after token verification.
 */
exports.resetPassword = async function (req, res) {
   console.log('resetPassword function called with body:', {...req.body, newPassword: '[HIDDEN]'});
   
   console.log('Running validation...');
   const errors = validationResult(req);
   console.log('Validation result:', errors.isEmpty() ? 'No errors' : errors.array());
   
   if (!errors.isEmpty()) {
       console.log('Validation errors detected:', errors.array());
       return res.status(400).json({ 
           success: false,
           errors: errors.array().map(error => ({
               field: error.path,
               message: error.msg,
           }))
       });
   }
   console.log('Validation passed, continuing with password reset');
   
   try {
       console.log('Extracting email and new password...');
       const { email, newPassword, token } = req.body;
       
       // Validate inputs
       if (!email || !newPassword) {
           console.log('Missing required fields');
           return res.status(400).json({ 
               success: false,
               message: 'Email and new password are required' 
           });
       }
       
       console.log('Finding user with email:', email);
       const user = await User.findOne({ email: email.toLowerCase() });
       console.log('User found:', user ? 'Yes' : 'No');
       
       if (!user) {
           console.log('User not found, returning 404');
           return res.status(404).json({ 
               success: false,
               message: 'Invalid or expired reset link' 
           });
       }
       
       // Check if token was directly verified (when using verifyPasswordResetToken first)
       // or if we need to verify the token now
       if (user.resetPasswordToken !== 'VERIFIED') {
           console.log('Token not previously verified, verifying now...');
           
           if (!token) {
               console.log('No token provided for verification');
               return res.status(400).json({ 
                   success: false,
                   message: 'Reset token is required' 
               });
           }
           
           if (!user.resetPasswordToken || !user.resetPasswordOtpExpires) {
               console.log('No reset token found or token field missing');
               return res.status(401).json({ 
                   success: false,
                   message: 'Invalid reset link' 
               });
           }
           
           if (Date.now() > user.resetPasswordOtpExpires) {
               console.log('Reset token expired');
               return res.status(401).json({ 
                   success: false,
                   message: 'This reset link has expired. Please request a new one.' 
               });
           }
           
           // Direct token comparison
           console.log('Comparing tokens directly...');
           if (user.resetPasswordToken !== token) {
               console.log('Invalid token provided');
               return res.status(401).json({ 
                   success: false,
                   message: 'Invalid reset link' 
               });
           }
       } else {
           console.log('Token was previously verified');
           
           if (!user.resetPasswordOtpExpires || Date.now() > user.resetPasswordOtpExpires) {
               console.log('Reset window expired, returning 401');
               return res.status(401).json({ 
                   success: false,
                   message: 'Password reset time window expired. Please request a new reset link' 
               });
           }
       }
       
       // Check that new password isn't the same as old password
       const currentPasswordValid = customHash.verifyPassword(
           newPassword, 
           user.passwordHash, 
           user.passwordSalt
       );
       
       if (currentPasswordValid) {
           console.log('New password is same as old password');
           return res.status(400).json({ 
               success: false,
               message: 'New password cannot be the same as your old password' 
           });
       }
       
       console.log('Token verified, hashing new password with custom implementation...');
       const hashResult = customHash.hashPassword(newPassword);
       console.log('Password hashed successfully');
       
       // Update password fields
       user.passwordHash = hashResult.hash;
       user.passwordSalt = hashResult.salt;
       
       console.log('Clearing reset fields...');
       user.resetPasswordToken = undefined;
       user.resetPasswordOtpExpires = undefined;
       
       console.log('Saving user with new password...');
       await user.save();
       console.log('User saved with new password');
       
       // Invalidate all tokens for this user for security
       console.log('Invalidating existing tokens...');
       await Token.deleteMany({ userId: user._id });
       console.log('Tokens invalidated');
       
       console.log('Returning success response');
       return res.json({ 
           success: true,
           message: 'Password reset successfully. Please log in with your new password.' 
       });
   } catch (error) {
       console.error('Error in resetPassword:', error);
       return res.status(500).json({ 
           success: false,
           message: 'An error occurred while resetting your password' 
       });
   }
};

/**
 * Generate a cryptographically secure random token
 * @param {number} length - The length of the token to generate
 * @returns {string} A random token string
 */
function generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
}