const mongoose = require('mongoose');

const tokenSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    token: {
        type: String,
        required: true
    },
    accessToken: {
        type: String
    },
    encryptedData: {
        type: String
    },
    iv: {
        type: String
    },
    key: {
        type: String
    },
    expiresAt: {
        type: Date,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: '7d' // Automatically delete after 7 days
    }
});

const Token = mongoose.model('Token', tokenSchema);

module.exports = { Token };