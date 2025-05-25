const mongoose = require('mongoose');

const encryptionKeySchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true
  },
  purpose: {
    type: String,
    enum: ['user-data', 'authentication', 'mfa', 'custom'],
    required: true
  },
  key: { 
    type: String, 
    required: true 
  },
  iv: {
    type: String,
    required: true
  },
  algorithm: { 
    type: String, 
    default: 'aes-256-cbc' 
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  expiresAt: { 
    type: Date 
  },
  isActive: {
    type: Boolean,
    default: true
  }
});

// Index for quick lookups
encryptionKeySchema.index({ userId: 1, purpose: 1, isActive: 1 });

exports.EncryptionKey = mongoose.model('EncryptionKey', encryptionKeySchema);