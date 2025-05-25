const mongoose = require('mongoose');

const encryptedDataSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true
  },
  dataType: {
    type: String,
    enum: ['personal', 'security', 'preferences', 'mfa', 'address', 'payment'],
    required: true
  },
  ciphertext: { 
    type: String, 
    required: true 
  },
  keyId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'EncryptionKey', 
    required: true 
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  updatedAt: { 
    type: Date, 
    default: Date.now 
  }
});

// Index for quick lookups
encryptedDataSchema.index({ userId: 1, dataType: 1 });

exports.EncryptedData = mongoose.model('EncryptedData', encryptedDataSchema);