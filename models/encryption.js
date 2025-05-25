const mongoose = require('mongoose');

const encryptionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  ciphertext: {
    type: String,
    required: true
  },
  iv: {
    type: String,
    required: true
  },
  key: {
    type: String,
    required: true
  },
  algorithm: {
    type: String,
    default: 'Custom-AES-CBC'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Create index for faster lookups by user
encryptionSchema.index({ userId: 1, createdAt: -1 });

const Encryption = mongoose.model('Encryption', encryptionSchema);

module.exports = { Encryption };