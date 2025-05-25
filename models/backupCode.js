const mongoose = require('mongoose');

const backupCodeSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  // Hashed backup code
  code: {
    type: String,
    required: true
  },
  used: {
    type: Boolean,
    default: false
  },
  usedAt: {
    type: Date,
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: 31536000 // 1 year expiry in seconds
  }
});

// Create a compound index for faster lookups
backupCodeSchema.index({ userId: 1, used: 1 });

const BackupCode = mongoose.model('BackupCode', backupCodeSchema);

module.exports = { BackupCode };