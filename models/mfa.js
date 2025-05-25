const mongoose = require('mongoose');

const mfaSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  secret: {
    type: String,
    required: true
  },
  enabled: {
    type: Boolean,
    default: false
  },
  method: {
    type: String,
    enum: ['totp', 'sms', 'email'],
    default: 'totp'
  },
  verifiedAt: {
    type: Date,
    default: null
  },
  lastUsedAt: {
    type: Date,
    default: null
  }
}, {
  timestamps: true
});

// For security, never include the secret in JSON responses
mfaSchema.set('toJSON', {
  transform: function (doc, ret) {
    delete ret.secret;
    return ret;
  }
});

const MFA = mongoose.model('MFA', mfaSchema);

module.exports = { MFA };