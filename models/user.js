const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Name is required']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email address']
  },
  passwordHash: {
    type: String,
    required: [true, 'Password is required']
  },
  passwordSalt: {
    type: String,
    required: [true, 'Password salt is required']
  },
  isAdmin: {
    type: Boolean,
    default: false
  },
  // Optional profile fields - basic non-sensitive data
  phone: {
    type: String,
    default: null
  },
  profilePicture: {
    type: String,
    default: null
  },
  company: {
    type: String,
    default: null
  },
  title: {
    type: String,
    default: null
  },
  // Fields for password reset
  resetPasswordToken: String,
  resetPasswordOtpExpires: Date,
  
  // Reference to MFA (not embedding)
  mfaEnabled: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true,
  strictQuery: false
});

// Virtual for hiding sensitive data
userSchema.set('toJSON', {
  transform: function (doc, ret) {
    delete ret.passwordHash;
    delete ret.passwordSalt;
    delete ret.resetPasswordToken;
    delete ret.resetPasswordOtpExpires;
    return ret;
  }
});

const User = mongoose.model('User', userSchema);

module.exports = { User };