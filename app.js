require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { MongoClient } = require('mongodb');
const mongoose = require('mongoose');

// Import routes
const itemRoutes = require('./routes/itemRoutes');
const authRoutes = require('./routes/authRoutes');
const totpRoutes = require('./routes/totpRoutes');

// Initialize express app
const app = express();

// Middleware
app.use(bodyParser.json());
app.use(cookieParser());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

// Database connection - MongoDB native client for flexibility
let db;
async function connectToDatabase() {
  try {
    // Get MongoDB URI from environment variables
    const uri = process.env.MONGODB_URI;
    
    if (!uri) {
      throw new Error('MongoDB URI not provided in environment variables');
    }
    
    // Make sure URI ends with database name, add 'cryptography_db' if not specified
    let fullUri = uri;
    if (uri.endsWith('/')) {
      fullUri = uri + 'cryptography_db';
    } else if (!uri.split('/').pop()) {
      fullUri = uri + '/cryptography_db';
    }
    
    // Connect with MongoDB native client
    const client = new MongoClient(fullUri);
    await client.connect();
    console.log('Connected to MongoDB successfully (native client)');
    
    // Get database from client
    db = client.db();
    app.locals.db = db; // Make db available to routes
    
    // Also connect with Mongoose for models - use the same URI
    await mongoose.connect(fullUri);
    console.log('Connected to MongoDB successfully (mongoose)');
    
    return client;
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error);
    process.exit(1);
  }
}

// Simple route to test the server
app.get('/', (req, res) => {
  res.json({ message: 'Welcome to Cryptography Backend API' });
});

// Register routes
app.use('/api/auth', authRoutes);
app.use('/api/auth/mfa', totpRoutes);
app.use('/api/items', itemRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ error: 'Unauthorized access' });
  }
  
  res.status(500).json({
    error: 'Something went wrong',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// 404 handler - must be last
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: `Route ${req.method} ${req.originalUrl} not found`
  });
});

// Start the server
const PORT = process.env.PORT || 8000;
connectToDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  console.error('Unhandled Promise rejection:', err);
  // In a production environment, you might want to exit and let the process manager restart the application
  // process.exit(1);
});

module.exports = app; // For testing purposes