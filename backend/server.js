// server.js - Backend Server (Node.js v8+ Compatible)
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB Connection (Compatible with older Mongoose versions)
console.log("MONGO URI:", process.env.MONGODB_URI);

mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(async () => {
        console.log('✅ MongoDB Connected');

        // 👇 Seed demo user
        const demoUser = await User.findOne({ username: 'testuser' });

        if (!demoUser) {
            const hashed = await bcrypt.hash('test123', 10);

            await new User({
                username: 'testuser',
                password: hashed,
                role: 'user'
            }).save();

            console.log('🎯 Demo user created: testuser / test123');
        } else {
            console.log('ℹ️ Demo user already exists');
        }
    })
    .catch(err => console.error('❌ MongoDB Connection Error:', err));

app.get('/', (req, res) => {
    res.send('Backend is running 🚀');
});

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// File Schema
const fileSchema = new mongoose.Schema({
    name: { type: String, required: true },
    originalName: { type: String, required: true },
    encryptedData: { type: String, required: true },
    iv: { type: String, required: true },
    size: { type: Number, required: true },
    mimeType: { type: String, required: true },
    uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    uploadDate: { type: Date, default: Date.now },
    accessRole: { type: String, enum: ['user', 'admin'], default: 'user' }
});

const File = mongoose.model('File', fileSchema);

// Activity Log Schema
const activitySchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    action: { type: String, required: true },
    details: { type: String, required: true },
    timestamp: { type: Date, default: Date.now }
});

const Activity = mongoose.model('Activity', activitySchema);

// Configure Multer for file upload
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, function (err, user) {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// Encryption functions
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const IV_LENGTH = 16;

function encryptFile(buffer, userKey) {
    // Combine system key with user key
    const combinedKey = crypto.createHash('sha256')
        .update(ENCRYPTION_KEY + userKey)
        .digest();

    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', combinedKey, iv);

    const encrypted = Buffer.concat([
        cipher.update(buffer),
        cipher.final()
    ]);

    return {
        iv: iv.toString('hex'),
        encryptedData: encrypted.toString('base64')
    };
}

function decryptFile(encryptedData, iv, userKey) {
    try {
        const combinedKey = crypto.createHash('sha256')
            .update(ENCRYPTION_KEY + userKey)
            .digest();

        const decipher = crypto.createDecipheriv(
            'aes-256-cbc',
            combinedKey,
            Buffer.from(iv, 'hex')
        );

        const decrypted = Buffer.concat([
            decipher.update(Buffer.from(encryptedData, 'base64')),
            decipher.final()
        ]);

        return decrypted;
    } catch (error) {
        console.error('Decryption error:', error);
        return null;
    }
}

// Routes

// Register
app.post('/api/auth/register', function (req, res) {
    const username = req.body.username;
    const password = req.body.password;
    const role = req.body.role;

    // Check if user exists
    User.findOne({ username: username })
        .then(function (existingUser) {
            if (existingUser) {
                return res.status(400).json({ message: 'Username already exists' });
            }

            // Hash password
            bcrypt.hash(password, 10)
                .then(function (hashedPassword) {
                    // Create user
                    const user = new User({
                        username: username,
                        password: hashedPassword,
                        role: role || 'user'
                    });

                    user.save()
                        .then(function (savedUser) {
                            // Log activity
                            const activity = new Activity({
                                user: savedUser._id,
                                action: 'REGISTER',
                                details: 'New user ' + username + ' registered'
                            });

                            activity.save().catch(function (err) {
                                console.error('Activity log error:', err);
                            });

                            res.status(201).json({
                                message: 'User registered successfully',
                                userId: savedUser._id
                            });
                        })
                        .catch(function (error) {
                            res.status(500).json({ message: 'Error creating user', error: error.message });
                        });
                })
                .catch(function (error) {
                    res.status(500).json({ message: 'Error hashing password', error: error.message });
                });
        })
        .catch(function (error) {
            res.status(500).json({ message: 'Error checking user', error: error.message });
        });
});

// Login
app.post('/api/auth/login', function (req, res) {
    const username = req.body.username;
    const password = req.body.password;

    // Find user
    User.findOne({ username: username })
        .then(function (user) {
            if (!user) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }

            // Check password
            bcrypt.compare(password, user.password)
                .then(function (isValidPassword) {
                    if (!isValidPassword) {
                        return res.status(401).json({ message: 'Invalid credentials' });
                    }

                    // Generate JWT token
                    const token = jwt.sign(
                        {
                            userId: user._id,
                            username: user.username,
                            role: user.role
                        },
                        JWT_SECRET,
                        { expiresIn: '24h' }
                    );

                    // Log activity
                    const activity = new Activity({
                        user: user._id,
                        action: 'LOGIN',
                        details: 'User ' + username + ' logged in successfully'
                    });

                    activity.save().catch(function (err) {
                        console.error('Activity log error:', err);
                    });

                    res.json({
                        message: 'Login successful',
                        token: token,
                        user: {
                            id: user._id,
                            username: user.username,
                            role: user.role
                        }
                    });
                })
                .catch(function (error) {
                    res.status(500).json({ message: 'Error checking password', error: error.message });
                });
        })
        .catch(function (error) {
            res.status(500).json({ message: 'Error finding user', error: error.message });
        });
});

// Upload file
app.post('/api/files/upload', authenticateToken, upload.single('file'), function (req, res) {
    if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded' });
    }

    const encryptionKey = req.body.encryptionKey;
    if (!encryptionKey) {
        return res.status(400).json({ message: 'Encryption key required' });
    }

    try {
        // Encrypt file
        const encrypted = encryptFile(req.file.buffer, encryptionKey);

        // Save file metadata
        const file = new File({
            name: Date.now() + '-' + req.file.originalname,
            originalName: req.file.originalname,
            encryptedData: encrypted.encryptedData,
            iv: encrypted.iv,
            size: req.file.size,
            mimeType: req.file.mimetype,
            uploadedBy: req.user.userId,
            accessRole: req.user.role
        });

        file.save()
            .then(function (savedFile) {
                // Log activity
                const activity = new Activity({
                    user: req.user.userId,
                    action: 'UPLOAD',
                    details: 'File "' + req.file.originalname + '" uploaded and encrypted'
                });

                activity.save().catch(function (err) {
                    console.error('Activity log error:', err);
                });

                res.status(201).json({
                    message: 'File uploaded successfully',
                    file: {
                        id: savedFile._id,
                        name: savedFile.originalName,
                        size: savedFile.size,
                        mimeType: savedFile.mimeType,
                        uploadDate: savedFile.uploadDate
                    }
                });
            })
            .catch(function (error) {
                res.status(500).json({ message: 'Error saving file', error: error.message });
            });
    } catch (error) {
        res.status(500).json({ message: 'Error encrypting file', error: error.message });
    }
});

// Get all files
app.get('/api/files', authenticateToken, function (req, res) {
    const query = {};

    // If user is not admin, only show their files
    if (req.user.role !== 'admin') {
        query.uploadedBy = req.user.userId;
    }

    File.find(query)
        .populate('uploadedBy', 'username')
        .select('-encryptedData')
        .sort({ uploadDate: -1 })
        .then(function (files) {
            res.json(files);
        })
        .catch(function (error) {
            res.status(500).json({ message: 'Error fetching files', error: error.message });
        });
});

// Download file
app.post('/api/files/download/:id', authenticateToken, function (req, res) {
    const decryptionKey = req.body.decryptionKey;

    File.findById(req.params.id)
        .then(function (file) {
            if (!file) {
                return res.status(404).json({ message: 'File not found' });
            }

            // Check access permissions
            if (req.user.role !== 'admin' && file.uploadedBy.toString() !== req.user.userId) {
                return res.status(403).json({ message: 'Access denied' });
            }

            // Decrypt file
            const decryptedData = decryptFile(file.encryptedData, file.iv, decryptionKey);

            if (!decryptedData) {
                // Log failed attempt
                const activity = new Activity({
                    user: req.user.userId,
                    action: 'FAILED_ACCESS',
                    details: 'Failed attempt to decrypt "' + file.originalName + '"'
                });

                activity.save().catch(function (err) {
                    console.error('Activity log error:', err);
                });

                return res.status(401).json({ message: 'Invalid decryption key' });
            }

            // Log successful download
            const activity = new Activity({
                user: req.user.userId,
                action: 'DOWNLOAD',
                details: 'File "' + file.originalName + '" decrypted and downloaded'
            });

            activity.save().catch(function (err) {
                console.error('Activity log error:', err);
            });

            // Send file
            res.set({
                'Content-Type': file.mimeType,
                'Content-Disposition': 'attachment; filename="' + file.originalName + '"'
            });
            res.send(decryptedData);
        })
        .catch(function (error) {
            res.status(500).json({ message: 'Error downloading file', error: error.message });
        });
});

// Delete file
app.delete('/api/files/:id', authenticateToken, function (req, res) {
    File.findById(req.params.id)
        .then(function (file) {
            if (!file) {
                return res.status(404).json({ message: 'File not found' });
            }

            // Check permissions
            if (req.user.role !== 'admin' && file.uploadedBy.toString() !== req.user.userId) {
                return res.status(403).json({ message: 'Access denied' });
            }

            const fileName = file.originalName;

            File.findByIdAndDelete(req.params.id)
                .then(function () {
                    // Log activity
                    const activity = new Activity({
                        user: req.user.userId,
                        action: 'DELETE',
                        details: 'File "' + fileName + '" deleted'
                    });

                    activity.save().catch(function (err) {
                        console.error('Activity log error:', err);
                    });

                    res.json({ message: 'File deleted successfully' });
                })
                .catch(function (error) {
                    res.status(500).json({ message: 'Error deleting file', error: error.message });
                });
        })
        .catch(function (error) {
            res.status(500).json({ message: 'Error finding file', error: error.message });
        });
});

// Get activity logs (admin only)
app.get('/api/logs', authenticateToken, function (req, res) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Admin access required' });
    }

    Activity.find()
        .populate('user', 'username')
        .sort({ timestamp: -1 })
        .limit(50)
        .then(function (logs) {
            res.json(logs);
        })
        .catch(function (error) {
            res.status(500).json({ message: 'Error fetching logs', error: error.message });
        });
});

// Health check
app.get('/api/health', function (req, res) {
    res.json({ status: 'OK', message: 'Server is running' });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, function () {
    console.log('🚀 Server running on port ' + PORT);
    console.log('📡 API available at http://localhost:' + PORT + '/api');
});