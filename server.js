const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const WebSocket = require('ws');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
app.use(express.json());

// --- PHASE 5: SECURITY HARDENING ---
// 1. HTTP Headers Security
app.use(helmet());

// 2. Rate Limiting: Max 100 requests per 15 minutes
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { success: false, message: 'Too many requests' }
});
app.use('/api/', apiLimiter);

// --- MONGODB CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB error:', err));

// --- MONGODB MODELS ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    publicKey: { type: String },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

// --- AUTH ROUTES ---
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        // Basic Input Validation
        if (!email.includes('@')) return res.status(400).json({ success: false, message: 'Invalid email' });

        const hashedPassword = await bcrypt.hash(password, 12);
        const user = new User({ username, email, password: hashedPassword });
        await user.save();
        res.status(201).json({ success: true, message: 'User registered' });
    } catch (e) {
        res.status(400).json({ success: false, message: 'Email already exists' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
        res.json({ success: true, token, user: { id: user._id, username: user.username, email: user.email } });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const clients = new Map();

wss.on('connection', (ws, req) => {
    const urlParams = new URL(req.url, 'http://localhost').searchParams;
    const token = urlParams.get('token');

    try {
        if (!token) throw new Error('No token');
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        ws.userId = decoded.userId;
        clients.set(ws.userId, ws);
        console.log(`User ${ws.userId} connected`);
    } catch (e) {
        console.warn('Unauthorized WebSocket connection');
        ws.terminate();
    }

    ws.on('message', (data) => {
        try {
            const msg = JSON.parse(data);
            if (!msg.to || !msg.payload) return;

            const target = clients.get(msg.to);
            if (target && target.readyState === WebSocket.OPEN) {
                target.send(JSON.stringify({
                    from: ws.userId,
                    payload: msg.payload,
                    timestamp: Date.now()
                }));
            }
        } catch (e) {}
    });

    ws.on('close', () => clients.delete(ws.userId));
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
