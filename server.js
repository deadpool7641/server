const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const path = require('path');
const WebSocket = require('ws');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

// Trust proxy is required for express-rate-limit to work correctly on platforms like Render/Heroku
app.set('trust proxy', 1);

app.use(express.json());

// --- PHASE 5: SECURITY HARDENING ---
app.use(helmet({
    contentSecurityPolicy: false, // Disable CSP for easier admin panel integration if needed, or configure it properly
}));

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { success: false, message: 'Too many requests' }
});
app.use('/api/', apiLimiter);

const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || process.env.JWT_SECRET;
const ADMIN_TOKEN_TTL = process.env.ADMIN_TOKEN_TTL || '8h';

const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100, // Increased for admin use
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Too many admin requests' }
});
app.use('/admin', adminLimiter);

// --- HELPER FUNCTIONS ---
function isValidEmail(email) {
    return typeof email === 'string' && email.includes('@') && email.length <= 254;
}

function isValidPassword(password) {
    return typeof password === 'string' && password.length >= 8 && password.length <= 128;
}

function sanitizePagination(value, fallback, max) {
    const parsed = parseInt(value, 10);
    if (isNaN(parsed) || parsed <= 0) return fallback;
    return Math.min(parsed, max);
}

function isValidObjectId(id) {
    return mongoose.Types.ObjectId.isValid(id);
}

// --- MONGODB CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB error:', err));

// --- MONGODB MODELS ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, trim: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user', index: true },
    isBanned: { type: Boolean, default: false, index: true },
    bannedAt: { type: Date, default: null },
    bannedReason: { type: String, default: null },
    lastLoginAt: { type: Date, default: null },
    publicKey: { type: String },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

const MessageSchema = new mongoose.Schema({
    from: { type: String, required: true, trim: true },
    to: { type: String, required: true, trim: true },
    payload: { type: String, required: true }, // renamed to payload to match app logic
    timestamp: { type: Number, required: true }
}, { versionKey: false });
MessageSchema.index({ from: 1, to: 1, timestamp: 1 });
const Message = mongoose.model('Message', MessageSchema);

// --- AUTH MIDDLEWARE ---
function extractBearerToken(req) {
    const auth = req.headers.authorization || '';
    if (!auth.startsWith('Bearer ')) return null;
    return auth.slice(7).trim();
}

async function verifyAdminToken(req, res, next) {
    try {
        const token = extractBearerToken(req);
        if (!token) return res.status(401).json({ success: false, message: 'Missing admin token' });

        const payload = jwt.verify(token, ADMIN_JWT_SECRET);
        if (payload.type !== 'admin' || payload.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Admin access required' });
        }

        const admin = await User.findById(payload.adminId).select('_id role username email isBanned').lean();
        if (!admin || admin.role !== 'admin' || admin.isBanned) {
            return res.status(403).json({ success: false, message: 'Admin account not authorized' });
        }

        req.admin = admin;
        next();
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Invalid or expired admin token' });
    }
}

// --- ADMIN ROUTES ---

// Serve the admin panel
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.post('/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const admin = await User.findOne({ email, role: 'admin' });
        if (!admin || !await bcrypt.compare(password, admin.password)) {
            return res.status(401).json({ success: false, message: 'Invalid admin credentials' });
        }
        if (admin.isBanned) return res.status(403).json({ success: false, message: 'Admin account is banned' });

        admin.lastLoginAt = new Date();
        await admin.save();

        const token = jwt.sign(
            { adminId: admin._id.toString(), role: admin.role, type: 'admin' },
            ADMIN_JWT_SECRET,
            { expiresIn: ADMIN_TOKEN_TTL }
        );
        res.json({ success: true, token, admin: { id: admin._id, username: admin.username, email: admin.email, role: admin.role } });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Admin login failed' });
    }
});

app.get('/admin/dashboard', verifyAdminToken, async (req, res) => {
    try {
        const [totalUsers, bannedUsers, messagesCount] = await Promise.all([
            User.countDocuments(),
            User.countDocuments({ isBanned: true }),
            Message.countDocuments()
        ]);
        const last24h = Date.now() - 24 * 60 * 60 * 1000;
        const messagesLast24h = await Message.countDocuments({ timestamp: { $gte: last24h } });

        res.json({
            success: true,
            data: {
                totalUsers,
                bannedUsers,
                activeUsers: clients.size,
                messagesCount,
                messagesLast24h,
                uptimeSeconds: Math.floor(process.uptime())
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Failed to load dashboard' });
    }
});

app.get('/admin/users', verifyAdminToken, async (req, res) => {
    try {
        const { q, role, banned } = req.query;
        const limit = sanitizePagination(req.query.limit, 20, 100);
        const filter = {};
        if (q) filter.$or = [{ username: { $regex: q, $options: 'i' } }, { email: { $regex: q, $options: 'i' } }];
        if (role) filter.role = role;
        if (banned === 'true') filter.isBanned = true;
        if (banned === 'false') filter.isBanned = false;

        const users = await User.find(filter).sort({ createdAt: -1 }).limit(limit).lean();
        res.json({ success: true, data: { users } });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Failed to load users' });
    }
});

app.patch('/admin/users/:id/ban', verifyAdminToken, async (req, res) => {
    try {
        const { banned, reason } = req.body;
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        if (user.role === 'admin') return res.status(400).json({ success: false, message: 'Cannot ban an admin' });

        user.isBanned = banned;
        user.bannedAt = banned ? new Date() : null;
        user.bannedReason = banned ? reason : null;
        await user.save();
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Ban action failed' });
    }
});

app.post('/admin/users/:id/reset-password', verifyAdminToken, async (req, res) => {
    try {
        const { newPassword } = req.body;
        if (!isValidPassword(newPassword)) return res.status(400).json({ success: false, message: 'Invalid password' });
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });

        user.password = await bcrypt.hash(newPassword, 12);
        await user.save();
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Reset failed' });
    }
});

app.delete('/admin/users/:id', verifyAdminToken, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user || user.role === 'admin') return res.status(400).json({ success: false, message: 'Cannot delete' });
        await User.deleteOne({ _id: req.params.id });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Delete failed' });
    }
});

app.get('/admin/messages', verifyAdminToken, async (req, res) => {
    try {
        const { from, to } = req.query;
        const limit = sanitizePagination(req.query.limit, 50, 200);
        const filter = {};
        if (from) filter.from = from;
        if (to) filter.to = to;
        const messages = await Message.find(filter).sort({ timestamp: -1 }).limit(limit).select('_id from to timestamp').lean();
        res.json({ success: true, data: { messages: messages.map(m => ({ id: m._id, ...m })) } });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Failed to load messages' });
    }
});

app.delete('/admin/messages/:id', verifyAdminToken, async (req, res) => {
    try {
        await Message.deleteOne({ _id: req.params.id });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Delete failed' });
    }
});

// --- USER API ROUTES ---
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!isValidEmail(email)) return res.status(400).json({ success: false, message: 'Invalid email' });
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
        if (user.isBanned) return res.status(403).json({ success: false, message: 'Banned' });
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
        res.json({ success: true, token, user: { id: user._id, username: user.username, email: user.email } });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// --- WEBSOCKET LOGIC ---
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const clients = new Map();
const adminMonitors = new Set();
const connectionLogs = [];

function pushConnectionLog(event, userId, extra = {}) {
    connectionLogs.push({ event, userId, timestamp: Date.now(), ...extra });
    if (connectionLogs.length > 100) connectionLogs.shift();
    broadcastMonitorSnapshot();
}

function broadcastMonitorSnapshot() {
    const payload = JSON.stringify({
        type: 'monitor_snapshot',
        activeConnections: clients.size,
        connectionLogs: connectionLogs.slice(-50)
    });
    adminMonitors.forEach(ws => { if (ws.readyState === WebSocket.OPEN) ws.send(payload); });
}

wss.on('connection', async (ws, req) => {
    const urlParams = new URL(req.url, 'http://localhost').searchParams;
    const token = urlParams.get('token');
    const adminToken = urlParams.get('adminToken');

    if (adminToken) {
        try {
            const payload = jwt.verify(adminToken, ADMIN_JWT_SECRET);
            if (payload.type !== 'admin') throw new Error();
            ws.isAdminMonitor = true;
            adminMonitors.add(ws);
            broadcastMonitorSnapshot();
            return;
        } catch (e) { ws.close(4001); return; }
    }

    try {
        if (!token) throw new Error();
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId).lean();
        if (!user || user.isBanned) throw new Error();
        ws.userId = user.username;
        clients.set(ws.userId, ws);
        pushConnectionLog('connected', ws.userId);
    } catch (e) { ws.terminate(); return; }

    ws.on('message', async (data) => {
        try {
            const msg = JSON.parse(data);
            if (msg.type === 'message') {
                const dbMsg = new Message({ from: ws.userId, to: msg.to, payload: msg.payload, timestamp: Date.now() });
                await dbMsg.save();
                const target = clients.get(msg.to);
                if (target && target.readyState === WebSocket.OPEN) {
                    target.send(JSON.stringify({ type: 'message', from: ws.userId, to: msg.to, payload: msg.payload, timestamp: dbMsg.timestamp }));
                }
                pushConnectionLog('message_routed', ws.userId, { to: msg.to });
            }
        } catch (e) {}
    });

    ws.on('close', () => {
        if (ws.isAdminMonitor) adminMonitors.delete(ws);
        else { clients.delete(ws.userId); pushConnectionLog('disconnected', ws.userId); }
    });
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
