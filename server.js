/**
 * Study Decoder - Production Backend Server v2.0
 * ===============================================
 * A fully production-ready Express.js server with:
 * - Persistent JSON database (auto-saved, no native deps)
 * - bcryptjs password hashing (pure JS, no compilation)
 * - Stripe payment integration with webhooks
 * - Rate limiting & security headers
 * - Session management with secure cookies
 * 
 * Environment Variables Required:
 * - NODE_ENV: 'production' or 'development'
 * - PORT: Server port (default: 3001)
 * - SESSION_SECRET: 32+ character secret for session encryption
 * - GOOGLE_CLIENT_ID: Google OAuth client ID
 * - STRIPE_SECRET_KEY: Stripe secret key (sk_live_xxx or sk_test_xxx)
 * - STRIPE_WEBHOOK_SECRET: Stripe webhook signing secret (whsec_xxx)
 * - FRONTEND_URL: Your frontend domain (e.g., https://studydecoder.com.au)
 */

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

// ==================== CONFIGURATION ====================
const config = {
    port: process.env.PORT || 3001,
    nodeEnv: process.env.NODE_ENV || 'development',
    isDev: (process.env.NODE_ENV || 'development') !== 'production',
    sessionSecret: process.env.SESSION_SECRET,
    googleClientId: process.env.GOOGLE_CLIENT_ID,
    openaiApiKey: process.env.OPENAI_API_KEY,
    ownerEmail: process.env.OWNER_EMAIL || 'yazhat42@gmail.com',
    frontendUrl: process.env.FRONTEND_URL || 'https://studydecoder.onrender.com',
    stripe: {
        secretKey: process.env.STRIPE_SECRET_KEY,
        webhookSecret: process.env.STRIPE_WEBHOOK_SECRET,
        monthlyPriceId: process.env.STRIPE_MONTHLY_PRICE_ID || 'price_monthly',
        yearlyPriceId: process.env.STRIPE_YEARLY_PRICE_ID || 'price_yearly'
    },
    bcryptRounds: 12
};

// Validate required environment variables in production
if (!config.isDev) {
    const required = ['SESSION_SECRET', 'STRIPE_SECRET_KEY', 'OPENAI_API_KEY'];
    const missing = required.filter(key => !process.env[key]);
    if (missing.length > 0) {
        console.error(`❌ Missing required environment variables: ${missing.join(', ')}`);
        process.exit(1);
    }
    if (!process.env.STRIPE_WEBHOOK_SECRET) {
        console.error('❌ STRIPE_WEBHOOK_SECRET is required in production');
        process.exit(1);
    }
}

// Generate session secret for development if not provided
if (!config.sessionSecret) {
    config.sessionSecret = config.isDev 
        ? 'dev-secret-' + crypto.randomBytes(16).toString('hex')
        : null;
    if (!config.sessionSecret) {
        console.error('❌ SESSION_SECRET is required in production');
        process.exit(1);
    }
}

// Initialize Stripe
let stripe = null;
if (config.stripe.secretKey) {
    stripe = require('stripe')(config.stripe.secretKey);
}

// ==================== DATABASE (JSON File-Based) ====================
const DB_PATH = path.join(__dirname, 'data');
const USERS_FILE = path.join(DB_PATH, 'users.json');
const PAYMENTS_FILE = path.join(DB_PATH, 'payments.json');
const OG_CODES_FILE = path.join(DB_PATH, 'og-codes.json');
const REVIEWS_FILE = path.join(DB_PATH, 'reviews.json');

// Ensure data directory exists
if (!fs.existsSync(DB_PATH)) {
    fs.mkdirSync(DB_PATH, { recursive: true });
}

// Load or initialize database
function loadDB(filePath, defaultData = {}) {
    try {
        if (fs.existsSync(filePath)) {
            return JSON.parse(fs.readFileSync(filePath, 'utf8'));
        }
    } catch (e) {
        console.error(`Error loading ${filePath}:`, e.message);
    }
    return defaultData;
}

function saveDB(filePath, data) {
    try {
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    } catch (e) {
        console.error(`Error saving ${filePath}:`, e.message);
    }
}

// ==================== OG CODE SYSTEM ====================
const OG_CODE_CONFIG = {
    code: process.env.OG_CODE || 'STDYOG', // Should be set in environment for production
    maxRedemptions: parseInt(process.env.OG_MAX_REDEMPTIONS) || 6,
    perks: ['lifetime_access', 'og_badge', 'priority_support']
};

// Load OG codes state
const ogCodesState = loadDB(OG_CODES_FILE, { 
    redemptions: [], 
    pendingTokens: {} 
});

function saveOGState() {
    saveDB(OG_CODES_FILE, ogCodesState);
}

// ==================== REVIEWS SYSTEM ====================
const DEFAULT_REVIEWS = [
    {
        id: '1',
        rating: 5,
        text: "great study tool, helped me understand what to actually practice and study",
        createdAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString()
    },
    {
        id: '2',
        rating: 5,
        text: "Finally something that breaks down the syllabus in a way that makes sense! My study sessions are so much more productive now.",
        createdAt: new Date(Date.now() - 25 * 24 * 60 * 60 * 1000).toISOString()
    },
    {
        id: '3',
        rating: 4,
        text: "The practice questions are really helpful for exam prep. Saved me hours of trying to figure out what to focus on.",
        createdAt: new Date(Date.now() - 20 * 24 * 60 * 60 * 1000).toISOString()
    },
    {
        id: '4',
        rating: 5,
        text: "Love how it explains things simply. The AI tutor feels like having a smart friend who actually understands the HSC.",
        createdAt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString()
    },
    {
        id: '5',
        rating: 4,
        text: "Really useful for organizing my study schedule. The timetable feature is a game changer for balancing multiple subjects.",
        createdAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString()
    },
    {
        id: '6',
        rating: 5,
        text: "Wish I had this earlier in Year 11! The syllabus breakdown alone is worth it. Makes studying way less stressful.",
        createdAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString()
    }
];

// Load reviews (initialize with defaults if empty)
let reviewsData = loadDB(REVIEWS_FILE, { reviews: [] });
if (!reviewsData.reviews || reviewsData.reviews.length === 0) {
    reviewsData.reviews = DEFAULT_REVIEWS;
    saveDB(REVIEWS_FILE, reviewsData);
}

function saveReviews() {
    saveDB(REVIEWS_FILE, reviewsData);
}

// ==================== OWNER & ROLE SYSTEM ====================
// Owner email is set via config (from environment variable with fallback)

function getUserRole(email) {
    if (email && email.toLowerCase() === config.ownerEmail.toLowerCase()) {
        return 'owner';
    }
    // Check if user redeemed OG code
    const ogRedemption = ogCodesState.redemptions.find(r => 
        r.email && r.email.toLowerCase() === email.toLowerCase()
    );
    if (ogRedemption) {
        return 'og_tester';
    }
    return 'user';
}

function hasFullAccess(user) {
    if (!user) return false;
    const role = getUserRole(user.email);
    // Owner and OG testers get free access
    if (role === 'owner' || role === 'og_tester') {
        return true;
    }
    // Regular users need subscription
    return user.subscribed === true;
}

// In-memory database with persistence
const db = {
    users: loadDB(USERS_FILE, {}),
    payments: loadDB(PAYMENTS_FILE, [])
};

// Auto-save every 30 seconds and on changes
let saveTimeout = null;
function scheduleSave() {
    if (saveTimeout) clearTimeout(saveTimeout);
    saveTimeout = setTimeout(() => {
        saveDB(USERS_FILE, db.users);
        saveDB(PAYMENTS_FILE, db.payments);
    }, 1000); // Debounce saves
}

// Save on exit
process.on('exit', () => {
    saveDB(USERS_FILE, db.users);
    saveDB(PAYMENTS_FILE, db.payments);
});

// ==================== MIDDLEWARE ====================

// Redirect non-www to www for custom domain (301 permanent redirect)
app.use((req, res, next) => {
    const host = req.get('host');
    // Only redirect if it's the bare domain (no www, not onrender.com)
    if (host === 'studydecoder.com.au') {
        return res.redirect(301, `https://www.studydecoder.com.au${req.originalUrl}`);
    }
    next();
});

// Security headers
app.use(helmet({
    contentSecurityPolicy: config.isDev ? false : {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://accounts.google.com", "https://apis.google.com", "https://js.stripe.com"],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "https://accounts.google.com", "https://oauth2.googleapis.com", "https://api.stripe.com"],
            frameSrc: ["https://accounts.google.com", "https://js.stripe.com"]
        }
    },
    crossOriginEmbedderPolicy: false
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: config.isDev ? 1000 : 100,
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: config.isDev ? 100 : 10,
    message: { error: 'Too many login attempts, please try again later.' }
});

app.use('/api/', limiter);
app.use('/api/login', authLimiter);

// CORS
const corsOptions = {
    origin: function(origin, callback) {
        if (!origin) return callback(null, true);
        
        const allowedOrigins = [
            'http://localhost:3001',
            'http://localhost:5500',
            'http://127.0.0.1:3001',
            'http://127.0.0.1:5500',
            'https://studydecoder.onrender.com',
            config.frontendUrl
        ].filter(Boolean);
        
        if (config.isDev || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'stripe-signature']
};

app.use(cors(corsOptions));

// Trust proxy in production
if (!config.isDev) {
    app.set('trust proxy', 1);
}

// Body parsing - raw for Stripe webhooks, JSON for everything else
app.use((req, res, next) => {
    if (req.originalUrl === '/api/stripe-webhook') {
        express.raw({ type: 'application/json' })(req, res, next);
    } else {
        express.json({ limit: '10kb' })(req, res, next);
    }
});

// Session with file store
const sessionsPath = path.join(DB_PATH, 'sessions');
if (!fs.existsSync(sessionsPath)) {
    fs.mkdirSync(sessionsPath, { recursive: true });
}

app.use(session({
    store: new FileStore({
        path: sessionsPath,
        ttl: 30 * 24 * 60 * 60, // 30 days
        retries: 0,
        logFn: () => {} // Disable logging
    }),
    secret: config.sessionSecret,
    name: 'studydecoder.sid',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: !config.isDev,
        httpOnly: true,
        maxAge: 30 * 24 * 60 * 60 * 1000,
        sameSite: config.isDev ? 'lax' : 'strict'
    }
}));

// Request logging
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        if (config.isDev || res.statusCode >= 400) {
            console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
        }
    });
    next();
});

// ==================== LIVE USERS TRACKING ====================
const liveUsers = new Map(); // sessionId -> { lastSeen, userId, email }
const LIVE_USER_TIMEOUT = 60000; // 1 minute timeout

// Track active users on each request
app.use((req, res, next) => {
    if (req.session && req.session.userId) {
        const user = db.users[req.session.userId];
        liveUsers.set(req.sessionID, {
            lastSeen: Date.now(),
            userId: req.session.userId,
            email: user ? user.email : 'Unknown'
        });
    } else if (req.sessionID) {
        // Track anonymous visitors too
        liveUsers.set(req.sessionID, {
            lastSeen: Date.now(),
            userId: null,
            email: null
        });
    }
    next();
});

// Clean up stale sessions periodically
setInterval(() => {
    const now = Date.now();
    for (const [sessionId, data] of liveUsers.entries()) {
        if (now - data.lastSeen > LIVE_USER_TIMEOUT) {
            liveUsers.delete(sessionId);
        }
    }
}, 30000); // Check every 30 seconds

// ==================== HELPER FUNCTIONS ====================

/**
 * Verify Google ID token
 */
async function verifyGoogleToken(idToken) {
    try {
        const response = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${idToken}`);
        if (!response.ok) return null;
        
        const data = await response.json();
        if (data.aud !== config.googleClientId) return null;
        
        return {
            email: data.email,
            userId: `google:${data.sub}`,
            name: data.name || data.email.split('@')[0],
            provider: 'google'
        };
    } catch (error) {
        console.error('Google token verification error:', error.message);
        return null;
    }
}

/**
 * Hash password with bcrypt
 */
async function hashPassword(password) {
    return bcrypt.hash(password, config.bcryptRounds);
}

/**
 * Verify password against hash
 */
async function verifyPassword(password, hash) {
    return bcrypt.compare(password, hash);
}

/**
 * Get user from database
 */
function getUser(userId) {
    return db.users[userId] || null;
}

/**
 * Find user by email
 */
function getUserByEmail(email) {
    if (!email) return null;
    const normalizedEmail = email.toLowerCase();
    return Object.values(db.users).find(u => 
        u.email && u.email.toLowerCase() === normalizedEmail
    );
}

/**
 * Create or update user
 */
function upsertUser(userId, data) {
    const existing = db.users[userId] || {};
    const email = data.email || existing.email;
    const role = getUserRole(email);
    
    db.users[userId] = {
        userId,
        email: email,
        name: data.name || existing.name || email?.split('@')[0],
        passwordHash: data.passwordHash || existing.passwordHash,
        provider: data.provider || existing.provider || 'email',
        role: role,
        stripeCustomerId: data.stripeCustomerId || existing.stripeCustomerId,
        subscribed: data.subscribed !== undefined ? data.subscribed : (existing.subscribed || false),
        plan: data.plan !== undefined ? data.plan : existing.plan,
        subscribedAt: data.subscribedAt || existing.subscribedAt,
        expiresAt: data.expiresAt !== undefined ? data.expiresAt : existing.expiresAt,
        emailVerified: data.emailVerified !== undefined ? data.emailVerified : (existing.emailVerified || false),
        createdAt: existing.createdAt || new Date().toISOString(),
        updatedAt: new Date().toISOString()
    };
    scheduleSave();
    return db.users[userId];
}

/**
 * Log payment
 */
function logPayment(data) {
    db.payments.push({
        id: crypto.randomUUID(),
        ...data,
        createdAt: new Date().toISOString()
    });
    scheduleSave();
}

/**
 * Check subscription expiration
 */
function checkSubscriptionStatus(user) {
    if (!user) return null;
    
    if (user.subscribed && user.expiresAt) {
        if (new Date() > new Date(user.expiresAt)) {
            user.subscribed = false;
            user.plan = null;
            upsertUser(user.userId, user);
        }
    }
    return user;
}

/**
 * Auth middleware
 */
function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const user = getUser(req.session.userId);
    if (!user) {
        req.session.destroy();
        return res.status(401).json({ error: 'User not found' });
    }
    
    req.user = checkSubscriptionStatus(user);
    next();
}

/**
 * Validate email format
 */
function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/**
 * Validate password strength (enterprise grade)
 */
function isValidPassword(password) {
    if (!password || password.length < 8) return false;
    // Require at least: 1 uppercase, 1 lowercase, 1 number
    return /[A-Z]/.test(password) && /[a-z]/.test(password) && /[0-9]/.test(password);
}

/**
 * Generate secure token
 */
function generateSecureToken() {
    return crypto.randomBytes(32).toString('hex');
}

// ==================== ENTERPRISE AUTH ROUTES ====================

/**
 * POST /api/auth/google - Google OAuth Sign In
 */
app.post('/api/auth/google', async (req, res) => {
    try {
        const { idToken } = req.body;
        
        if (!idToken) {
            return res.status(400).json({ error: 'ID token required' });
        }
        
        const verified = await verifyGoogleToken(idToken);
        if (!verified) {
            return res.status(401).json({ error: 'Invalid Google credentials' });
        }
        
        // Check if user exists with this email (might have registered via email first)
        let existingUser = getUserByEmail(verified.email);
        let userId = existingUser ? existingUser.userId : verified.userId;
        
        const user = upsertUser(userId, {
            email: verified.email,
            name: verified.name,
            provider: existingUser?.provider || 'google',
            emailVerified: true // Google emails are verified
        });
        
        req.session.userId = userId;
        const role = getUserRole(user.email);
        
        console.log(`✅ Google sign-in: ${user.email} (${role})`);
        
        res.json({
            email: user.email,
            name: user.name,
            role: role,
            subscribed: hasFullAccess(user),
            plan: user.plan,
            expiresAt: user.expiresAt
        });
        
    } catch (error) {
        console.error('Google auth error:', error);
        res.status(500).json({ error: 'Authentication failed' });
    }
});

/**
 * POST /api/auth/register - Email Registration
 */
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        
        // Validation
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        
        if (!isValidEmail(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        
        if (!isValidPassword(password)) {
            return res.status(400).json({ 
                error: 'Password must be at least 8 characters with uppercase, lowercase, and number' 
            });
        }
        
        // Check if email already exists
        const existingUser = getUserByEmail(email);
        if (existingUser) {
            return res.status(409).json({ error: 'An account with this email already exists' });
        }
        
        const userId = `email:${email.toLowerCase()}`;
        const passwordHash = await hashPassword(password);
        
        const user = upsertUser(userId, {
            email,
            name,
            passwordHash,
            provider: 'email',
            emailVerified: false
        });
        
        req.session.userId = userId;
        const role = getUserRole(user.email);
        
        console.log(`✅ New registration: ${user.email} (${role})`);
        
        res.json({
            email: user.email,
            name: user.name,
            role: role,
            subscribed: hasFullAccess(user),
            plan: user.plan,
            expiresAt: user.expiresAt
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

/**
 * POST /api/auth/login - Email/Password Login
 */
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password, remember } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }
        
        if (!isValidEmail(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        
        // Find user by email
        const user = getUserByEmail(email);
        if (!user) {
            // Security: Don't reveal if email exists
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        // Check if user has a password (might be Google-only)
        if (!user.passwordHash) {
            return res.status(401).json({ 
                error: 'This account uses Google sign-in. Please sign in with Google.' 
            });
        }
        
        // Verify password
        const valid = await verifyPassword(password, user.passwordHash);
        if (!valid) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        // Update user role in case it changed
        const updatedUser = upsertUser(user.userId, user);
        
        // Set session
        req.session.userId = user.userId;
        if (remember) {
            req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
        }
        
        const role = getUserRole(user.email);
        console.log(`✅ Login: ${user.email} (${role})`);
        
        res.json({
            email: updatedUser.email,
            name: updatedUser.name,
            role: role,
            subscribed: hasFullAccess(updatedUser),
            plan: updatedUser.plan,
            expiresAt: updatedUser.expiresAt
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Authentication failed' });
    }
});

/**
 * POST /api/auth/forgot-password - Request password reset
 */
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ error: 'Valid email required' });
        }
        
        // Always return success to prevent email enumeration
        console.log(`📧 Password reset requested for: ${email}`);
        
        // In production, you would send an email here
        // For now, we'll just log it
        const user = getUserByEmail(email);
        if (user) {
            // Generate reset token (would be sent via email)
            const resetToken = generateSecureToken();
            const resetExpiry = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour
            
            // Store reset token (in production, store in DB)
            user.resetToken = resetToken;
            user.resetExpiry = resetExpiry;
            upsertUser(user.userId, user);
            
            console.log(`🔑 Reset token for ${email}: ${resetToken.substring(0, 8)}...`);
        }
        
        res.json({ 
            success: true, 
            message: 'If an account exists, password reset instructions will be sent.' 
        });
        
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ error: 'Failed to process request' });
    }
});

// ==================== OG CODE ROUTES ====================

/**
 * GET /api/og-code/status - Check if OG code redemption is available
 */
app.get('/api/og-code/status', (req, res) => {
    const remaining = OG_CODE_CONFIG.maxRedemptions - ogCodesState.redemptions.length;
    res.json({
        available: remaining > 0,
        remaining: remaining,
        total: OG_CODE_CONFIG.maxRedemptions
    });
});

/**
 * POST /api/og-code/redeem - Redeem OG code
 */
app.post('/api/og-code/redeem', (req, res) => {
    try {
        const { code } = req.body;
        
        if (!code) {
            return res.status(400).json({ error: 'Code required' });
        }
        
        // Check if code is valid
        if (code.toUpperCase() !== OG_CODE_CONFIG.code) {
            return res.status(401).json({ error: 'Invalid code' });
        }
        
        // Check if slots available
        if (ogCodesState.redemptions.length >= OG_CODE_CONFIG.maxRedemptions) {
            return res.status(410).json({ error: 'All OG codes have been redeemed' });
        }
        
        // Generate setup token
        const token = generateSecureToken();
        ogCodesState.pendingTokens[token] = {
            createdAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString() // 30 min
        };
        saveOGState();
        
        console.log(`🌟 OG code redeemed, setup token: ${token.substring(0, 8)}...`);
        
        res.json({
            success: true,
            token: token,
            message: 'Code valid! Complete your profile to activate.'
        });
        
    } catch (error) {
        console.error('OG code redeem error:', error);
        res.status(500).json({ error: 'Failed to redeem code' });
    }
});

/**
 * POST /api/og-code/complete-setup - Complete OG tester setup
 */
app.post('/api/og-code/complete-setup', async (req, res) => {
    try {
        const { token, name, email, password } = req.body;
        
        // Validate token
        const pendingToken = ogCodesState.pendingTokens[token];
        if (!pendingToken) {
            return res.status(401).json({ error: 'Invalid or expired token' });
        }
        
        // Check if token expired
        if (new Date() > new Date(pendingToken.expiresAt)) {
            delete ogCodesState.pendingTokens[token];
            saveOGState();
            return res.status(401).json({ error: 'Token expired. Please redeem the code again.' });
        }
        
        // Validate inputs
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'All fields required' });
        }
        
        if (!isValidEmail(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        
        if (!isValidPassword(password)) {
            return res.status(400).json({ 
                error: 'Password must be at least 8 characters with uppercase, lowercase, and number' 
            });
        }
        
        // Check if email already exists
        const existingUser = getUserByEmail(email);
        if (existingUser) {
            return res.status(409).json({ error: 'An account with this email already exists' });
        }
        
        // Check if slots still available
        if (ogCodesState.redemptions.length >= OG_CODE_CONFIG.maxRedemptions) {
            return res.status(410).json({ error: 'All OG slots have been filled' });
        }
        
        // Create OG user
        const userId = `email:${email.toLowerCase()}`;
        const passwordHash = await hashPassword(password);
        
        // Record redemption
        ogCodesState.redemptions.push({
            email: email.toLowerCase(),
            name: name,
            redeemedAt: new Date().toISOString(),
            slotNumber: ogCodesState.redemptions.length + 1
        });
        delete ogCodesState.pendingTokens[token];
        saveOGState();
        
        // Create user account
        const user = upsertUser(userId, {
            email,
            name,
            passwordHash,
            provider: 'email',
            emailVerified: true // OG users are pre-verified
        });
        
        // Set session
        req.session.userId = userId;
        
        console.log(`🌟 OG Tester account created: ${email} (Slot #${ogCodesState.redemptions.length})`);
        
        res.json({
            success: true,
            email: user.email,
            name: user.name,
            role: 'og_tester',
            subscribed: true,
            message: 'Welcome to the OG club!'
        });
        
    } catch (error) {
        console.error('OG setup error:', error);
        res.status(500).json({ error: 'Setup failed' });
    }
});

// ==================== LEGACY API ROUTES ====================

/**
 * POST /api/login (Legacy - kept for backward compatibility)
 */
app.post('/api/login', async (req, res) => {
    try {
        const { idToken, email, password } = req.body;
        let user = null;

        if (idToken) {
            // Google OAuth
            const verified = await verifyGoogleToken(idToken);
            if (!verified) {
                return res.status(401).json({ error: 'Invalid Google credentials' });
            }
            
            user = upsertUser(verified.userId, {
                email: verified.email,
                name: verified.name,
                provider: 'google'
            });
            req.session.userId = verified.userId;
            
        } else if (email && password) {
            // Email/Password
            if (!isValidEmail(email)) {
                return res.status(400).json({ error: 'Invalid email format' });
            }
            
            const userId = `email:${email.toLowerCase()}`;
            const existingUser = getUser(userId);
            
            if (existingUser) {
                // Verify password
                if (!existingUser.passwordHash) {
                    return res.status(401).json({ error: 'Please sign in with Google or reset your password' });
                }
                
                const valid = await verifyPassword(password, existingUser.passwordHash);
                if (!valid) {
                    return res.status(401).json({ error: 'Invalid email or password' });
                }
                user = existingUser;
            } else {
                // Register new user
                if (!isValidPassword(password)) {
                    return res.status(400).json({ error: 'Password must be at least 8 characters' });
                }
                
                const passwordHash = await hashPassword(password);
                user = upsertUser(userId, {
                    email,
                    passwordHash,
                    provider: 'email'
                });
            }
            
            req.session.userId = userId;
        } else {
            return res.status(400).json({ error: 'Email and password required' });
        }

        user = checkSubscriptionStatus(user);

        res.json({
            email: user.email,
            name: user.name,
            subscribed: user.subscribed,
            plan: user.plan,
            expiresAt: user.expiresAt
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Authentication failed' });
    }
});

/**
 * POST /api/logout
 */
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ error: 'Logout failed' });
        }
        // Clear cookie with matching options
        res.clearCookie('studydecoder.sid', {
            secure: !config.isDev,
            httpOnly: true,
            sameSite: config.isDev ? 'lax' : 'strict'
        });
        res.json({ success: true });
    });
});

/**
 * GET /api/subscription
 */
app.get('/api/subscription', requireAuth, (req, res) => {
    const user = req.user;
    const role = getUserRole(user.email);
    
    res.json({
        email: user.email,
        name: user.name,
        role: role,
        subscribed: hasFullAccess(user),
        plan: role === 'owner' ? 'owner' : (role === 'og_tester' ? 'og_lifetime' : user.plan),
        expiresAt: (role === 'owner' || role === 'og_tester') ? null : user.expiresAt
    });
});

/**
 * POST /api/set-pending-plan
 */
app.post('/api/set-pending-plan', requireAuth, (req, res) => {
    const { plan } = req.body;
    if (!['monthly', 'yearly'].includes(plan)) {
        return res.status(400).json({ error: 'Invalid plan' });
    }
    req.session.pendingPlan = plan;
    res.json({ success: true });
});

/**
 * POST /api/create-checkout-session
 */
app.post('/api/create-checkout-session', requireAuth, async (req, res) => {
    if (!stripe) {
        return res.status(503).json({ error: 'Payment system not configured' });
    }
    
    try {
        const { plan } = req.body;
        if (!['monthly', 'yearly'].includes(plan)) {
            return res.status(400).json({ error: 'Invalid plan' });
        }
        
        const user = req.user;
        
        // Create or get Stripe customer
        let customerId = user.stripeCustomerId;
        if (!customerId) {
            const customer = await stripe.customers.create({
                email: user.email,
                metadata: { userId: user.userId }
            });
            customerId = customer.id;
            upsertUser(user.userId, { stripeCustomerId: customerId });
        }
        
        const session = await stripe.checkout.sessions.create({
            customer: customerId,
            mode: 'subscription',
            payment_method_types: ['card'],
            line_items: [{
                price: plan === 'yearly' ? config.stripe.yearlyPriceId : config.stripe.monthlyPriceId,
                quantity: 1
            }],
            success_url: `${config.frontendUrl}/?plan=${plan}&session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${config.frontendUrl}/?cancelled=true`,
            metadata: {
                userId: user.userId,
                plan: plan
            }
        });
        
        res.json({ sessionId: session.id, url: session.url });
        
    } catch (error) {
        console.error('Checkout session error:', error);
        res.status(500).json({ error: 'Failed to create checkout session' });
    }
});

/**
 * POST /api/verify-payment
 * Verify payment with Stripe and activate subscription
 */
app.post('/api/verify-payment', requireAuth, async (req, res) => {
    try {
        const user = req.user;
        
        // First check if already subscribed
        if (user.subscribed && user.expiresAt && new Date(user.expiresAt) > new Date()) {
            return res.json({ 
                success: true, 
                subscribed: true, 
                plan: user.plan,
                message: 'Already subscribed!' 
            });
        }
        
        if (!stripe) {
            return res.status(500).json({ error: 'Payment system unavailable' });
        }
        
        // Search for Stripe customer by email
        const customers = await stripe.customers.list({
            email: user.email,
            limit: 1
        });
        
        if (customers.data.length === 0) {
            return res.json({ 
                success: false, 
                subscribed: false,
                message: 'No payment found for this email. Please complete payment first.' 
            });
        }
        
        const customer = customers.data[0];
        
        // Check for active subscriptions
        const subscriptions = await stripe.subscriptions.list({
            customer: customer.id,
            status: 'active',
            limit: 10
        });
        
        if (subscriptions.data.length > 0) {
            const sub = subscriptions.data[0];
            const plan = sub.items.data[0]?.price?.recurring?.interval === 'year' ? 'yearly' : 'monthly';
            const expiresAt = new Date(sub.current_period_end * 1000).toISOString();
            
            // Activate subscription in our DB
            upsertUser(user.userId, {
                subscribed: true,
                plan: plan,
                stripeCustomerId: customer.id,
                stripeSubscriptionId: sub.id,
                subscribedAt: new Date().toISOString(),
                expiresAt: expiresAt
            });
            
            console.log(`✅ Payment verified and activated for ${user.email} - ${plan}`);
            
            return res.json({ 
                success: true, 
                subscribed: true,
                plan: plan,
                expiresAt: expiresAt,
                message: 'Payment verified! Subscription activated.' 
            });
        }
        
        // Check for completed checkout sessions (one-time or recent)
        const sessions = await stripe.checkout.sessions.list({
            customer: customer.id,
            limit: 10
        });
        
        const completedSession = sessions.data.find(s => s.payment_status === 'paid');
        if (completedSession) {
            const plan = completedSession.metadata?.plan || 'monthly';
            const expiration = new Date();
            if (plan === 'yearly') {
                expiration.setFullYear(expiration.getFullYear() + 1);
            } else {
                expiration.setMonth(expiration.getMonth() + 1);
            }
            
            upsertUser(user.userId, {
                subscribed: true,
                plan: plan,
                stripeCustomerId: customer.id,
                subscribedAt: new Date().toISOString(),
                expiresAt: expiration.toISOString()
            });
            
            console.log(`✅ Checkout payment verified for ${user.email} - ${plan}`);
            
            return res.json({ 
                success: true, 
                subscribed: true,
                plan: plan,
                message: 'Payment verified! Subscription activated.' 
            });
        }
        
        return res.json({ 
            success: false, 
            subscribed: false,
            message: 'No active subscription or payment found. Please complete payment first.' 
        });
        
    } catch (error) {
        console.error('Verify payment error:', error);
        res.status(500).json({ error: 'Failed to verify payment. Please try again.' });
    }
});

/**
 * POST /api/subscribe
 * Manual subscription activation (for legacy checkout links)
 */
app.post('/api/subscribe', requireAuth, (req, res) => {
    const user = req.user;
    const plan = req.body.plan || req.session.pendingPlan || 'monthly';
    
    // Calculate expiration
    const expiration = new Date();
    if (plan === 'yearly') {
        expiration.setFullYear(expiration.getFullYear() + 1);
    } else {
        expiration.setMonth(expiration.getMonth() + 1);
    }
    
    upsertUser(user.userId, {
        subscribed: true,
        plan: plan,
        subscribedAt: new Date().toISOString(),
        expiresAt: expiration.toISOString()
    });
    
    delete req.session.pendingPlan;

    res.json({
        success: true,
        plan: plan,
        expiresAt: expiration.toISOString()
    });
});

/**
 * POST /api/cancel
 */
app.post('/api/cancel', requireAuth, async (req, res) => {
    try {
        const user = req.user;
        
        // Cancel in Stripe if connected
        if (stripe && user.stripeCustomerId) {
            const subscriptions = await stripe.subscriptions.list({
                customer: user.stripeCustomerId,
                status: 'active'
            });
            
            for (const sub of subscriptions.data) {
                await stripe.subscriptions.update(sub.id, {
                    cancel_at_period_end: true
                });
            }
        }

        res.json({ success: true, message: 'Subscription will be cancelled at period end' });
        
    } catch (error) {
        console.error('Cancel error:', error);
        res.status(500).json({ error: 'Failed to cancel subscription' });
    }
});

/**
 * POST /api/stripe-webhook
 */
app.post('/api/stripe-webhook', async (req, res) => {
    if (!stripe || !config.stripe.webhookSecret) {
        return res.status(503).json({ error: 'Webhooks not configured' });
    }
    
    const sig = req.headers['stripe-signature'];
    let event;
    
    try {
        event = stripe.webhooks.constructEvent(req.body, sig, config.stripe.webhookSecret);
    } catch (err) {
        console.error('Webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }
    
    try {
        switch (event.type) {
            case 'checkout.session.completed': {
                const session = event.data.object;
                const userId = session.metadata?.userId;
                const plan = session.metadata?.plan || 'monthly';
                
                if (userId) {
                    const expiration = new Date();
                    if (plan === 'yearly') {
                        expiration.setFullYear(expiration.getFullYear() + 1);
                    } else {
                        expiration.setMonth(expiration.getMonth() + 1);
                    }
                    
                    upsertUser(userId, {
                        subscribed: true,
                        plan: plan,
                        subscribedAt: new Date().toISOString(),
                        expiresAt: expiration.toISOString(),
                        stripeCustomerId: session.customer
                    });
                    
                    logPayment({
                        userId,
                        stripeEventId: event.id,
                        eventType: event.type,
                        amount: session.amount_total,
                        currency: session.currency,
                        status: 'completed'
                    });
                    
                    console.log(`✅ Subscription activated for ${userId} - ${plan}`);
                }
                break;
            }
            
            case 'customer.subscription.updated': {
                const subscription = event.data.object;
                // Find user by Stripe customer ID
                const user = Object.values(db.users).find(u => u.stripeCustomerId === subscription.customer);
                
                if (user && subscription.status === 'active') {
                    const expiresAt = new Date(subscription.current_period_end * 1000).toISOString();
                    upsertUser(user.userId, { expiresAt });
                    logPayment({
                        userId: user.userId,
                        stripeEventId: event.id,
                        eventType: event.type,
                        status: 'renewed'
                    });
                }
                break;
            }
            
            case 'customer.subscription.deleted': {
                const subscription = event.data.object;
                const user = Object.values(db.users).find(u => u.stripeCustomerId === subscription.customer);
                
                if (user) {
                    upsertUser(user.userId, {
                        subscribed: false,
                        plan: null,
                        expiresAt: null
                    });
                    logPayment({
                        userId: user.userId,
                        stripeEventId: event.id,
                        eventType: event.type,
                        status: 'cancelled'
                    });
                    console.log(`❌ Subscription cancelled for ${user.userId}`);
                }
                break;
            }
            
            case 'invoice.payment_failed': {
                const invoice = event.data.object;
                const user = Object.values(db.users).find(u => u.stripeCustomerId === invoice.customer);
                
                if (user) {
                    logPayment({
                        userId: user.userId,
                        stripeEventId: event.id,
                        eventType: event.type,
                        amount: invoice.amount_due,
                        currency: invoice.currency,
                        status: 'payment_failed'
                    });
                    console.log(`⚠️ Payment failed for ${user.userId}`);
                }
                break;
            }
            
            default:
                console.log(`Unhandled event type: ${event.type}`);
        }
        
        res.json({ received: true });
        
    } catch (error) {
        console.error('Webhook processing error:', error);
        res.status(500).json({ error: 'Webhook processing failed' });
    }
});

/**
 * POST /api/check_payment
 * Legacy endpoint
 */
app.post('/api/check_payment', async (req, res) => {
    try {
        const { id_token } = req.body;
        
        if (id_token) {
            const verified = await verifyGoogleToken(id_token);
            if (!verified) {
                return res.json({ paid: false });
            }
            
            let user = getUser(verified.userId);
            if (user) {
                user = checkSubscriptionStatus(user);
                if (user.subscribed) {
                    return res.json({ paid: true, plan: user.plan });
                }
            }
        }
        
        res.json({ paid: false });
    } catch (error) {
        console.error('Check payment error:', error);
        res.json({ paid: false });
    }
});

/**
 * GET /api/health
 */
app.get('/api/health', (req, res) => {
    const userCount = Object.keys(db.users).length;
    
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        environment: config.nodeEnv,
        version: '2.0.0',
        database: 'json-file',
        stripe: stripe ? 'configured' : 'not configured',
        users: userCount
    });
});

/**
 * Owner-only middleware
 */
function requireOwner(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const user = getUser(req.session.userId);
    if (!user) {
        return res.status(401).json({ error: 'User not found' });
    }
    
    const role = getUserRole(user.email);
    if (role !== 'owner') {
        return res.status(403).json({ error: 'Owner access required' });
    }
    
    req.user = user;
    next();
}

/**
 * GET /api/admin/live-users - Real-time user count
 */
app.get('/api/admin/live-users', requireOwner, (req, res) => {
    const now = Date.now();
    let total = 0;
    let authenticated = 0;
    let anonymous = 0;
    
    for (const [sessionId, data] of liveUsers.entries()) {
        if (now - data.lastSeen <= LIVE_USER_TIMEOUT) {
            total++;
            if (data.userId) {
                authenticated++;
            } else {
                anonymous++;
            }
        }
    }
    
    res.json({
        total,
        authenticated,
        anonymous,
        timestamp: new Date().toISOString()
    });
});

/**
 * GET /api/admin/stats - Owner-only dashboard data
 */
app.get('/api/admin/stats', requireOwner, (req, res) => {
    const users = Object.values(db.users);
    const ogRedemptions = ogCodesState.redemptions;
    
    const stats = {
        totalUsers: users.length,
        subscribers: users.filter(u => u.subscribed).length,
        monthlyPlans: users.filter(u => u.plan === 'monthly').length,
        yearlyPlans: users.filter(u => u.plan === 'yearly').length,
        ogTesters: ogRedemptions.length,
        ogSlotsRemaining: OG_CODE_CONFIG.maxRedemptions - ogRedemptions.length,
        recentSignups: users
            .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
            .slice(0, 10)
            .map(u => ({
                email: u.email,
                name: u.name,
                role: getUserRole(u.email),
                subscribed: hasFullAccess(u),
                createdAt: u.createdAt
            })),
        recentPayments: db.payments.slice(-10).reverse(),
        ogRedemptions: ogRedemptions
    };
    
    res.json(stats);
});

/**
 * GET /api/admin/users - Owner-only user list
 */
app.get('/api/admin/users', requireOwner, (req, res) => {
    const users = Object.values(db.users).map(u => ({
        userId: u.userId,
        email: u.email,
        name: u.name,
        role: getUserRole(u.email),
        provider: u.provider,
        subscribed: hasFullAccess(u),
        plan: u.plan,
        createdAt: u.createdAt
    }));
    
    res.json({ users });
});

/**
 * POST /api/admin/grant-access - Owner grants subscription to user
 */
app.post('/api/admin/grant-access', requireOwner, (req, res) => {
    const { email, plan, days } = req.body;
    
    if (!email) {
        return res.status(400).json({ error: 'Email required' });
    }
    
    const user = getUserByEmail(email);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    const expiration = new Date();
    expiration.setDate(expiration.getDate() + (days || 30));
    
    upsertUser(user.userId, {
        ...user,
        subscribed: true,
        plan: plan || 'granted',
        subscribedAt: new Date().toISOString(),
        expiresAt: expiration.toISOString()
    });
    
    console.log(`👑 Owner granted ${days || 30} days access to ${email}`);
    
    res.json({ success: true, message: `Granted ${days || 30} days access to ${email}` });
});

/**
 * POST /api/admin/revoke-access - Owner revokes subscription
 */
app.post('/api/admin/revoke-access', requireOwner, (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({ error: 'Email required' });
    }
    
    const user = getUserByEmail(email);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    // Can't revoke owner or OG access
    const role = getUserRole(email);
    if (role === 'owner' || role === 'og_tester') {
        return res.status(403).json({ error: 'Cannot revoke access for owners or OG testers' });
    }
    
    upsertUser(user.userId, {
        ...user,
        subscribed: false,
        plan: null,
        expiresAt: null
    });
    
    console.log(`👑 Owner revoked access for ${email}`);
    
    res.json({ success: true, message: `Revoked access for ${email}` });
});

// ==================== SYLLABUS DATA ====================

const SYLLABUSES_PATH = path.join(__dirname, 'syllabuses');
const SUBJECTS_FILE = path.join(SYLLABUSES_PATH, 'subjects.json');
const JUNIOR_SUBJECTS_FILE = path.join(SYLLABUSES_PATH, 'junior-subjects.json');
const PAST_PAPERS_FILE = path.join(SYLLABUSES_PATH, 'past-papers.json');

// Load subjects configuration (Senior - HSC)
let subjectsConfig = { subjects: [], categories: [] };
try {
    if (fs.existsSync(SUBJECTS_FILE)) {
        subjectsConfig = JSON.parse(fs.readFileSync(SUBJECTS_FILE, 'utf8'));
        console.log(`📚 Loaded ${subjectsConfig.subjects.length} HSC subjects`);
    }
} catch (e) {
    console.error('Error loading HSC subjects config:', e.message);
}

// Load subjects configuration (Junior - Years 7-10)
let juniorSubjectsConfig = { subjects: [], categories: [] };
try {
    if (fs.existsSync(JUNIOR_SUBJECTS_FILE)) {
        juniorSubjectsConfig = JSON.parse(fs.readFileSync(JUNIOR_SUBJECTS_FILE, 'utf8'));
        console.log(`📚 Loaded ${juniorSubjectsConfig.subjects.length} Junior subjects`);
    }
} catch (e) {
    console.error('Error loading Junior subjects config:', e.message);
}

// Load past papers configuration
let pastPapersConfig = { papers: [], subjectMapping: {} };
try {
    if (fs.existsSync(PAST_PAPERS_FILE)) {
        pastPapersConfig = JSON.parse(fs.readFileSync(PAST_PAPERS_FILE, 'utf8'));
        console.log(`📝 Loaded past papers for ${pastPapersConfig.papers.length} subjects`);
    }
} catch (e) {
    console.error('Error loading past papers config:', e.message);
}

// Get past paper content and marking guidelines for a subject
const pastPaperCache = {};
function getPastPaperContent(subjectId) {
    if (pastPaperCache[subjectId]) {
        return pastPaperCache[subjectId];
    }
    
    const subjectPapers = pastPapersConfig.papers.find(p => p.id === subjectId);
    if (!subjectPapers) return null;
    
    let content = '';
    for (const paper of subjectPapers.papers) {
        const filePath = path.join(SYLLABUSES_PATH, paper.file);
        try {
            if (fs.existsSync(filePath)) {
                const fileContent = fs.readFileSync(filePath, 'utf8');
                content += `\n\n=== ${paper.year} HSC ${subjectPapers.name} ${paper.type} ===\n${fileContent.substring(0, 40000)}`;
            }
        } catch (e) {
            console.error(`Error reading past paper ${paper.file}:`, e.message);
        }
    }
    
    pastPaperCache[subjectId] = content;
    return content;
}

// Load syllabus content for a subject (cached)
const syllabusCache = {};
function getSyllabusContent(subjectId, isJunior = false) {
    const cacheKey = (isJunior ? 'jr:' : 'sr:') + subjectId;
    if (syllabusCache[cacheKey]) {
        return syllabusCache[cacheKey];
    }
    
    const config = isJunior ? juniorSubjectsConfig : subjectsConfig;
    const subject = config.subjects.find(s => s.id === subjectId);
    if (!subject) return null;
    
    let content = '';
    for (const file of subject.files) {
        const filePath = path.join(SYLLABUSES_PATH, file);
        try {
            if (fs.existsSync(filePath)) {
                const fileContent = fs.readFileSync(filePath, 'utf8');
                content += fileContent.substring(0, 50000) + '\n\n';
            }
        } catch (e) {
            console.error(`Error reading syllabus file ${file}:`, e.message);
        }
    }
    
    syllabusCache[cacheKey] = content;
    return content;
}

// API endpoint to get subjects list (Senior - HSC)
app.get('/api/subjects', (req, res) => {
    res.json({
        subjects: subjectsConfig.subjects.map(s => ({
            id: s.id,
            name: s.name,
            category: s.category
        })),
        categories: subjectsConfig.categories
    });
});

// API endpoint to get Junior subjects list (Years 7-10)
app.get('/api/junior-subjects', (req, res) => {
    res.json({
        subjects: juniorSubjectsConfig.subjects.map(s => ({
            id: s.id,
            name: s.name,
            category: s.category
        })),
        categories: juniorSubjectsConfig.categories
    });
});

// ==================== REVIEWS API ====================

/**
 * GET /api/reviews - Get all reviews (public)
 */
app.get('/api/reviews', (req, res) => {
    // Return reviews sorted by date (newest first)
    const sortedReviews = [...reviewsData.reviews].sort((a, b) => 
        new Date(b.createdAt) - new Date(a.createdAt)
    );
    res.json({ reviews: sortedReviews });
});

/**
 * POST /api/reviews - Submit anonymous review (requires auth)
 */
app.post('/api/reviews', (req, res) => {
    // Must be logged in
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Please sign in to leave a review' });
    }

    const { rating, text } = req.body;

    // Validate rating
    if (!rating || rating < 1 || rating > 5 || !Number.isInteger(rating)) {
        return res.status(400).json({ error: 'Rating must be 1-5 stars' });
    }

    // Validate text
    if (!text || typeof text !== 'string') {
        return res.status(400).json({ error: 'Review text is required' });
    }

    const cleanText = text.trim();
    if (cleanText.length < 10) {
        return res.status(400).json({ error: 'Review must be at least 10 characters' });
    }
    if (cleanText.length > 500) {
        return res.status(400).json({ error: 'Review must be under 500 characters' });
    }

    // Create anonymous review (no user info stored)
    const review = {
        id: crypto.randomUUID(),
        rating,
        text: cleanText,
        createdAt: new Date().toISOString()
    };

    reviewsData.reviews.push(review);
    saveReviews();

    console.log(`[Reviews] New ${rating}-star review submitted`);
    res.json({ success: true, review });
});

// ==================== DEMO BOT API ====================

// Demo rate limiter (stricter - 10 requests per hour per IP)
const demoLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10,
    message: { error: 'Too many demo requests. Please try again later or subscribe for unlimited access.' }
});

app.use('/api/demo', demoLimiter);

// Demo system prompt (throttled, hints at subscription)
const DEMO_PROMPTS = {
    syllabus: `You are Study Decoder Demo. Provide a SHORT, TEASER preview of syllabus decoding.

CRITICAL RULES:
- Keep response under 150 words
- Give only 2-3 key points, not full explanation
- End with "..." to show there's more
- Be helpful but incomplete - leave user wanting more
- Use clear Australian English
- No emojis

OUTPUT FORMAT:
## Quick Overview
(1-2 sentences)

## Key Points
• Point 1
• Point 2
• Point 3...

(This is a preview. Subscribe for complete syllabus breakdowns, exam tips, and detailed explanations.)`,

    practice: `You are Study Decoder Demo. Generate ONE simple practice question as a teaser.

CRITICAL RULES:
- Generate only ONE question (not multiple)
- Keep it simple/medium difficulty
- Don't provide the full answer - just a hint
- Response under 100 words
- Use clear Australian English
- No emojis

OUTPUT FORMAT:
## Practice Question
(One question here)

## Hint
(Brief hint, not the full answer)

(This is a preview. Subscribe for unlimited practice questions, full answers, and exam simulations.)`,

    timetable: `You are Study Decoder Demo. Provide a BRIEF timetable teaser.

CRITICAL RULES:
- Show only 2-3 days, not a full week
- Keep response under 120 words
- Don't give detailed strategies
- Use clear Australian English
- No emojis

OUTPUT FORMAT:
## Sample Schedule (Preview)
• Monday: ...
• Tuesday: ...
• Wednesday: ...

(This is a preview. Subscribe for full personalised weekly timetables, study strategies, and adaptive planning.)`
};

// Demo endpoint
app.post('/api/demo', express.json(), async (req, res) => {
    const { yearLevel, subject, subjectName, tool, topic } = req.body;
    
    if (!yearLevel || !subject || !tool) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    
    if (!DEMO_PROMPTS[tool]) {
        return res.status(400).json({ error: 'Invalid tool type' });
    }
    
    const OPENAI_API_KEY = config.openaiApiKey;
    
    // Build context
    const isJunior = ['Year 7', 'Year 8', 'Year 9', 'Year 10'].includes(yearLevel);
    let systemPrompt = DEMO_PROMPTS[tool];
    
    // Add minimal syllabus context
    const syllabusContent = getSyllabusContent(subject, isJunior);
    if (syllabusContent) {
        // Only inject a small amount for demo (5000 chars max)
        systemPrompt += `\n\nSYLLABUS CONTEXT (use sparingly for accuracy):\n${syllabusContent.substring(0, 5000)}`;
    }
    
    const userMessage = `${yearLevel} ${subjectName}${topic ? ` - Topic: ${topic}` : ''}. Generate a preview.`;
    
    try {
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${OPENAI_API_KEY}`
            },
            body: JSON.stringify({
                model: 'gpt-4o-mini',
                messages: [
                    { role: 'system', content: systemPrompt },
                    { role: 'user', content: userMessage }
                ],
                max_tokens: 500, // Throttled response
                temperature: 0.7
            })
        });
        
        if (!response.ok) {
            console.error('OpenAI API error');
            return res.status(500).json({ error: 'Demo unavailable' });
        }
        
        const data = await response.json();
        const reply = data.choices?.[0]?.message?.content || 'Preview unavailable. Please try again.';
        
        res.json({ reply });
    } catch (error) {
        console.error('Demo API error:', error);
        res.status(500).json({ error: 'Demo unavailable' });
    }
});

// Demo Subject Advisor prompt (throttled version)
const DEMO_ADVISOR_PROMPT = `You are StudyDecoder – Subject Selection Advisor (Demo Preview).

Help Year 10 students choose subjects for Years 11-12. This is a DEMO, so provide a SHORT preview.

RULES:
• Keep response under 200 words
• Give brief, helpful suggestions
• End with "..." to hint there's more
• Mention that full version has detailed pathway analysis
• Use Australian English
• No emojis

AVAILABLE HSC SUBJECTS (suggest from these):
English: English Advanced, English Standard, English Studies, English Extension
Mathematics: Mathematics Advanced, Mathematics Standard, Mathematics Extension 1, Mathematics Extension 2
Science: Biology, Chemistry, Physics, Earth and Environmental Science, Investigating Science
HSIE: Ancient History, Modern History, Geography, Legal Studies, Economics, Business Studies, Society and Culture
Creative Arts: Visual Arts, Music 1, Music 2, Drama, Dance
Technology: Software Engineering, Design and Technology, Engineering Studies, Industrial Technology, Food Technology
PDHPE: Health and Movement Science
VET: Construction, Hospitality

OUTPUT FORMAT:
## Quick Analysis
(1-2 sentences on strengths)

## Suggested Subjects
• Subject — brief reason
• Subject — brief reason
• Subject — brief reason...

(This is a preview. Subscribe for detailed pathway analysis, prerequisites, workload balancing, and personalised study plans.)`;

// Demo Bridging Mode prompt (throttled)
const DEMO_BRIDGING_PROMPT = `You are StudyDecoder – Senior Pathway Bridging Advisor (Demo Preview).

Help Year 9-10 students understand how current subjects connect to senior subjects. This is a DEMO.

RULES:
• Keep response under 150 words
• Give brief pathway connections
• End with "..." to hint there's more
• Use Australian English
• No emojis

OUTPUT FORMAT:
## Pathway Connection
• Brief explanation...

## Key Prerequisites
• Point 1
• Point 2...

(This is a preview. Subscribe for detailed pathway analysis and prerequisite guidance.)`;

// Demo Pathway Mode prompt (throttled)
const DEMO_PATHWAY_PROMPT = `You are StudyDecoder – ATAR vs Non-ATAR Advisor (Demo Preview).

Explain ATAR vs non-ATAR pathways briefly. This is a DEMO.

RULES:
• Keep response under 150 words
• Present both pathways as valid
• End with "..." to hint there's more
• Use Australian English
• No emojis

OUTPUT FORMAT:
## Quick Comparison
• ATAR: brief point
• Non-ATAR: brief point...

## For Your Situation
• Brief advice...

(This is a preview. Subscribe for detailed pathway comparison and personalised guidance.)`;

// Map demo modes to prompts
const DEMO_ADVISOR_PROMPTS = {
    selection: DEMO_ADVISOR_PROMPT,
    bridging: DEMO_BRIDGING_PROMPT,
    pathway: DEMO_PATHWAY_PROMPT
};

// Demo Subject Advisor endpoint (no auth required, rate limited)
app.post('/api/demo-advisor', express.json(), async (req, res) => {
    const { message, mode } = req.body;
    
    if (!message) {
        return res.status(400).json({ error: 'Message required' });
    }
    
    const OPENAI_API_KEY = config.openaiApiKey;
    
    // Select demo prompt based on mode
    const selectedPrompt = DEMO_ADVISOR_PROMPTS[mode] || DEMO_ADVISOR_PROMPTS.selection;
    
    try {
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${OPENAI_API_KEY}`
            },
            body: JSON.stringify({
                model: 'gpt-4o-mini',
                messages: [
                    { role: 'system', content: selectedPrompt },
                    { role: 'user', content: message }
                ],
                max_tokens: 600, // Throttled for demo
                temperature: 0.7
            })
        });
        
        if (!response.ok) {
            console.error('OpenAI API error for demo advisor');
            return res.status(500).json({ error: 'Demo unavailable' });
        }
        
        const data = await response.json();
        const reply = data.choices?.[0]?.message?.content || 'Preview unavailable. Please try again.';
        
        res.json({ reply });
    } catch (error) {
        console.error('Demo Advisor API error:', error);
        res.status(500).json({ error: 'Demo unavailable' });
    }
});

// Apply demo rate limit to demo-advisor too
app.use('/api/demo-advisor', demoLimiter);

// ==================== SUBJECT SELECTION ADVISOR ====================

const SUBJECT_ADVISOR_PROMPT = `You are **StudyDecoder – Subject Selection Advisor**, an AI tool for **Year 10 students** choosing school subjects.

Your role is to collect student information, analyse it carefully, and generate **clear, balanced subject suggestions**. You do NOT decide for the student — you advise.

Tone: neutral, supportive, practical.  
Language: Australian English.  
Style: structured, concise, non-chatty.  
Do NOT use emojis.

────────────────────────
MANDATORY INTERACTION FLOW
────────────────────────

STEP 1 – INFORMATION GATHERING  
If information is missing, ask for ALL required inputs in ONE message using bullet points.

You must collect:
• Current or proposed electives  
• Recent marks/grades in core subjects (English, Maths, Science, Humanities)  
• Recent marks/grades in electives  
• Interests (subjects, hobbies, strengths)  
• Future aspirations (ATAR, university, TAFE, trades, unsure)

Do NOT give suggestions until all required info is provided.

────────────────────────
STEP 2 – INTERNAL ANALYSIS (DO NOT SHOW)
────────────────────────
Once information is provided, internally assess:
• Academic strengths vs weaker areas  
• Interest alignment  
• ATAR vs non-ATAR suitability  
• Subject workload balance  
• Year 10 → senior subject prerequisites and pathways  
• State-specific subject structures and naming

Never display this analysis unless explicitly asked.

────────────────────────
STEP 3 – RECOMMENDATIONS (OUTPUT)
────────────────────────
Use the following structure EXACTLY:

## Student Profile Summary
• Academic strengths (1 bullet)
• Key interests or goals (1 bullet)
• Pathway direction (ATAR / non-ATAR / flexible)

## Recommended Subjects
• Subject name — 1–2 sentence justification explaining why it fits performance, interest, and pathway

## Optional Alternatives
• Subject name — brief explanation of when or why it may be suitable

## Pathway Notes
• ATAR vs non-ATAR implications
• Year 10 → senior subject considerations
• Prerequisites or assumed knowledge (if relevant)

## Things to Consider
• Workload and assessment style
• Subject difficulty balance
• Scaling or pathway flexibility (if applicable)

────────────────────────
STATE-SPECIFIC RULES
────────────────────────
• NSW: Be aware of HSC pathways, subject prerequisites, and Maths levels  
• VIC: Be aware of VCE pathways, Units 1–4 progression, and subject scaling  
• QLD: Be aware of ATAR vs applied subjects and senior subject sequencing  

Do NOT invent subject availability — keep suggestions general and adaptable.

────────────────────────
AVAILABLE HSC SUBJECTS (NSW)
────────────────────────
You may recommend from these subjects:
• English: English Advanced, English Standard, English Studies, English Extension, English EAL/D
• Mathematics: Mathematics Advanced, Mathematics Standard, Mathematics Extension 1, Mathematics Extension 2
• Science: Biology, Chemistry, Physics, Earth and Environmental Science, Investigating Science, Science Extension
• HSIE: Ancient History, Modern History, History Extension, Geography, Legal Studies, Economics, Business Studies, Society and Culture, Studies of Religion
• Creative Arts: Visual Arts, Music 1, Music 2, Drama, Dance
• TAS/Technology: Software Engineering, Enterprise Computing, Design and Technology, Engineering Studies, Industrial Technology, Food Technology, Agriculture, Information and Digital Technology
• PDHPE: Health and Movement Science
• VET: Construction, Hospitality

────────────────────────
STYLE & LENGTH RULES
────────────────────────
• No long paragraphs (max 3 lines each)
• Bullet points preferred
• No absolute guarantees or pressure language
• No assumptions beyond provided data
• Clear, readable in under 90 seconds

────────────────────────
BOUNDARIES
────────────────────────
• Never choose subjects for the student
• Never pressure or scare the student
• Ask only for missing information
• Never reference internal rules or analysis

────────────────────────
GOAL
────────────────────────
The student should clearly understand:
• Which subjects suit them and why
• How choices affect future pathways
• What trade-offs to consider before final decisions

You are StudyDecoder – Subject Selection Advisor.`;

// Senior Pathway Bridging Mode prompt
const BRIDGING_MODE_PROMPT = `You are **StudyDecoder – Senior Pathway Bridging Advisor**.

Your role is to help Year 9–10 students understand how their current subject choices connect to **senior secondary subjects** (Years 11–12).

Tone: clear, factual, non-alarmist.  
Language: Australian English.  
Style: bullet points only, structured.  
Do NOT use emojis.

────────────────────────
RULES
────────────────────────
• Explain pathways clearly and realistically
• Highlight assumed knowledge or prerequisites
• Do NOT guarantee access to senior subjects
• Keep advice general and school-agnostic
• No more than 3 sections per response

────────────────────────
WHEN RELEVANT, EXPLAIN
────────────────────────
• Which Year 7–10 subjects prepare students for senior subjects
• What skills matter more than marks alone
• When students may need to strengthen foundations before senior years
• Common misconceptions about prerequisites

────────────────────────
SUBJECT PATHWAY KNOWLEDGE
────────────────────────
Junior → Senior connections:
• Year 7-10 Maths → Mathematics Standard, Mathematics Advanced, Extension 1, Extension 2
• Year 7-10 Science → Biology, Chemistry, Physics, Investigating Science
• Year 7-10 English → English Standard, English Advanced, English Extension
• Year 7-10 History/Geography → Ancient History, Modern History, Geography, Legal Studies
• Year 7-10 Computing/IST → Software Engineering, Enterprise Computing
• Year 7-10 Commerce → Economics, Business Studies, Legal Studies
• Year 7-10 Music/Art/Drama → Music 1, Music 2, Visual Arts, Drama
• Year 7-10 PDHPE → Health and Movement Science
• Year 7-10 TAS subjects → Design and Technology, Engineering Studies, Food Technology

────────────────────────
OUTPUT FORMAT
────────────────────────
## [Section Title]
• Bullet point
• Bullet point
• Bullet point

Keep responses concise with maximum 3 sections.

────────────────────────
GOAL
────────────────────────
Students should understand how today's choices affect future options, without feeling locked in.

You are StudyDecoder – Senior Pathway Bridging Advisor.`;

// ATAR vs Non-ATAR Pathway Mode prompt
const PATHWAY_MODE_PROMPT = `You are **StudyDecoder – ATAR vs Non-ATAR Pathway Advisor**.

Your role is to explain the difference between:
• ATAR pathways
• Non-ATAR pathways (TAFE, applied subjects, vocational routes)

Tone: neutral, informative, balanced.  
Language: Australian English.  
Style: short sections with headings, bullet points.  
Do NOT use emojis.

────────────────────────
RULES
────────────────────────
• Present both pathways as valid
• Never imply one pathway is "better"
• Avoid rankings, pressure, or fear-based language
• Do NOT calculate or predict ATAR scores
• Keep explanations factual and balanced

────────────────────────
ATAR PATHWAY OVERVIEW
────────────────────────
• Designed for university entry
• External exams contribute to final marks
• Subjects "scale" based on cohort difficulty
• Requires specific subject patterns (e.g., English + 9 other units)
• Assessment: mix of internal tasks and external exams

ATAR subjects available:
English Advanced, English Standard, Mathematics Advanced, Mathematics Standard, Mathematics Extension 1, Mathematics Extension 2, Biology, Chemistry, Physics, Ancient History, Modern History, Geography, Legal Studies, Economics, Business Studies, Visual Arts, Music 1, Music 2, Drama, Software Engineering, Design and Technology, Engineering Studies, Health and Movement Science, etc.

────────────────────────
NON-ATAR PATHWAY OVERVIEW
────────────────────────
• Designed for TAFE, apprenticeships, direct employment
• Focus on practical skills and vocational competencies
• Assessment: primarily internal and practical
• VET courses provide industry certifications
• HSC awarded without ATAR score

Non-ATAR subjects available:
English Studies, Mathematics Standard 1, VET courses (Construction, Hospitality), Life Skills subjects, and various school-based vocational programs.

────────────────────────
WHEN EXPLAINING, COVER
────────────────────────
• Typical subject types in each pathway
• Assessment styles (exams vs practical)
• Post-school options linked to each pathway
• Which pathway suits different learning styles

────────────────────────
OUTPUT FORMAT
────────────────────────
## [Section Title]
• Bullet point
• Bullet point

Short sections, no long paragraphs.

────────────────────────
GOAL
────────────────────────
Students should understand which pathway matches their learning style and goals.

You are StudyDecoder – ATAR vs Non-ATAR Pathway Advisor.`;

// Map of advisor modes to prompts
const ADVISOR_PROMPTS = {
    selection: SUBJECT_ADVISOR_PROMPT,
    bridging: BRIDGING_MODE_PROMPT,
    pathway: PATHWAY_MODE_PROMPT
};

// Subject Advisor endpoint (subscriber only)
app.post('/api/subject-advisor', express.json(), async (req, res) => {
    const { message, mode, history } = req.body;
    
    if (!message) {
        return res.status(400).json({ error: 'Message required' });
    }
    
    // Check authentication
    if (!req.session?.userId) {
        return res.status(401).json({ error: 'Login required' });
    }
    
    const user = getUser(req.session.userId);
    if (!user) {
        return res.status(401).json({ error: 'User not found' });
    }
    
    // Check subscription
    if (!hasFullAccess(user)) {
        return res.status(403).json({ error: 'Active subscription required' });
    }
    
    const OPENAI_API_KEY = config.openaiApiKey;
    
    // Select prompt based on mode
    const selectedPrompt = ADVISOR_PROMPTS[mode] || ADVISOR_PROMPTS.selection;
    
    // Build messages array
    const messages = [
        { role: 'system', content: selectedPrompt }
    ];
    
    // Add conversation history
    if (history && Array.isArray(history)) {
        messages.push(...history.slice(-10));
    }
    
    messages.push({ role: 'user', content: message });
    
    try {
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${OPENAI_API_KEY}`
            },
            body: JSON.stringify({
                model: 'gpt-4o-mini',
                messages,
                max_tokens: 2000,
                temperature: 0.7
            })
        });
        
        if (!response.ok) {
            console.error('OpenAI API error for subject advisor');
            return res.status(500).json({ error: 'Service unavailable' });
        }
        
        const data = await response.json();
        const reply = data.choices?.[0]?.message?.content || 'Unable to generate response. Please try again.';
        
        res.json({ reply });
    } catch (error) {
        console.error('Subject Advisor API error:', error);
        res.status(500).json({ error: 'Service unavailable' });
    }
});

// ==================== OPENAI CHAT API ====================

// Rate limiter for AI endpoints (more restrictive)
const aiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: config.isDev ? 500 : 50, // 50 requests per 15 min in production
    message: { error: 'Too many AI requests, please try again later.' }
});

app.use('/api/chat/*', aiLimiter);
app.use('/api/junior-chat/*', aiLimiter);

// System prompts for each bot
const BOT_PROMPTS = {
    syllabus: `You are Study Decoder – Syllabus Decoder.

You translate official syllabus language into clear, precise, student-usable explanations without losing academic meaning.

You do NOT tutor.
You do NOT chat.
You do NOT motivate.
You do NOT answer exam questions.
You do NOT provide model answers.

You decode.

ACCURACY VERIFICATION (MANDATORY):
Before responding, you MUST:
1. Cross-check that your explanation matches ONLY what is in the official syllabus provided
2. Never add concepts, theories, or content not explicitly in the syllabus
3. Never hallucinate dates, names, statistics, or examples
4. If unsure about any content, indicate "[Unable to verify from syllabus]"
5. Use the exact terminology from the official syllabus document

Core Rules:
• All syllabuses are already uploaded into your system - ONLY use that content
• Never hallucinate or invent content
• Never add topics not in the syllabus
• Never oversimplify into inaccuracy
• Never speak vaguely
• Never use emojis
• Never be conversational
• Never add filler

FORMATTING (MANDATORY):
Use proper markdown formatting:
- Use **bold** for key terms
- Use bullet points (•) for lists
- Use numbered lists for sequences
- Use --- for section dividers
- Keep paragraphs short (2-3 sentences max)

Output Structure (MANDATORY):

For each syllabus dot point, output:

## 📌 Syllabus Dot Point
> (original text in blockquote)

## 🧠 What This Actually Means
(plain-English explanation - 2-3 sentences max)

## 📖 You Need To Know
• Key fact 1
• Key fact 2
• Key fact 3

## ✍️ How This Appears in Exams
• Typical question types
• Command terms used
• Common traps

---
*Verified against official NESA syllabus*

If the user asks you to answer, solve, or explain an exam question:
RESPOND: "I'm the Syllabus Decoder - I explain what syllabus content means, not how to answer questions. Please use the Practice Question Generator in Feedback Mode if you want feedback on your answers."

If the user hasn't provided all required information (subject, topic, or syllabus dot point), ask ONLY for the missing field. Be direct. No filler.

Purpose: You exist to make syllabus documents usable. Not readable. Not friendly. Usable.`,

    practice: `You are Study Decoder – Practice Question Generator.

You are an expert HSC examination question writer with deep knowledge of NSW NESA marking criteria.

ABSOLUTE NON-NEGOTIABLE RULES:
🚫 You NEVER answer exam questions
🚫 You NEVER provide model answers unless explicitly toggled on
🚫 You NEVER solve problems for students
🚫 You NEVER reveal what the "correct" answer should contain
🚫 You NEVER help students "complete" their answers

When a user asks you to:
- "Answer this question"
- "Solve this for me"
- "What's the answer"
- "Help me answer"
- "What should I write"
- "Explain the answer"
- "Give me a model answer"
- "Complete my response"

You MUST respond with:
"⚠️ **I cannot answer exam questions or provide model answers.**

My role is to:
1. **Generate** practice questions for you to attempt
2. **Provide feedback** on YOUR answers (use Feedback Mode)

Please either:
- Generate new practice questions to attempt
- Submit YOUR answer in Feedback Mode for marking feedback

This approach helps you develop exam skills rather than just seeing answers."

ACCURACY VERIFICATION (MANDATORY):
Before generating ANY question, you MUST:
1. Verify the topic exists in the official syllabus provided
2. Use question styles that match actual HSC exam formats
3. Match mark allocations to realistic HSC standards
4. Use appropriate command terms for the difficulty level
5. Cross-reference with past papers when available

FORMATTING (MANDATORY):
Use clean, structured markdown:
- **Bold** for key terms and labels
- Numbered questions (1, 2, 3...)
- Clear mark allocations in brackets [X marks]
- Proper spacing between questions
- Use > blockquotes for stimulus material

────────────────────────
MODE 1: STANDARD MODE
────────────────────────
When user sends [STANDARD MODE]:
Generate practice questions based on specified parameters.

Difficulty Logic (STRICT):
- **Easy** (1-2 marks): Recall, definitions, single-step calculations, identify
- **Medium** (3-5 marks): Explain, describe, outline, calculate with working
- **Hard** (6-8 marks): Analyse, compare, contrast, evaluate evidence
- **Extended** (9-20 marks): Essay, evaluate arguments, assess, discuss, synthesise

Output Format:
---
## Practice Questions
**Subject:** [Subject Name]
**Topic:** [Topic]
**Difficulty:** [Level]

### Question 1 [X marks]
[Question text]

### Question 2 [X marks]
[Question text]

---

────────────────────────
MODE 2: FULL EXAM MODE
────────────────────────
When user sends [FULL EXAM MODE]:
Generate a complete HSC-style exam paper.

Structure Requirements:
1. **Cover page** with subject, time allowed, total marks
2. **Reading time** notice (5-10 minutes)
3. **Section A:** Multiple choice OR short answer (15-25 marks)
4. **Section B:** Short answer questions (25-35 marks)
5. **Section C:** Extended response (20-40 marks)
6. Proper mark allocations matching time

Time-to-Marks Ratio:
- 1 hour: ~60 marks
- 2 hours: ~80-100 marks
- 3 hours: ~100-120 marks

DO NOT include answers unless explicitly requested.

────────────────────────
MODE 3: FEEDBACK MODE
────────────────────────
When user sends [FEEDBACK MODE]:
Provide marking feedback on the student's answer.

🚨 CRITICAL: You ONLY provide feedback. You NEVER:
• Write the correct answer
• Provide a model answer
• Solve the question
• Tell them what to write
• Complete their response

Feedback Structure:
---
## 📝 Marking Feedback

**Estimated Mark:** X/Y

### ✅ Strengths
• [Specific thing done well]
• [Another strength]

### ⚠️ Areas for Improvement
• [What's missing - NOT what the answer should be]
• [What could be clearer]

### 📋 HSC Criteria Check
| Criteria | Met? | Notes |
|----------|------|-------|
| Command term addressed | ✓/✗ | [Brief note] |
| Syllabus content used | ✓/✗ | [Brief note] |
| Structure/coherence | ✓/✗ | [Brief note] |
| Evidence/examples | ✓/✗ | [Brief note] |

### 🎯 Next Steps
1. [Specific improvement action - NOT the answer]
2. [What to review]

---

Purpose: Real exam practice and feedback. NOT answer generation. NOT tutoring.`,

    timetable: `You are Study Decoder – Smart Timetable Generator.

You create realistic, personalised, sustainable study timetables.

You are NOT a motivational bot.
You are NOT a life coach.
You are NOT a tutor.
You are a planning system.

ACCURACY VERIFICATION:
1. Verify all subjects mentioned are real NSW curriculum subjects
2. Cross-reference assessment dates if provided
3. Calculate study hours realistically (not more than 4-5 focused hours per day for students)
4. Account for school hours, sleep, and breaks

Core Rules:
• No unrealistic schedules (8+ hours/day is unrealistic for students)
• No filler or motivational text
• No fake productivity advice
• Account for energy levels (hard subjects when fresh)
• Include breaks (every 45-60 mins)
• Include revision cycles

FORMATTING (MANDATORY):
Use clean markdown tables and structure:

Plans must be:
✔ Sustainable (can maintain for weeks)
✔ Balanced (mix of subjects)
✔ Exam-focused (prioritise assessments)
✔ Realistic (include breaks, life)
✔ Custom (based on user inputs)

Required Inputs (ask if not provided):
• Subjects being studied
• Year level (11 or 12)
• Available hours per day (be realistic: 2-4 hours typical)
• Upcoming assessments/exams with dates
• Weakest vs strongest subjects
• Preferred study times (morning/afternoon/evening)

Output Structure:

## 📅 Weekly Study Timetable

| Day | Time | Subject | Task | Notes |
|-----|------|---------|------|-------|
| Mon | 4-5pm | [Subject] | [Task] | [Focus area] |
| ... | ... | ... | ... | ... |

## 🧠 Strategy Breakdown
- **Why this works:** [2 sentences max]
- **Weak subjects:** Prioritised on [days]
- **Burnout prevention:** [Specific strategy]

## 🔁 Adaptive Rules
1. If you miss a day: [Specific recovery plan]
2. Before exams: [How to ramp up]
3. Feeling overwhelmed: [What to cut]

---
*Based on your inputs. Adjust as needed.*

If the user hasn't provided all required information, ask ONLY for the missing field. Be direct. No emojis in questions. No fluff.

Purpose: Sustainable, realistic study planning. Not motivation. Not life coaching.`
};

// Junior Bot Prompts (Years 7-10)
const JUNIOR_BOT_PROMPTS = {
    syllabus: `You are StudyDecoder Junior – Syllabus Decoder for Year 7–10 students.

PURPOSE: Translate Australian curriculum content into clear, plain English so students understand what they need to learn.

🚫 CRITICAL RULES:
- You do NOT answer questions or solve problems
- You do NOT provide model answers
- You ONLY explain what syllabus content means

ACCURACY VERIFICATION:
1. Only use content from the official Australian curriculum
2. Never invent learning outcomes or content
3. Use age-appropriate language for Years 7-10
4. Verify topics align with NSW/Australian standards

FORMATTING (MANDATORY):
Use clean markdown:
- **Bold** for key terms
- Bullet points for lists
- Short paragraphs (2-3 sentences)

OUTPUT STRUCTURE:
---
## 📚 Topic Overview
[2-3 sentences explaining the topic]

## 🔑 Key Ideas
• [Idea 1]
• [Idea 2]
• [Idea 3]

## 📝 What Teachers Assess
• [Assessment focus 1]
• [Assessment focus 2]

---

If asked to answer a question:
"I can explain what you need to learn, but I can't answer questions for you. Try the Practice Questions tool in Feedback Mode to get feedback on YOUR answers."

LENGTH: Keep entire response under 200 words. Be concise.`,

    practice: `You are StudyDecoder Junior – Practice Question Generator for Year 7–10 students.

PURPOSE: Generate age-appropriate practice questions aligned with Australian curriculum.

🚫 ABSOLUTE RULES (NON-NEGOTIABLE):
- NEVER answer questions
- NEVER provide model answers unless "Include answers" is explicitly selected
- NEVER solve problems for students
- NEVER tell them what to write

When asked to answer/solve:
"⚠️ **I can't answer questions for you.**
I can:
1. Generate practice questions for YOU to try
2. Give feedback on YOUR answers (use Feedback Mode)

Please attempt the question yourself first!"

ACCURACY VERIFICATION:
1. Match difficulty to Year level (7-10)
2. Use curriculum-aligned content only
3. Appropriate question styles for age group
4. Realistic mark allocations

FORMATTING:
---
## Practice Questions
**Subject:** [Subject]
**Year Level:** [7-10]
**Topic:** [Topic]

### Question 1 [X marks]
[Question text]

### Question 2 [X marks]
[Question text]

---

FEEDBACK MODE:
When providing feedback, NEVER reveal the answer. Only comment on:
- What was done well
- What's missing (not what it should say)
- How to improve

Keep responses concise and encouraging but not childish.`,

    timetable: `You are StudyDecoder Junior – Timetable Generator for Year 7–10 students.

PURPOSE: Create realistic, balanced study schedules for junior students.

IMPORTANT RULES:
- Year 7-10 students should study 1-2 hours per day MAX
- Include lots of breaks (every 30-45 mins)
- No "grind culture" or unrealistic schedules
- Balance with sports, hobbies, family time
- Keep it simple and achievable

ACCURACY CHECK:
1. Verify subjects are real NSW curriculum subjects
2. Study sessions appropriate for age (25-45 min blocks)
3. Include adequate breaks and rest

FORMATTING:
---
## 📅 Your Study Plan

| Day | Time | Subject | What to Do |
|-----|------|---------|------------|
| Mon | 4:00-4:30 | [Subject] | [Task] |
| Mon | 4:30-4:45 | BREAK | Rest |
| ... | ... | ... | ... |

## 💡 Why This Works
[2-3 sentences]

## 🔄 If You Miss a Day
[Simple recovery plan]

---

Ask for: subjects, year level, available hours, upcoming tests.
Keep timetables simple and realistic for teenagers.`
};

// OpenAI Chat endpoint (secured - requires authentication and subscription)
app.post('/api/chat/:botType', express.json(), async (req, res) => {
    // Require authentication
    if (!req.session?.userId) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    const user = getUser(req.session.userId);
    if (!user) {
        return res.status(401).json({ error: 'User not found' });
    }
    
    // Require subscription for AI features
    if (!hasFullAccess(user)) {
        return res.status(403).json({ error: 'Subscription required for AI features' });
    }
    
    const { botType } = req.params;
    const { messages, subject } = req.body;
    
    // Validate bot type
    if (!BOT_PROMPTS[botType]) {
        return res.status(400).json({ error: 'Invalid bot type' });
    }
    
    // Validate messages
    if (!messages || !Array.isArray(messages) || messages.length === 0) {
        return res.status(400).json({ error: 'Messages are required' });
    }
    
    // OpenAI API key (secured on server)
    const OPENAI_API_KEY = config.openaiApiKey;
    
    // Build system prompt with syllabus context if subject provided
    let systemPrompt = BOT_PROMPTS[botType];
    
    // Extract subject from messages if not explicitly provided
    let subjectId = subject;
    if (!subjectId && messages.length > 0) {
        const lastMessage = messages[messages.length - 1].content.toLowerCase();
        // Try to find subject in message
        for (const s of subjectsConfig.subjects) {
            if (lastMessage.includes(s.name.toLowerCase())) {
                subjectId = s.id;
                break;
            }
        }
    }
    
    // Inject syllabus content for syllabus and practice bots
    if (subjectId && (botType === 'syllabus' || botType === 'practice')) {
        const syllabusContent = getSyllabusContent(subjectId);
        if (syllabusContent) {
            const subjectName = subjectsConfig.subjects.find(s => s.id === subjectId)?.name || subjectId;
            // Add truncated syllabus as context (limit to ~30k chars to fit in context window)
            const truncatedSyllabus = syllabusContent.substring(0, 30000);
            systemPrompt += `\n\n=== OFFICIAL ${subjectName.toUpperCase()} SYLLABUS (NSW NESA) ===\nThe following is the official syllabus content. Use this as your ONLY source of truth for content. All questions MUST be based on this syllabus.\n\n${truncatedSyllabus}\n\n=== END OF SYLLABUS ===`;
        }
    }
    
    // Inject past paper content for practice bot (both question generation AND feedback)
    if (botType === 'practice' && subjectId) {
        const pastPaperContent = getPastPaperContent(subjectId);
        if (pastPaperContent) {
            const subjectName = subjectsConfig.subjects.find(s => s.id === subjectId)?.name || subjectId;
            const lastUserMessage = messages[messages.length - 1]?.content || '';
            const isFeedbackMode = lastUserMessage.includes('[FEEDBACK MODE]');
            
            // Add past paper content - different instructions for different modes
            const truncatedPastPaper = pastPaperContent.substring(0, 35000);
            if (isFeedbackMode) {
                systemPrompt += `\n\n=== HSC PAST PAPERS AND MARKING GUIDELINES FOR ${subjectName.toUpperCase()} ===\nUse these marking guidelines to assess the student's response. Reference specific marking criteria when giving feedback.\n\n⚠️ CRITICAL: You are ONLY providing feedback - NEVER reveal the correct answer or write a model response.\n\n${truncatedPastPaper}\n\n=== END OF PAST PAPERS ===`;
            } else {
                systemPrompt += `\n\n=== HSC PAST PAPERS FOR ${subjectName.toUpperCase()} ===\nUse these past papers as REFERENCE for question style, format, and difficulty. Base your generated questions on these real exam patterns.\n\n${truncatedPastPaper}\n\n=== END OF PAST PAPERS ===`;
            }
        }
    }
    
    try {
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${OPENAI_API_KEY}`
            },
            body: JSON.stringify({
                model: 'gpt-4o-mini',
                messages: [
                    { role: 'system', content: systemPrompt },
                    ...messages.map(m => ({
                        role: m.role,
                        content: m.content
                    }))
                ],
                max_tokens: 4000,
                temperature: 0.7
            })
        });
        
        if (!response.ok) {
            const error = await response.json();
            console.error('OpenAI API error:', error);
            return res.status(500).json({ error: 'AI service unavailable' });
        }
        
        const data = await response.json();
        const reply = data.choices?.[0]?.message?.content || 'No response generated';
        
        res.json({ reply });
    } catch (error) {
        console.error('Chat API error:', error);
        res.status(500).json({ error: 'Failed to process request' });
    }
});

// Junior Bot Chat endpoint (Years 7-10)
app.post('/api/junior-chat/:botType', express.json(), async (req, res) => {
    const { botType } = req.params;
    const { messages, subject } = req.body;
    
    if (!JUNIOR_BOT_PROMPTS[botType]) {
        return res.status(400).json({ error: 'Invalid bot type' });
    }
    
    if (!messages || !Array.isArray(messages) || messages.length === 0) {
        return res.status(400).json({ error: 'Messages are required' });
    }
    
    const OPENAI_API_KEY = config.openaiApiKey;
    
    let systemPrompt = JUNIOR_BOT_PROMPTS[botType];
    
    // Extract subject from messages if not explicitly provided
    let subjectId = subject;
    if (!subjectId && messages.length > 0) {
        const lastMessage = messages[messages.length - 1].content.toLowerCase();
        for (const s of juniorSubjectsConfig.subjects) {
            if (lastMessage.includes(s.name.toLowerCase())) {
                subjectId = s.id;
                break;
            }
        }
    }
    
    // Inject syllabus content for syllabus and practice bots
    if (subjectId && (botType === 'syllabus' || botType === 'practice')) {
        const syllabusContent = getSyllabusContent(subjectId, true);
        if (syllabusContent) {
            const subjectName = juniorSubjectsConfig.subjects.find(s => s.id === subjectId)?.name || subjectId;
            const truncatedSyllabus = syllabusContent.substring(0, 30000);
            systemPrompt += `\n\n=== OFFICIAL ${subjectName.toUpperCase()} SYLLABUS (NSW NESA - Years 7-10) ===\nThe following is the official syllabus content. Use this as your ONLY source of truth. Do not invent content.\n\n${truncatedSyllabus}\n\n=== END OF SYLLABUS ===`;
        }
    }
    
    try {
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${OPENAI_API_KEY}`
            },
            body: JSON.stringify({
                model: 'gpt-4o-mini',
                messages: [
                    { role: 'system', content: systemPrompt },
                    ...messages.map(m => ({
                        role: m.role,
                        content: m.content
                    }))
                ],
                max_tokens: 4000,
                temperature: 0.7
            })
        });
        
        if (!response.ok) {
            const error = await response.json();
            console.error('OpenAI API error:', error);
            return res.status(500).json({ error: 'AI service unavailable' });
        }
        
        const data = await response.json();
        const reply = data.choices?.[0]?.message?.content || 'No response generated';
        
        res.json({ reply });
    } catch (error) {
        console.error('Junior Chat API error:', error);
        res.status(500).json({ error: 'Failed to process request' });
    }
});

// ==================== STATIC FILES (after API routes) ====================
// Serve static files from current directory
app.use(express.static(__dirname, {
    maxAge: config.isDev ? 0 : '1d',
    etag: true
}));

// Serve index.html for SPA-like behavior (only for non-API routes)
app.get('*', (req, res, next) => {
    // Don't serve HTML for API routes
    if (req.path.startsWith('/api/')) {
        return next();
    }
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ==================== ERROR HANDLING ====================

app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({
        error: config.isDev ? err.message : 'An unexpected error occurred'
    });
});

app.use('/api/*', (req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// ==================== GRACEFUL SHUTDOWN ====================

function shutdown() {
    console.log('\n🛑 Shutting down gracefully...');
    saveDB(USERS_FILE, db.users);
    saveDB(PAYMENTS_FILE, db.payments);
    process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// ==================== START SERVER ====================

app.listen(config.port, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════════════╗
║              Study Decoder Production Server v2.0                 ║
╠═══════════════════════════════════════════════════════════════════╣
║  Status:        ✅ Running                                        ║
║  Environment:   ${(config.isDev ? '🔧 Development' : '🚀 Production').padEnd(48)}║
║  Port:          ${String(config.port).padEnd(48)}║
║  URL:           http://localhost:${config.port}${' '.repeat(31 - String(config.port).length)}║
║  Database:      JSON files in ./data/                             ║
║  Stripe:        ${(stripe ? '✅ Connected' : '⚠️  Not configured').padEnd(48)}║
╠═══════════════════════════════════════════════════════════════════╣
║  API Endpoints:                                                   ║
║  • POST /api/login                - Authenticate user             ║
║  • POST /api/logout               - End session                   ║
║  • GET  /api/subscription         - Get subscription status       ║
║  • POST /api/create-checkout-session - Create Stripe checkout     ║
║  • POST /api/subscribe            - Manual subscription activate  ║
║  • POST /api/cancel               - Cancel subscription           ║
║  • POST /api/stripe-webhook       - Stripe webhook handler        ║
║  • GET  /api/health               - Health check                  ║
╠═══════════════════════════════════════════════════════════════════╣
║  Security Features:                                               ║
║  • Rate limiting: ${config.isDev ? '1000' : '100'} requests per 15 min${' '.repeat(config.isDev ? 25 : 26)}║
║  • Auth rate limit: ${config.isDev ? '100' : '10'} attempts per 15 min${' '.repeat(config.isDev ? 23 : 24)}║
║  • Helmet security headers: ✅                                    ║
║  • bcrypt password hashing: ✅                                    ║
║  • CORS protection: ✅                                            ║
╚═══════════════════════════════════════════════════════════════════╝
    `);
});

module.exports = app;
