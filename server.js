/**
 * Study Decoder - Production Backend Server v2.0
 * ===============================================
 * A fully production-ready Express.js server with:
 * - Persistent JSON database (auto-saved, no native deps)
 * - bcryptjs password hashing (pure JS, no compilation)
 * - Stripe payment integration with webhooks
 * - Rate limiting & security headers
 * - Session management with secure cookies
 * - Email sending for password reset
 * 
 * Environment Variables Required:
 * - NODE_ENV: 'production' or 'development'
 * - PORT: Server port (default: 3001)
 * - SESSION_SECRET: 32+ character secret for session encryption
 * - GOOGLE_CLIENT_ID: Google OAuth client ID
 * - STRIPE_SECRET_KEY: Stripe secret key (sk_live_xxx or sk_test_xxx)
 * - STRIPE_WEBHOOK_SECRET: Stripe webhook signing secret (whsec_xxx)
 * - FRONTEND_URL: Your frontend domain (e.g., https://studydecoder.com.au)
 * - EMAIL_USER: Gmail address for sending emails
 * - EMAIL_APP_PASSWORD: Gmail App Password (16-char code from Google)
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
const nodemailer = require('nodemailer');
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
const DB_PATH = config.isDev ? path.join(__dirname, 'data') : '/var/data';
const USERS_FILE = path.join(DB_PATH, 'users.json');
const PAYMENTS_FILE = path.join(DB_PATH, 'payments.json');
const OG_CODES_FILE = path.join(DB_PATH, 'og-codes.json');

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

// ==================== LIFETIME ACCESS EMAILS ====================
// These emails get full lifetime access (like owner but without admin page)
const LIFETIME_ACCESS_EMAILS = [
    'ryanhatu@gmail.com',
    'hatuahmad7@gmail.com',
    'khaledsalt1945@gmail.com',
    'Quizzywolf@gmail.com',
    'australiaball87@gmail.com',
    'aydinhalim2008@gmail.com',
    'urameshiboi4@gmail.com'

];

// ==================== FREE TIER CONFIGURATION ====================
const FREE_TIER_CONFIG = {
    totalUsesPerDay: 10,         // Total uses across ALL bots per day
    specialLimits: {
        'worksheet': 1,          // 1 worksheet decode per day
        'notes-transcriber': 1   // 1 notes transcription per day
    },
    enabled: true
};

// ==================== AI QUALITY TIERS ====================
// Different quality settings based on user role (owner > lifetime > paid > free)
const AI_QUALITY_TIERS = {
    owner: {
        maxTokens: 35000,     // GPT-5 mini supports up to 128k, but 35k is plenty
        temperature: 1.0,     // Maximum creativity
        model: 'gpt-5-mini'   // Latest flagship model
    },
    lifetime: {
        maxTokens: 16384,     // Same as old owner tier
        temperature: 1.0,     // Same as old owner tier
        model: 'gpt-4o'       // Upgraded to GPT-4o (old owner model)
    },
    og_tester: {
        maxTokens: 16384,     // Same as lifetime
        temperature: 1.0,
        model: 'gpt-4o'
    },
    paid: {
        maxTokens: 4000,      // Standard for subscribers
        temperature: 0.7,
        model: 'gpt-4o-mini'
    },
    free: {
        maxTokens: 1500,      // Limited output
        temperature: 0.5,     // Less creative
        model: 'gpt-4o-mini'
    }
};

// Get AI settings based on user role
function getAISettings(user) {
    if (!user) return AI_QUALITY_TIERS.free;
    const role = getUserRole(user.email);
    if (role === 'owner') return AI_QUALITY_TIERS.owner;
    if (role === 'lifetime' || role === 'og_tester') return AI_QUALITY_TIERS.lifetime;
    if (user.subscribed === true) return AI_QUALITY_TIERS.paid;
    return AI_QUALITY_TIERS.free;
}

// Track daily usage for free tier — GLOBAL total + per-bot specials (resets at midnight UTC)
const freeUsageTracker = new Map();

function _getToday() {
    return new Date().toISOString().split('T')[0];
}

function _getKey(userId, suffix) {
    return `${_getToday()}_${userId}_${suffix}`;
}

function _getCount(key) {
    return freeUsageTracker.get(key) || 0;
}

function getFreeTierUsage(userId, botType) {
    return _getCount(_getKey(userId, botType));
}

function getTotalFreeTierUsage(userId) {
    return _getCount(_getKey(userId, '_total'));
}

function incrementFreeTierUsage(userId, botType) {
    const today = _getToday();
    // Increment per-bot counter
    const botKey = _getKey(userId, botType);
    freeUsageTracker.set(botKey, _getCount(botKey) + 1);
    // Increment global total counter
    const totalKey = _getKey(userId, '_total');
    freeUsageTracker.set(totalKey, _getCount(totalKey) + 1);
    
    // Clean up old entries
    for (const [k] of freeUsageTracker) {
        if (!k.startsWith(today)) freeUsageTracker.delete(k);
    }
    
    return _getCount(totalKey);
}

function canUseFreeTier(userId, botType) {
    if (!FREE_TIER_CONFIG.enabled) return false;
    // Check special per-bot limit (worksheet, notes-transcriber)
    const specialLimit = FREE_TIER_CONFIG.specialLimits[botType];
    if (specialLimit !== undefined) {
        if (getFreeTierUsage(userId, botType) >= specialLimit) return false;
    }
    // Check global total
    return getTotalFreeTierUsage(userId) < FREE_TIER_CONFIG.totalUsesPerDay;
}

function getFreeTierRemaining(userId, botType) {
    const totalUsed = getTotalFreeTierUsage(userId);
    return Math.max(0, FREE_TIER_CONFIG.totalUsesPerDay - totalUsed);
}

function getFreeTierStatus(userId, botType) {
    const totalUsed = getTotalFreeTierUsage(userId);
    const totalRemaining = Math.max(0, FREE_TIER_CONFIG.totalUsesPerDay - totalUsed);
    const specialLimit = FREE_TIER_CONFIG.specialLimits[botType];
    const botUsed = getFreeTierUsage(userId, botType);
    
    let hitSpecialLimit = false;
    let specialRemaining = null;
    if (specialLimit !== undefined) {
        hitSpecialLimit = botUsed >= specialLimit;
        specialRemaining = Math.max(0, specialLimit - botUsed);
    }
    
    return { totalUsed, totalRemaining, botUsed, hitSpecialLimit, specialRemaining };
}

// Get all bot usage for a user (for status display)
function getAllFreeTierUsage(userId) {
    const today = _getToday();
    const usage = {};
    for (const [key, count] of freeUsageTracker) {
        if (key.startsWith(today + '_' + userId + '_')) {
            const botType = key.split('_').slice(2).join('_');
            usage[botType] = count;
        }
    }
    return usage;
}

// ==================== EMAIL CONFIGURATION ====================
// Gmail transporter for sending password reset emails
// Requires EMAIL_USER and EMAIL_APP_PASSWORD environment variables
const emailTransporter = process.env.EMAIL_USER && process.env.EMAIL_APP_PASSWORD 
    ? nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_APP_PASSWORD
        }
    })
    : null;

// Log warning at startup if email not configured
if (!emailTransporter) {
    console.warn('⚠️ =====================================================');
    console.warn('⚠️ EMAIL NOT CONFIGURED - Password reset will NOT work!');
    console.warn('⚠️ Set EMAIL_USER and EMAIL_APP_PASSWORD in environment');
    console.warn('⚠️ =====================================================');
}

async function sendPasswordResetEmail(email, resetToken) {
    if (!emailTransporter) {
        console.error('❌ EMAIL NOT CONFIGURED - Cannot send password reset to:', email);
        console.error('   Reset token was generated:', resetToken.substring(0, 8) + '...');
        console.error('   To fix: Add EMAIL_USER and EMAIL_APP_PASSWORD to Render environment variables');
        return false;
    }
    
    const resetLink = `${config.frontendUrl}/reset-password.html?token=${resetToken}&email=${encodeURIComponent(email)}`;
    
    const mailOptions = {
        from: `"Study Decoder" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'Reset Your Study Decoder Password',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #6366f1;">Password Reset Request</h2>
                <p>Hi,</p>
                <p>We received a request to reset your password for your Study Decoder account.</p>
                <p>Click the button below to reset your password. This link will expire in 1 hour.</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="${resetLink}" style="background-color: #6366f1; color: white; padding: 12px 30px; text-decoration: none; border-radius: 8px; display: inline-block;">Reset Password</a>
                </div>
                <p>If you didn't request this, you can safely ignore this email.</p>
                <p style="color: #666; font-size: 12px; margin-top: 30px;">
                    If the button doesn't work, copy and paste this link into your browser:<br>
                    <a href="${resetLink}" style="color: #6366f1;">${resetLink}</a>
                </p>
                <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                <p style="color: #999; font-size: 11px;">Study Decoder - AI-Powered HSC Exam Preparation</p>
            </div>
        `
    };
    
    try {
        console.log(`📧 Attempting to send password reset email to: ${email}`);
        console.log(`   Using EMAIL_USER: ${process.env.EMAIL_USER?.substring(0, 5)}***`);
        await emailTransporter.sendMail(mailOptions);
        console.log(`✅ Password reset email sent successfully to: ${email}`);
        return true;
    } catch (error) {
        console.error('❌ Failed to send email:', error.message);
        console.error('   Full error:', error);
        return false;
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

// ==================== OWNER & ROLE SYSTEM ====================
// Owner email is set via config (from environment variable with fallback)

function getUserRole(email) {
    if (email && email.toLowerCase() === config.ownerEmail.toLowerCase()) {
        return 'owner';
    }
    // Check if user has lifetime access (hardcoded emails)
    if (email && LIFETIME_ACCESS_EMAILS.some(e => e.toLowerCase() === email.toLowerCase())) {
        return 'lifetime';
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
    // Owner, lifetime access emails, and OG testers get free access
    if (role === 'owner' || role === 'lifetime' || role === 'og_tester') {
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

// Security headers (Australian Cyber Security Centre recommendations)
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
            frameSrc: ["https://accounts.google.com", "https://js.stripe.com"],
            upgradeInsecureRequests: [] // Force HTTPS
        }
    },
    crossOriginEmbedderPolicy: false,
    // Additional security headers for Australian compliance
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    hsts: {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true
    },
    noSniff: true, // X-Content-Type-Options: nosniff
    xssFilter: true, // X-XSS-Protection
    frameguard: { action: 'deny' } // X-Frame-Options: DENY (prevent clickjacking)
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
            'https://www.studydecoder.com.au',
            'https://studydecoder.com.au',
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

// Body parsing - raw for Stripe webhooks, large limit for image uploads, JSON for everything else
app.use((req, res, next) => {
    if (req.originalUrl === '/api/stripe-webhook') {
        express.raw({ type: 'application/json' })(req, res, next);
    } else if (req.originalUrl === '/api/chat/worksheet' || req.originalUrl === '/api/chat/notes-transcriber') {
        express.json({ limit: '25mb' })(req, res, next);
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
 * Auto-sync subscription status from Stripe on login
 * This handles cases where the server restarts and loses user data
 */
async function autoSyncStripeSubscription(userId, email) {
    if (!stripe || !email) return null;
    
    try {
        // Search for Stripe customer by email
        const searchEmail = email.toLowerCase();
        const customers = await stripe.customers.list({
            email: searchEmail,
            limit: 1
        });
        
        if (customers.data.length === 0) return null;
        
        const customer = customers.data[0];
        
        // Check for active subscriptions
        const subscriptions = await stripe.subscriptions.list({
            customer: customer.id,
            status: 'active',
            limit: 1
        });
        
        if (subscriptions.data.length > 0) {
            const sub = subscriptions.data[0];
            const plan = sub.items.data[0]?.price?.recurring?.interval === 'year' ? 'yearly' : 'monthly';
            const expiresAt = new Date(sub.current_period_end * 1000).toISOString();
            
            // Update user with subscription info
            upsertUser(userId, {
                subscribed: true,
                plan: plan,
                stripeCustomerId: customer.id,
                stripeSubscriptionId: sub.id,
                expiresAt: expiresAt
            });
            
            console.log(`🔄 Auto-synced subscription for ${email} (${plan})`);
            return { subscribed: true, plan, expiresAt };
        }
        
        // Check for completed checkout sessions
        const sessions = await stripe.checkout.sessions.list({
            customer: customer.id,
            limit: 5
        });
        
        const completedSession = sessions.data.find(s => 
            s.payment_status === 'paid' || s.payment_status === 'no_payment_required'
        );
        
        if (completedSession) {
            const plan = completedSession.metadata?.plan || 'monthly';
            const existingUser = getUser(userId);
            
            // Check if we already have valid expiration
            if (existingUser?.expiresAt && new Date(existingUser.expiresAt) > new Date()) {
                return { subscribed: true, plan: existingUser.plan, expiresAt: existingUser.expiresAt };
            }
            
            // Calculate new expiration from session creation
            const sessionDate = new Date(completedSession.created * 1000);
            const expiration = new Date(sessionDate);
            if (plan === 'yearly') {
                expiration.setFullYear(expiration.getFullYear() + 1);
            } else {
                expiration.setMonth(expiration.getMonth() + 1);
            }
            
            // Only update if expiration is in the future
            if (expiration > new Date()) {
                upsertUser(userId, {
                    subscribed: true,
                    plan: plan,
                    stripeCustomerId: customer.id,
                    expiresAt: expiration.toISOString()
                });
                
                console.log(`🔄 Auto-synced checkout payment for ${email} (${plan})`);
                return { subscribed: true, plan, expiresAt: expiration.toISOString() };
            }
        }
        
        return null;
    } catch (error) {
        console.error('Auto-sync Stripe error:', error.message);
        return null;
    }
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
        preferences: data.preferences || existing.preferences || {},
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
 * Sanitize user input to prevent XSS
 * Strips HTML tags and encodes special characters
 */
function sanitizeInput(input) {
    if (typeof input !== 'string') return input;
    return input
        .replace(/[<>]/g, '') // Remove angle brackets
        .replace(/javascript:/gi, '') // Remove javascript: protocol
        .replace(/on\w+=/gi, '') // Remove inline event handlers
        .trim();
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

/**
 * Check if user needs onboarding (preferences setup)
 * Returns true for:
 * - Users explicitly marked as not onboarded (onboarded === false)
 * - Pre-preferences users who never set a level (signed up before the update)
 */
function needsOnboarding(user) {
    if (!user) return false;
    if (user.preferences?.onboarded === false) return true;
    // Pre-preferences user: has no level set and wasn't explicitly onboarded
    if (!user.preferences?.level && user.preferences?.onboarded === undefined) return true;
    return false;
}

/**
 * For existing users missing preferences, mark them as needing onboarding
 * so they get prompted on next page load.
 */
function ensureOnboardingFlag(user) {
    if (needsOnboarding(user) && user.preferences?.onboarded !== false) {
        if (!user.preferences) user.preferences = {};
        user.preferences.onboarded = false;
        scheduleSave();
    }
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
        
        // If brand new user, mark as not onboarded
        if (!existingUser) {
            user.preferences = { ...(user.preferences || {}), onboarded: false };
            scheduleSave();
        } else {
            // Existing user: check if they signed up before preferences update
            ensureOnboardingFlag(user);
        }
        
        // Auto-sync subscription status from Stripe (handles server restarts)
        if (!user.subscribed || !user.expiresAt || new Date(user.expiresAt) < new Date()) {
            await autoSyncStripeSubscription(userId, verified.email);
        }
        
        // Get updated user after potential sync
        const updatedUser = getUser(userId) || user;
        
        req.session.userId = userId;
        const role = getUserRole(updatedUser.email);
        
        console.log(`✅ Google sign-in: ${updatedUser.email} (${role})`);
        
        res.json({
            email: updatedUser.email,
            name: updatedUser.name,
            role: role,
            subscribed: hasFullAccess(updatedUser),
            plan: updatedUser.plan,
            expiresAt: updatedUser.expiresAt,
            onboarded: !needsOnboarding(updatedUser)
        });
        
    } catch (error) {
        console.error('Google auth error:', error);
        res.status(500).json({ error: 'Authentication failed' });
    }
});

/**
 * POST /api/auth/google-oauth - Google OAuth Access Token Sign In
 * Fallback for browsers that block One Tap (Brave, Firefox with strict privacy)
 */
app.post('/api/auth/google-oauth', async (req, res) => {
    try {
        const { accessToken } = req.body;
        
        if (!accessToken) {
            return res.status(400).json({ error: 'Access token required' });
        }
        
        // Verify the access token and get user info from Google
        const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });
        
        if (!userInfoResponse.ok) {
            return res.status(401).json({ error: 'Invalid access token' });
        }
        
        const userInfo = await userInfoResponse.json();
        
        if (!userInfo.email) {
            return res.status(401).json({ error: 'Could not retrieve email from Google' });
        }
        
        // Check if user exists with this email
        let existingUser = getUserByEmail(userInfo.email);
        let userId = existingUser ? existingUser.userId : `google:${userInfo.sub}`;
        
        const user = upsertUser(userId, {
            email: userInfo.email,
            name: userInfo.name || userInfo.email.split('@')[0],
            provider: existingUser?.provider || 'google',
            emailVerified: userInfo.email_verified !== false
        });
        
        // If brand new user, mark as not onboarded
        if (!existingUser) {
            user.preferences = { ...(user.preferences || {}), onboarded: false };
            scheduleSave();
        } else {
            // Existing user: check if they signed up before preferences update
            ensureOnboardingFlag(user);
        }
        
        // Auto-sync subscription status from Stripe (handles server restarts)
        if (!user.subscribed || !user.expiresAt || new Date(user.expiresAt) < new Date()) {
            await autoSyncStripeSubscription(userId, userInfo.email);
        }
        
        // Get updated user after potential sync
        const updatedUser = getUser(userId) || user;
        
        req.session.userId = userId;
        const role = getUserRole(updatedUser.email);
        
        console.log(`✅ Google OAuth sign-in: ${updatedUser.email} (${role})`);
        
        res.json({
            email: updatedUser.email,
            name: updatedUser.name,
            role: role,
            subscribed: hasFullAccess(updatedUser),
            plan: updatedUser.plan,
            expiresAt: updatedUser.expiresAt,
            onboarded: !needsOnboarding(updatedUser)
        });
        
    } catch (error) {
        console.error('Google OAuth error:', error);
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
        
        // Mark new registration as not onboarded
        user.preferences = { ...(user.preferences || {}), onboarded: false };
        scheduleSave();
        
        req.session.userId = userId;
        const role = getUserRole(user.email);
        
        console.log(`✅ New registration: ${user.email} (${role})`);
        
        res.json({
            email: user.email,
            name: user.name,
            role: role,
            subscribed: hasFullAccess(user),
            plan: user.plan,
            expiresAt: user.expiresAt,
            onboarded: false
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
        
        // Check if user signed up before preferences update
        ensureOnboardingFlag(user);
        
        // Auto-sync subscription status from Stripe (handles server restarts)
        if (!user.subscribed || !user.expiresAt || new Date(user.expiresAt) < new Date()) {
            await autoSyncStripeSubscription(user.userId, user.email);
        }
        
        // Get updated user after potential sync
        const updatedUser = getUser(user.userId) || user;
        
        // Set session
        req.session.userId = user.userId;
        if (remember) {
            req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
        }
        
        const role = getUserRole(updatedUser.email);
        console.log(`✅ Login: ${updatedUser.email} (${role})`);
        
        res.json({
            email: updatedUser.email,
            name: updatedUser.name,
            role: role,
            subscribed: hasFullAccess(updatedUser),
            plan: updatedUser.plan,
            expiresAt: updatedUser.expiresAt,
            onboarded: !needsOnboarding(updatedUser)
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
        
        // Check if email system is configured
        if (!emailTransporter) {
            console.error(`❌ Password reset attempted but email not configured for: ${email}`);
            return res.status(503).json({ 
                error: 'Password reset is currently unavailable. Please contact support or use Google Sign-In.' 
            });
        }
        
        // Always return success to prevent email enumeration
        console.log(`📧 Password reset requested for: ${email}`);
        
        const user = getUserByEmail(email);
        if (user && user.provider !== 'google') {
            // Only allow password reset for email accounts (Google accounts use Google auth)
            const resetToken = generateSecureToken();
            const resetExpiry = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour
            
            // Store reset token
            user.resetToken = resetToken;
            user.resetExpiry = resetExpiry;
            upsertUser(user.userId, user);
            
            // Send the reset email
            const sent = await sendPasswordResetEmail(email, resetToken);
            if (!sent) {
                console.error(`❌ Failed to send password reset email to: ${email}`);
            }
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

/**
 * POST /api/auth/reset-password - Reset password with token
 */
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { email, token, newPassword } = req.body;
        
        if (!email || !token || !newPassword) {
            return res.status(400).json({ error: 'Email, token, and new password are required' });
        }
        
        if (!isValidPassword(newPassword)) {
            return res.status(400).json({ 
                error: 'Password must be at least 8 characters with uppercase, lowercase, and number' 
            });
        }
        
        const user = getUserByEmail(email);
        
        if (!user || user.resetToken !== token) {
            return res.status(401).json({ error: 'Invalid or expired reset link' });
        }
        
        // Check if token has expired
        if (new Date(user.resetExpiry) < new Date()) {
            return res.status(401).json({ error: 'Reset link has expired. Please request a new one.' });
        }
        
        // Update password and clear reset token
        const passwordHash = await hashPassword(newPassword);
        user.passwordHash = passwordHash;
        user.resetToken = null;
        user.resetExpiry = null;
        upsertUser(user.userId, user);
        
        console.log(`✅ Password reset successful for: ${email}`);
        
        res.json({ 
            success: true, 
            message: 'Password has been reset successfully. You can now log in.' 
        });
        
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ error: 'Failed to reset password' });
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
            
            // Auto-sync subscription for Google users
            if (!user.subscribed || !user.expiresAt || new Date(user.expiresAt) < new Date()) {
                await autoSyncStripeSubscription(verified.userId, verified.email);
                user = getUser(verified.userId) || user;
            }
            
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

        // Auto-sync subscription status from Stripe (handles server restarts)
        if (user && (!user.subscribed || !user.expiresAt || new Date(user.expiresAt) < new Date())) {
            await autoSyncStripeSubscription(user.userId, user.email);
            user = getUser(user.userId) || user;
        }
        
        user = checkSubscriptionStatus(user);
        
        // Check if user signed up before preferences update
        ensureOnboardingFlag(user);

        res.json({
            email: user.email,
            name: user.name,
            subscribed: hasFullAccess(user),
            plan: user.plan,
            expiresAt: user.expiresAt,
            onboarded: !needsOnboarding(user)
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
    const hasFull = hasFullAccess(user);
    
    // Ensure pre-preferences users get flagged for onboarding
    ensureOnboardingFlag(user);
    
    res.json({
        email: user.email,
        name: user.name,
        role: role,
        subscribed: hasFull,
        freeAcknowledged: user.freeAcknowledged || false,
        plan: role === 'owner' ? 'owner' : (role === 'og_tester' ? 'og_lifetime' : user.plan),
        expiresAt: (role === 'owner' || role === 'og_tester') ? null : user.expiresAt,
        preferences: user.preferences || {},
        freeTier: !hasFull ? {
            enabled: FREE_TIER_CONFIG.enabled,
            totalUsesPerDay: FREE_TIER_CONFIG.totalUsesPerDay,
            specialLimits: FREE_TIER_CONFIG.specialLimits,
            usage: getAllFreeTierUsage(req.session.userId),
            totalUsed: getTotalFreeTierUsage(req.session.userId),
            totalRemaining: Math.max(0, FREE_TIER_CONFIG.totalUsesPerDay - getTotalFreeTierUsage(req.session.userId))
        } : null
    });
});

/**
 * POST /api/acknowledge-free
 * Mark that user has acknowledged the free tier (don't show paywall again)
 */
app.post('/api/acknowledge-free', requireAuth, (req, res) => {
    const user = req.user;
    user.freeAcknowledged = true;
    saveDB(USERS_FILE, db.users);
    console.log(`[Free] User ${user.email} acknowledged free tier`);
    res.json({ success: true });
});

/**
 * GET /api/user/preferences
 * Get user preferences (saved subjects, detail level, etc.)
 */
app.get('/api/user/preferences', requireAuth, (req, res) => {
    const user = req.user;
    res.json({
        subjects: user.preferences?.subjects || [],
        detailLevel: user.preferences?.detailLevel || 2,
        level: user.preferences?.level || null,
        onboarded: !needsOnboarding(user),
    });
});

/**
 * PUT /api/user/preferences
 * Update user preferences
 */
app.put('/api/user/preferences', requireAuth, express.json(), (req, res) => {
    const user = req.user;
    const { subjects, detailLevel, level, onboarded } = req.body;

    if (!user.preferences) user.preferences = {};

    if (subjects !== undefined) {
        if (!Array.isArray(subjects)) return res.status(400).json({ error: 'subjects must be an array' });
        user.preferences.subjects = subjects.map(String).slice(0, 20);
    }
    if (detailLevel !== undefined) {
        const dl = parseInt(detailLevel);
        if (isNaN(dl) || dl < 1 || dl > 3) return res.status(400).json({ error: 'detailLevel must be 1, 2, or 3' });
        user.preferences.detailLevel = dl;
    }
    if (level !== undefined) {
        if (!['senior', 'junior'].includes(level)) return res.status(400).json({ error: 'level must be senior or junior' });
        user.preferences.level = level;
    }
    if (onboarded !== undefined) {
        user.preferences.onboarded = !!onboarded;
        // Completing onboarding counts as acknowledging the free tier
        if (user.preferences.onboarded) {
            user.freeAcknowledged = true;
        }
    }

    scheduleSave();
    console.log(`[Prefs] Updated preferences for ${user.email}:`, user.preferences);
    res.json({ success: true, preferences: user.preferences });
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

// ==================== CHAT HISTORY (Server-side) ====================
const VALID_BOT_TYPES = ['notes-transcriber', 'worksheet-decoder', 'practice', 'timetable'];
const MAX_SESSIONS_PER_BOT = 20;

/**
 * GET /api/user/history/:botType
 * Get chat history for a specific bot
 */
app.get('/api/user/history/:botType', requireAuth, (req, res) => {
    const { botType } = req.params;
    if (!VALID_BOT_TYPES.includes(botType)) {
        return res.status(400).json({ error: 'Invalid bot type' });
    }
    const user = req.user;
    const history = user.chatHistory?.[botType] || [];
    res.json(history);
});

/**
 * PUT /api/user/history/:botType
 * Save/update chat history for a specific bot (full replacement)
 */
app.put('/api/user/history/:botType', requireAuth, express.json({ limit: '2mb' }), (req, res) => {
    const { botType } = req.params;
    if (!VALID_BOT_TYPES.includes(botType)) {
        return res.status(400).json({ error: 'Invalid bot type' });
    }
    const { history } = req.body;
    if (!Array.isArray(history)) {
        return res.status(400).json({ error: 'history must be an array' });
    }
    const user = req.user;
    if (!user.chatHistory) user.chatHistory = {};
    // Enforce max sessions and sanitise
    user.chatHistory[botType] = history.slice(0, MAX_SESSIONS_PER_BOT).map(session => ({
        id: String(session.id || ''),
        title: String(session.title || '').substring(0, 100),
        date: String(session.date || ''),
        preview: String(session.preview || '').substring(0, 150),
        messages: Array.isArray(session.messages) ? session.messages.slice(0, 200).map(m => ({
            role: m.role === 'assistant' ? 'assistant' : 'user',
            content: String(m.content || '').substring(0, 50000)
        })) : []
    }));
    scheduleSave();
    res.json({ success: true });
});

/**
 * DELETE /api/user/history/:botType/:sessionId
 * Delete a specific chat session
 */
app.delete('/api/user/history/:botType/:sessionId', requireAuth, (req, res) => {
    const { botType, sessionId } = req.params;
    if (!VALID_BOT_TYPES.includes(botType)) {
        return res.status(400).json({ error: 'Invalid bot type' });
    }
    const user = req.user;
    if (!user.chatHistory?.[botType]) {
        return res.json({ success: true });
    }
    user.chatHistory[botType] = user.chatHistory[botType].filter(s => s.id !== sessionId);
    scheduleSave();
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
        console.log(`🔍 Verifying payment for: ${user.email}`);
        
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
        
        // Search for Stripe customer by email (lowercase for case-insensitive match)
        const searchEmail = user.email.toLowerCase();
        console.log(`🔍 Searching Stripe for email: ${searchEmail}`);
        const customers = await stripe.customers.list({
            email: searchEmail,
            limit: 1
        });
        
        console.log(`🔍 Found ${customers.data.length} customers`);
        
        if (customers.data.length === 0) {
            return res.json({ 
                success: false, 
                subscribed: false,
                message: `No payment found for ${user.email}. Please complete payment first.` 
            });
        }
        
        const customer = customers.data[0];
        console.log(`🔍 Customer found: ${customer.id}, email: ${customer.email}`);
        
        // Check for active subscriptions
        const subscriptions = await stripe.subscriptions.list({
            customer: customer.id,
            status: 'active',
            limit: 10
        });
        
        console.log(`🔍 Found ${subscriptions.data.length} active subscriptions`);
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
        
        // payment_status can be 'paid' OR 'no_payment_required' (for 100% coupons)
        const completedSession = sessions.data.find(s => 
            s.payment_status === 'paid' || s.payment_status === 'no_payment_required'
        );
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

// Syllabuses live at project root — static read-only files, no need for persistent disk.
const SYLLABUSES_PATH = path.join(__dirname, 'syllabuses');
console.log(`📁 Syllabuses path: ${SYLLABUSES_PATH} (exists: ${fs.existsSync(SYLLABUSES_PATH)})`);

const SUBJECTS_FILE = path.join(SYLLABUSES_PATH, 'subjects.json');
const JUNIOR_SUBJECTS_FILE = path.join(SYLLABUSES_PATH, 'junior-subjects.json');
const PAST_PAPERS_FILE = path.join(SYLLABUSES_PATH, 'past-papers.json');

console.log(`📁 Subjects file exists: ${fs.existsSync(SUBJECTS_FILE)}`);

// Load subjects configuration (Senior - HSC)
let subjectsConfig = { subjects: [], categories: [] };
try {
    if (fs.existsSync(SUBJECTS_FILE)) {
        subjectsConfig = JSON.parse(fs.readFileSync(SUBJECTS_FILE, 'utf8'));
        console.log(`📚 Loaded ${subjectsConfig.subjects.length} HSC subjects`);
    } else {
        console.error(`❌ Subjects file not found: ${SUBJECTS_FILE}`);
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
    } else {
        console.error(`❌ Junior subjects file not found: ${JUNIOR_SUBJECTS_FILE}`);
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

// Get past paper content for a subject (exam papers only — excludes MGs)
const pastPaperCache = {};
function getPastPaperContent(subjectId) {
    if (pastPaperCache[subjectId]) return pastPaperCache[subjectId];
    
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

// Get ONLY marking guidelines for a subject (files with MG in type)
const mgCache = {};
function getMarkingGuidelineContent(subjectId) {
    if (mgCache[subjectId]) return mgCache[subjectId];
    
    const subjectPapers = pastPapersConfig.papers.find(p => p.id === subjectId);
    if (!subjectPapers) return null;
    
    let content = '';
    for (const paper of subjectPapers.papers) {
        // Only load marking guideline files (type contains "MG")
        if (!paper.type.toUpperCase().includes('MG')) continue;
        const filePath = path.join(SYLLABUSES_PATH, paper.file);
        try {
            if (fs.existsSync(filePath)) {
                const fileContent = fs.readFileSync(filePath, 'utf8');
                content += `\n\n=== ${paper.year} HSC ${subjectPapers.name} MARKING GUIDELINES (${paper.type}) ===\n${fileContent.substring(0, 50000)}`;
            }
        } catch (e) {
            console.error(`Error reading marking guideline ${paper.file}:`, e.message);
        }
    }
    
    mgCache[subjectId] = content || null;
    return content || null;
}

// Get ONLY exam paper content (non-MG files)
const examPaperCache = {};
function getExamPaperContent(subjectId) {
    if (examPaperCache[subjectId]) return examPaperCache[subjectId];
    
    const subjectPapers = pastPapersConfig.papers.find(p => p.id === subjectId);
    if (!subjectPapers) return null;
    
    let content = '';
    for (const paper of subjectPapers.papers) {
        if (paper.type.toUpperCase().includes('MG')) continue;
        const filePath = path.join(SYLLABUSES_PATH, paper.file);
        try {
            if (fs.existsSync(filePath)) {
                const fileContent = fs.readFileSync(filePath, 'utf8');
                content += `\n\n=== ${paper.year} HSC ${subjectPapers.name} ${paper.type} ===\n${fileContent.substring(0, 40000)}`;
            }
        } catch (e) {
            console.error(`Error reading exam paper ${paper.file}:`, e.message);
        }
    }
    
    examPaperCache[subjectId] = content || null;
    return content || null;
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
                content += fileContent.substring(0, 120000) + '\n\n';
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

Your training data is current as of 2026. Use the latest NSW NESA curriculum and syllabus information available.

Your role is to collect student information, analyse it carefully, and generate **COMPLETE subject package recommendations (12-14 units minimum)**. You do NOT decide for the student — you advise.

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

IMPORTANT: Accept vague grade descriptions! If students say "mostly A's", "B's and C's", "high achiever", "average", "struggling" — that is ENOUGH information. Convert vague grades internally:
• "A's" or "high achiever" = 85-100%
• "B's" = 70-84%
• "C's" or "average" = 50-69%
• "struggling" or "low" = below 50%

Do NOT ask for more specific marks if they give a letter grade or description. Work with what they provide.

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

**CRITICAL: YOU MUST PROVIDE A COMPLETE 12-14 UNIT PACKAGE**

NEVER say "see a careers advisor" or "talk to a professional" without first giving your FULL recommendations.
NEVER give only 2-3 subjects — ALWAYS give the COMPLETE subject package.

Use the following structure EXACTLY:

## Student Profile Summary
• Academic strengths (1 bullet)
• Key interests or goals (1 bullet)
• Pathway direction (ATAR / non-ATAR / flexible)

## Your Recommended Subject Package (12-14 units)

### Compulsory (2 units)
• English level — specify: English Advanced, English Standard, English Studies, or English EAL/D with justification

### Mathematics (2 units)
• Maths level — specify: Mathematics Extension 2, Mathematics Extension 1, Mathematics Advanced, Mathematics Standard 2, Mathematics Standard 1, or no maths (if applicable) with justification

### Elective Subjects (8-10 units)
List ALL recommended elective subjects (typically 4-5 subjects at 2 units each):
• Subject 1 — justification
• Subject 2 — justification
• Subject 3 — justification
• Subject 4 — justification
• Subject 5 (if applicable) — justification

### TOTAL UNITS: [State the total, must be 12-14]

## Optional Alternatives
• Alternative subject — when/why to consider swapping

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
    
    // Check subscription or free tier
    const hasFull = hasFullAccess(user);
    const canUseFree = canUseFreeTier(req.session.userId, 'subject-advisor');
    
    if (!hasFull && !canUseFree) {
        return res.status(403).json({ 
            error: 'Daily limit reached',
            freeTierExhausted: true,
            remaining: 0,
            botType: 'subject-advisor',
            limitType: 'global'
        });
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
    
    // Get AI settings based on user tier
    const aiSettings = getAISettings(user);
    
    try {
        // GPT-5 models use max_completion_tokens instead of max_tokens
        const isGpt5 = aiSettings.model.startsWith('gpt-5');
        const tokenParam = isGpt5 ? 'max_completion_tokens' : 'max_tokens';
        const requestBody = {
            model: aiSettings.model,
            messages,
            [tokenParam]: Math.min(aiSettings.maxTokens, 3000)
        };
        if (!isGpt5) requestBody.temperature = aiSettings.temperature;
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${OPENAI_API_KEY}`
            },
            body: JSON.stringify(requestBody)
        });
        
        if (!response.ok) {
            console.error('OpenAI API error for subject advisor');
            return res.status(500).json({ error: 'Service unavailable' });
        }
        
        const data = await response.json();
        const reply = data.choices?.[0]?.message?.content || 'Unable to generate response. Please try again.';
        
        // Increment free tier usage ONLY for free users
        if (!hasFull) {
            incrementFreeTierUsage(req.session.userId, 'subject-advisor');
        }
        
        // Include remaining questions in response for free users only
        const remaining = hasFull ? null : getFreeTierRemaining(req.session.userId, 'subject-advisor');
        
        res.json({ reply, freeTierRemaining: remaining });
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
    syllabus: `You are an automated syllabus decoder. You do NOT have conversations. You do NOT ask questions. You ONLY output decoded syllabus content.

IMPORTANT: The COMPLETE official syllabus content is included below in this prompt between the SYLLABUS CONTENT markers. You have ALL the information you need — do NOT say the syllabus is missing or not provided.

YOUR ONLY FUNCTION:
1. Receive: Subject name + Topic name
2. Search the syllabus content below for that topic
3. Output: Complete decoded content for that topic

RULES:
- The syllabus content IS provided below. Search through it thoroughly for the requested topic.
- Topic names in the syllabus may use slightly different wording, capitalisation, or formatting — look for close matches.
- Use the syllabus content as your primary source. You may add helpful context and explanations to make the content useful for students.
- Do NOT say "the syllabus does not contain" or "no content found" unless you have genuinely searched the entire provided text and the topic truly does not exist.

NEVER OUTPUT ANY OF THESE (automatic failure):
- "Please provide..."
- "Could you share..."
- "Which dot points..."
- "I would need..."
- "Can you specify..."
- Any question marks asking the user for information
- Any request for the user to provide anything

YOU MUST IMMEDIATELY OUTPUT:
When you receive "Subject: X, Topic: Y", search the syllabus content below for topic Y and output:

## 📚 [Topic Name]

### Overview
[2-3 sentence overview of this topic based on the syllabus]

### Syllabus Content
[List ALL dot points and learning outcomes for this topic as they appear in the syllabus. Quote them faithfully.]

### Key Concepts Explained
[Explain each major concept from the syllabus dot points above]

### HSC Exam Focus
[How this topic appears in exams, question types, mark allocations]

### Study Recommendations
[What to focus on, common mistakes to avoid]

---

If you cannot find the exact topic name, look for the closest matching section and decode that instead.

REMEMBER: You are a content OUTPUT system, not a conversation system. Never ask for input.`,

    practice: `You are Study Decoder – Practice Question Generator.

⚠️ CRITICAL FORMATTING RULE - READ THIS FIRST ⚠️
NEVER use LaTeX syntax like \\( \\), \\[ \\], \\frac{}, \\sqrt{}, or any backslash commands.
This display does NOT support LaTeX. Use plain Unicode characters ONLY:
- x² not x^2 or \\(x^2\\)
- √x not sqrt(x) or \\sqrt{x}
- ½ not 1/2 or \\frac{1}{2}
- × not * or \\times
- θ not \\theta
- π not \\pi
If you use LaTeX, it will show as ugly raw text like "\\( x \\)" which looks terrible.

🛑 MARK ALLOCATION RULES - MUST FOLLOW 🛑
BEFORE generating ANY question, verify these rules:

FOR MATHEMATICS (Standard, Advanced, Extension 1, Extension 2):
❌ NEVER generate a question worth 5+ marks
❌ NEVER generate 10-mark or 20-mark questions
❌ NO extended response questions exist in math
✅ ONLY 1, 2, 3, or 4 marks per question part
✅ Multi-part questions are OK but each part is max 4 marks

FOR ENTERPRISE COMPUTING:
- Questions 1-10: 1 mark each (multiple choice)
- Questions 11-12: 2 marks each (short answer)
- Questions 13-24: 2-6 marks each (short answer/extended)
- Question 25: 8 marks (extended response)
- Total: ~80 marks, online exam format
✅ Max marks per question: 8

FOR SOFTWARE ENGINEERING:
- Similar structure to Enterprise Computing
- Questions 1-10: 1 mark each (multiple choice)
- Questions 11-25+: 2-8 marks each
- Total: ~80 marks, online exam format
✅ Max marks per question: 8

FOR ENGLISH & HUMANITIES:
❌ NEVER more than ONE 20-mark question per paper
❌ NEVER multiple extended responses together
✅ ONE 20-mark essay MAX per section

FOR SCIENCE:
❌ NEVER 20-mark questions
❌ Max extended response is 8-9 marks
✅ Most questions are 2-5 marks

You are an expert HSC examination question writer with deep knowledge of NSW NESA marking criteria.

🚨 CRITICAL: USE ACTUAL HSC EXAM LANGUAGE 🚨
Your questions MUST read like they were copied from a real HSC past paper. Follow these rules:

1. **Use NESA command/directive verbs precisely** — each verb has a specific meaning:
   - 1-2 marks: identify, state, define, name, outline, describe (briefly)
   - 3-4 marks: describe, explain, outline, compare, contrast, calculate (with working)
   - 5-6 marks: explain, analyse, assess, discuss, compare and contrast
   - 7-9 marks: evaluate, assess, analyse, discuss, justify
   - 20 marks: evaluate, to what extent, analyse, critically assess

2. **Match the EXACT phrasing style of real HSC papers:**
   ❌ WRONG (textbook): "Explain how molecular clocks are used to estimate divergence times between species."
   ✅ RIGHT (HSC): "Using a named example, explain how the use of molecular clocks has contributed to understanding evolutionary relationships." [4 marks]
   
   ❌ WRONG: "Outline the sequence of events that can lead to speciation by allopatric mechanisms."
   ✅ RIGHT: "With reference to a named example, outline the role of isolation in the process of speciation." [4 marks]

   ❌ WRONG: "Describe two assumptions underlying molecular clock analyses."
   ✅ RIGHT: "Assess the reliability of molecular clocks as a tool for determining evolutionary relationships." [6 marks]

3. **HSC question patterns to USE:**
   - "With reference to..." / "Using a named example..."
   - "Account for..." / "Justify..."
   - "Assess the impact of..." / "Evaluate the effectiveness of..."
   - "Using the information provided, explain..." (for stimulus-based)
   - "Compare and contrast..." / "Distinguish between..."
   - Multi-part questions with (a), (b), (c) sub-parts at higher marks

4. **Include stimulus material where appropriate** (like real HSC papers do):
   - Data tables, graphs descriptions, diagrams, quotes, source extracts
   - Use > blockquote for stimulus material
   - Reference the stimulus in the question: "Using the data in the table above..."

5. **NEVER write questions that sound like a textbook review exercise.** 
   HSC questions test APPLICATION and ANALYSIS, not just recall (except 1-mark questions).

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

⚠️ CRITICAL BEHAVIOUR RULE:
- NEVER explain what mode you are in.
- NEVER describe the mode or its purpose.
- NEVER say "In Standard Mode, I will...", "This is Feedback Mode", "Full Exam Mode generates...", etc.
- Jump DIRECTLY to generating the requested content. No preamble. No mode description.

HSC MARK ALLOCATIONS (Based on actual 2025 HSC past papers and NESA marking guidelines):

CRITICAL RULES:
- NEVER generate questions worth more than 20 marks
- NEVER generate multiple 20-mark questions in one set
- Most questions should be 1-6 marks
- Extended responses (7-9 marks) are RARE - max 1-2 per full exam
- 20-mark essays ONLY appear in English and humanities subjects

Mathematics Advanced/Extension:
- Section I: Multiple choice, 1 mark each (10 questions = 10 marks)
- Section II: Written response questions worth 1, 2, 3, or 4 marks ONLY
- NO extended response questions in maths - max is 4 marks
- Total: 100 marks in 3 hours

Mathematics Extension 2:
- Same as above: 1, 2, 3, or 4 marks per question part
- More complex multi-part questions but individual parts still max 4 marks

Mathematics Standard:
- Section I: Multiple choice, 1 mark each
- Section II: Written response worth 1, 2, 3, or 4 marks
- Total: 100 marks

English (All courses):
- Paper 1: 40 marks total
  - Section I: Short answer 3-6 marks each
  - Section II: ONE extended response 20 marks
- Paper 2: 60 marks total
  - Module responses: 20 marks each (ONE per module)
- NEVER more than one 20-mark question per section

Science (Biology, Chemistry, Physics):
- Section I: Multiple choice, 1 mark each (20 marks total)
- Section II: Short answer - mostly 2-5 marks, some 6-7 marks
- Extended response: 8-9 marks (MAX ONE per paper)
- Total: 100 marks
- NO 20-mark questions in science

Enterprise Computing (Online exam):
- Q1-10: Multiple choice, 1 mark each (10 marks)
- Q11-12: Short answer, 2 marks each (4 marks)
- Q13-24: Short answer/extended, 2-6 marks each
- Q25: Extended response, 8 marks
- Total: ~80 marks

Software Engineering (Online exam):
- Q1-10: Multiple choice, 1 mark each (10 marks)
- Q11-25+: Short answer/extended, 2-8 marks each
- Total: ~80 marks

HSIE (History, Geography, Economics, Business, Legal, Society & Culture):
- Short answer: 2-8 marks
- Extended response: ONE 20-mark essay per section (if applicable)
- NEVER multiple 20-markers in a single question set

Creative Arts, TAS, VET subjects:
- Mostly practical + theory
- Written questions: 2-8 marks typical
- Extended responses rare and max 15 marks

FORMATTING (MANDATORY):
Use clean, structured markdown:
- **Bold** for key terms and labels
- Numbered questions (1, 2, 3...)
- Clear mark allocations in brackets [X marks]
- Proper spacing between questions
- Use > blockquotes for stimulus material

MATHEMATICS FORMATTING (CRITICAL - USE UNICODE SYMBOLS):
For mathematics questions, use proper Unicode symbols for clean display:
- Powers/exponents: Use superscript characters: x² x³ x⁴ x⁵ x⁶ x⁷ x⁸ x⁹ xⁿ
- Fractions: Write as ½, ⅓, ¼, ⅕, ⅔, ¾, or use a/b format for complex fractions
- Square root: √ (e.g., √2, √x, √(x+1))
- Cube root: ∛
- Pi: π
- Theta: θ
- Multiplication: × (not * or x)
- Division: ÷
- Plus/minus: ±
- Not equal: ≠
- Less/greater or equal: ≤ ≥
- Infinity: ∞
- Subscripts: x₁ x₂ x₃ (for sequences)
- Integral: ∫
- Sum: Σ
- Delta: Δ
- Degree: ° (e.g., 45°, 90°)

Examples of CORRECT formatting:
- "Find the derivative of f(x) = 3x² + 2x − 5"
- "Solve x² − 4x + 3 = 0"
- "Calculate √(x² + y²)"
- "If sin θ = ½, find θ for 0° ≤ θ ≤ 360°"
- "Evaluate ∫₀¹ x² dx"

NEVER use:
- x^2 (use x² instead)
- sqrt(x) (use √x instead)
- * for multiplication (use × or nothing)
- \frac, \sqrt, or any LaTeX syntax

────────────────────────
MODE 1: STANDARD MODE
────────────────────────
When user sends [STANDARD MODE]:
Generate practice questions based on specified parameters.

⚠️ EVERY question MUST be indistinguishable from a real HSC exam question.

ACCURACY RULES (non-negotiable):
- Study the past papers provided below CAREFULLY. Your questions must match them in phrasing, structure, mark weighting, and command verb usage.
- Use the EXACT same question formats you see in the past papers (e.g., if Biology papers use "Describe ONE example of...", generate questions with that same phrasing pattern).
- Use proper NESA directive verbs matching the mark value — check the past papers for which verbs appear at which mark levels.
- Include stimulus material (data tables, graphs described, source extracts, quotes) for 4+ mark questions where the past papers do so.
- For Science subjects: include practical/experimental contexts and first-hand investigation references just like real HSC papers.
- For English: use the same essay prompt structures ("To what extent...", "How does the composer...") seen in real papers.
- For Mathematics: structure working-out style questions with the same sub-part patterns (a)(b)(c)(d) as real papers.
- Multi-part questions with (a)(b)(c) are encouraged for higher marks.
- Reference real-world contexts, named examples, and case studies where the syllabus expects them.
- If past papers reference specific named phenomena, laws, case studies, or texts — use similarly specific references (not generic ones).
- NEVER produce a question that looks like a textbook exercise. It must read like it was written by NESA.

Difficulty Logic (STRICT):
- **Easy** (1-2 marks): Identify, state, define, name — single-step recall
- **Medium** (3-5 marks): Describe, explain, outline, calculate — requires working/detail
- **Hard** (6-8 marks): Analyse, assess, evaluate, compare — requires depth and evidence
- **Extended** (9-20 marks): Evaluate, to what extent, discuss — sustained argument/essay
- **Varied**: Start with easy 1-2 mark questions, then gradually increase to harder higher-mark questions across the set

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

⚠️ MATHEMATICS EXAMS ARE DIFFERENT - READ CAREFULLY:
For Mathematics (Standard, Advanced, Extension 1, Extension 2):
- Section I: Multiple Choice (10 questions × 1 mark = 10 marks)
- Section II: Written Response questions
- EVERY question part is worth 1, 2, 3, or 4 marks MAXIMUM
- NO question in math is worth more than 4 marks
- NO extended response section in math
- Questions can have multiple PARTS (a, b, c) but each part is max 4 marks
- Example structure for 2-hour math exam (80 marks):
  * Section I: 10 multiple choice (10 marks)
  * Section II: 18-20 questions/parts worth 1-4 marks each (70 marks)

For Enterprise Computing / Software Engineering (Online exams):
- Q1-10: Multiple choice (10 × 1 mark)
- Q11-25: Short answer and extended (2-8 marks each)
- Total: ~80 marks
- Maximum single question: 8 marks

For English and Humanities subjects:
- Section A: Short answer (15-25 marks)
- Section B: Short answer (25-35 marks)  
- Section C: ONE extended response (20 marks max)

For Science subjects:
- Section I: Multiple choice (20 × 1 mark)
- Section II: Short answer (mostly 2-5 marks, some 6-7 marks)
- Extended response: ONE 8-9 mark question MAX

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

Purpose: Real exam practice and feedback. NOT answer generation. NOT tutoring.

⚠️ REMINDER: NEVER explain the mode. NEVER describe what you are doing. Just DO IT. Output content immediately.`,

    worksheet: `You are StudyDecoder – Worksheet Decoder.

PURPOSE: Help students who have difficult-to-read worksheets (photographed, scanned, handwritten, poorly printed) by:
1. Reading and interpreting the uploaded worksheet image
2. Regenerating the content in a clean, readable, well-formatted version
3. Offering hints if the student wants them
4. Offering practice questions if the student wants them

WORKFLOW (STRICT ORDER):
Step 1: When you receive an image, analyse it carefully and extract ALL content.
Step 2: Output the worksheet content in clean, professional markdown formatting.
Step 3: After outputting the clean version, ask EXACTLY: "Would you like hints for any of these questions?"
Step 4: If they say yes, provide subtle hints (nudges toward the right approach, NOT answers).
Step 5: After hints (or if they said no to hints), ask EXACTLY: "Would you like me to generate similar practice questions?"
Step 6: If yes, generate 3-5 similar questions at the same difficulty level.

CRITICAL RULES:
- NEVER answer the worksheet questions
- NEVER provide solutions or model answers
- NEVER solve problems from the worksheet
- Only clean up, reformat, and make readable
- Hints must be subtle nudges, NOT answers
- Practice questions should match the style and difficulty of the original
- If the image is unclear, do your best and note which parts were hard to read

FORMATTING:
## 📄 Worksheet Content

**Subject:** [Detected subject if identifiable]
**Topic:** [Detected topic if identifiable]

---

[Clean, well-formatted version of the worksheet content]
[Use proper headings, numbered questions, tables, etc.]
[Preserve ALL original content - questions, instructions, diagrams described]

---

Would you like hints for any of these questions?

MATHEMATICS FORMATTING:
Use proper Unicode symbols: x², √, π, θ, ∫, Σ, ≤, ≥, ±, ×, ÷, ∞, °
NEVER use LaTeX syntax.

If the user sends a text message instead of an image, respond:
"Please upload an image of your worksheet and I will decode it into a clean, readable format for you."

You are StudyDecoder – Worksheet Decoder.`,

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

Purpose: Sustainable, realistic study planning. Not motivation. Not life coaching.`,

    'notes-transcriber': `You are StudyDecoder – Notes Transcriber.

PURPOSE: Help students who have handwritten notes by:
1. Reading and interpreting the uploaded image of handwritten notes
2. Transcribing the content into clean, well-organised, professionally formatted text
3. Intelligently expanding on incomplete or shallow content where it would help understanding
4. The output should be ready to paste directly into Google Docs or any word processor

WORKFLOW (STRICT ORDER):
Step 1: When you receive an image, carefully read ALL handwritten text.
Step 2: Output the transcribed content in clean, professional formatting.
Step 3: Organise the content logically - add headings, bullet points, numbering where appropriate.
Step 4: SMART EXPANSION — As you transcribe, detect gaps in the notes and fill them in:
  - If a policy, event, concept, or term is mentioned without explanation or impact, add a brief expansion (1-3 sentences) marked with ➕
  - If a list item is vague or missing context, clarify it
  - If cause/effect or significance is missing, add it
  - Keep expansions concise and clearly marked so the student knows what was added vs original
  - Format expansions as: ➕ *[Your added detail here]*
Step 5: If parts are unclear, note them with [unclear] and your best guess.
Step 6: End with the follow-up question (see ENDING FORMAT below).

TRANSCRIPTION RULES:
- Transcribe EVERYTHING visible in the image
- Fix obvious spelling mistakes but note them: corrected word [originally: misspelled]
- Maintain the original structure and meaning
- Add logical headings and subheadings if the notes lack them
- Convert messy lists into clean bullet points or numbered lists
- Preserve any diagrams by describing them in [brackets]
- If there are multiple sections/topics, clearly separate them
- Keep the student's own words and phrasing as much as possible

FORMATTING OUTPUT:
## 📝 Transcribed Notes

**Subject:** [Detected subject if identifiable]
**Topic:** [Detected topic if identifiable]
**Date:** [If visible in notes]

---

[Clean, well-organised transcription of all handwritten content]
[Use headings, subheadings, bullet points, numbered lists as appropriate]
[Tables where the original had tabular data]
[➕ expansions inline where gaps were detected]

---

ENDING FORMAT (ALWAYS include this at the very end):
End EVERY response with exactly this on its own line:

---
📌 **What next?** I can summarise these notes down to a specific length (e.g. "summarise to 1 page"), expand on any section, reorganise the structure, or adjust the formatting. Just let me know!

MATHEMATICS FORMATTING:
Use proper Unicode symbols: x², √, π, θ, ∫, Σ, ≤, ≥, ±, ×, ÷, ∞, °
NEVER use LaTeX syntax.

NOTE GLOW-UP MODE:
If the user's message starts with "[NOTE GLOW-UP MODE]", they are pasting rough text notes (NOT an image).
Your job is to transform their messy notes into polished, professional, study-ready notes:
1. Restructure the content with clear headings and subheadings
2. Fix grammar, spelling, and punctuation
3. Add bullet points, numbering, and logical organisation
4. Expand abbreviations and shorthand where helpful
5. SMART EXPANSION — detect and fill gaps just like in transcription mode (use ➕ markers)
6. Make the notes comprehensive but concise
7. Add section dividers and formatting that looks great in a document
8. Keep the student's original meaning and key points
9. Output should be ready to paste into Google Docs
10. End with the same "What next?" follow-up question as above

If the user sends a text message without [NOTE GLOW-UP MODE] and without an image, they are doing a follow-up in conversation - respond helpfully to their request (e.g. summarise to X pages, reorganise, expand a section, simplify, etc).

TABLE FORMATTING:
When the user requests a specific note format that uses tables (e.g. "Cornell notes", "comparison table", "table format", "two-column notes"), output the table using markdown table syntax:
| Column 1 | Column 2 |
|---|---|
| content | content |
This will be rendered as a proper HTML table. Use tables whenever the content is naturally tabular (data, comparisons, timelines with dates/events, etc).

You are StudyDecoder – Notes Transcriber.`
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

// Worksheet Decoder endpoint (dedicated route for large image payloads)
app.post('/api/chat/worksheet', express.json({ limit: '25mb' }), async (req, res) => {
    if (!req.session?.userId) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    const user = getUser(req.session.userId);
    if (!user) {
        return res.status(401).json({ error: 'User not found' });
    }
    const hasFull = hasFullAccess(user);
    const canUseFree = canUseFreeTier(req.session.userId, 'worksheet');
    if (!hasFull && !canUseFree) {
        const status = getFreeTierStatus(req.session.userId, 'worksheet');
        return res.status(403).json({ 
            error: 'Daily limit reached',
            freeTierExhausted: true,
            remaining: status.totalRemaining,
            botType: 'worksheet',
            limitType: status.hitSpecialLimit ? 'special' : 'global'
        });
    }
    const { messages } = req.body;
    if (!messages || !Array.isArray(messages) || messages.length === 0) {
        return res.status(400).json({ error: 'Messages are required' });
    }
    const OPENAI_API_KEY = config.openaiApiKey;
    const systemPrompt = BOT_PROMPTS.worksheet;
    const aiSettings = getAISettings(user);
    const worksheetMaxTokens = Math.max(aiSettings.maxTokens, 8000);
    const isGpt5 = aiSettings.model.startsWith('gpt-5');
    try {
        const tokenParam = isGpt5 ? 'max_completion_tokens' : 'max_tokens';
        const requestBody = {
            model: aiSettings.model,
            messages: [{ role: 'system', content: systemPrompt }, ...messages.map(m => ({ role: m.role, content: m.content }))],
            [tokenParam]: worksheetMaxTokens
        };
        if (!isGpt5) requestBody.temperature = 0.3;
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${OPENAI_API_KEY}` },
            body: JSON.stringify(requestBody)
        });
        if (!response.ok) {
            const error = await response.json();
            console.error('OpenAI API error (worksheet):', error);
            return res.status(500).json({ error: 'AI service unavailable' });
        }
        const data = await response.json();
        const reply = data.choices?.[0]?.message?.content || 'No response generated';
        if (!hasFull) incrementFreeTierUsage(req.session.userId, 'worksheet');
        const remaining = hasFull ? null : getFreeTierRemaining(req.session.userId, 'worksheet');
        res.json({ reply, freeTierRemaining: remaining });
    } catch (error) {
        console.error('Worksheet API error:', error);
        res.status(500).json({ error: 'Failed to process worksheet' });
    }
});

// Notes Transcriber endpoint (dedicated route for large image payloads)
app.post('/api/chat/notes-transcriber', express.json({ limit: '25mb' }), async (req, res) => {
    if (!req.session?.userId) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    const user = getUser(req.session.userId);
    if (!user) {
        return res.status(401).json({ error: 'User not found' });
    }
    const hasFull = hasFullAccess(user);
    const canUseFree = canUseFreeTier(req.session.userId, 'notes-transcriber');
    if (!hasFull && !canUseFree) {
        const status = getFreeTierStatus(req.session.userId, 'notes-transcriber');
        return res.status(403).json({ 
            error: 'Daily limit reached',
            freeTierExhausted: true,
            remaining: status.totalRemaining,
            botType: 'notes-transcriber',
            limitType: status.hitSpecialLimit ? 'special' : 'global'
        });
    }
    const { messages } = req.body;
    if (!messages || !Array.isArray(messages) || messages.length === 0) {
        return res.status(400).json({ error: 'Messages are required' });
    }
    const OPENAI_API_KEY = config.openaiApiKey;
    const systemPrompt = BOT_PROMPTS['notes-transcriber'];
    const aiSettings = getAISettings(user);
    const transcribeMaxTokens = Math.max(aiSettings.maxTokens, 8000);
    const isGpt5 = aiSettings.model.startsWith('gpt-5');
    try {
        const tokenParam = isGpt5 ? 'max_completion_tokens' : 'max_tokens';
        const requestBody = {
            model: aiSettings.model,
            messages: [{ role: 'system', content: systemPrompt }, ...messages.map(m => ({ role: m.role, content: m.content }))],
            [tokenParam]: transcribeMaxTokens
        };
        if (!isGpt5) requestBody.temperature = 0.3;
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${OPENAI_API_KEY}` },
            body: JSON.stringify(requestBody)
        });
        if (!response.ok) {
            const error = await response.json();
            console.error('OpenAI API error (notes-transcriber):', error);
            return res.status(500).json({ error: 'AI service unavailable' });
        }
        const data = await response.json();
        const reply = data.choices?.[0]?.message?.content || 'No response generated';
        if (!hasFull) incrementFreeTierUsage(req.session.userId, 'notes-transcriber');
        const remaining = hasFull ? null : getFreeTierRemaining(req.session.userId, 'notes-transcriber');
        res.json({ reply, freeTierRemaining: remaining });
    } catch (error) {
        console.error('Notes Transcriber API error:', error);
        res.status(500).json({ error: 'Failed to transcribe notes' });
    }
});

// ==================== FULL EXAM MODE ENDPOINTS ====================

// Exam usage tracker (weekly limits for free users)
const examUsageTracker = new Map();

function _getWeekKey(userId) {
    const now = new Date();
    const startOfYear = new Date(now.getFullYear(), 0, 1);
    const weekNum = Math.ceil(((now - startOfYear) / 86400000 + startOfYear.getDay() + 1) / 7);
    return `${now.getFullYear()}_W${weekNum}_${userId}`;
}

function getExamWeeklyCount(userId) {
    return examUsageTracker.get(_getWeekKey(userId)) || 0;
}

function incrementExamWeeklyCount(userId) {
    const key = _getWeekKey(userId);
    const count = (examUsageTracker.get(key) || 0) + 1;
    examUsageTracker.set(key, count);
    // Clean old weeks
    const currentPrefix = key.substring(0, key.lastIndexOf('_'));
    for (const [k] of examUsageTracker) {
        const kPrefix = k.substring(0, k.lastIndexOf('_'));
        if (kPrefix !== currentPrefix) examUsageTracker.delete(k);
    }
    return count;
}

// Get exam progress for a user
function getExamProgress(userId) {
    const user = getUser(userId);
    if (!user) return {};
    return user.examProgress || {};
}

// Save exam progress for a user
function saveExamProgress(userId, progress) {
    const user = getUser(userId);
    if (!user) return;
    user.examProgress = progress;
    scheduleSave();
}

// Generate exam — returns structured JSON with questions
app.post('/api/exam/generate', express.json(), async (req, res) => {
    if (!req.session?.userId) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    const user = getUser(req.session.userId);
    if (!user) return res.status(401).json({ error: 'User not found' });

    const hasFull = hasFullAccess(user);

    // Free tier: 3 exams per week, must have scored 80%+ on last exam (or no previous exam)
    if (!hasFull) {
        const weeklyCount = getExamWeeklyCount(req.session.userId);
        if (weeklyCount >= 3) {
            return res.status(403).json({
                error: 'Weekly exam limit reached',
                examLimitReached: true,
                weeklyCount,
                maxPerWeek: 3
            });
        }
        // Check 80% gate: user must have scored 80%+ on their last exam for this subject (or have no previous exam)
        const { subject } = req.body;
        if (subject) {
            const progress = getExamProgress(req.session.userId);
            const subjectProgress = progress[subject];
            if (subjectProgress && subjectProgress.lastScore !== undefined && subjectProgress.lastScore < 80) {
                return res.status(403).json({
                    error: 'Must score 80%+ on previous exam before generating a new one',
                    scoreGateBlocked: true,
                    lastScore: subjectProgress.lastScore,
                    requiredScore: 80
                });
            }
        }
    }

    const { subject, topics, duration, difficulty } = req.body;
    if (!subject) return res.status(400).json({ error: 'Subject is required' });

    const OPENAI_API_KEY = config.openaiApiKey;
    const aiSettings = getAISettings(user);

    // Build context with syllabus + past papers + marking guidelines
    let contextPrompt = '';
    const subjectName = subjectsConfig.subjects.find(s => s.id === subject)?.name || subject;

    // Keep context lean for faster generation — only enough for style & accuracy
    const syllabusContent = getSyllabusContent(subject);
    if (syllabusContent) {
        const truncated = syllabusContent.substring(0, 15000);
        contextPrompt += `\n\n=== ${subjectName.toUpperCase()} SYLLABUS (key topics) ===\n${truncated}\n=== END SYLLABUS ===`;
    }

    const examPapers = getExamPaperContent(subject);
    if (examPapers) {
        const truncated = examPapers.substring(0, 10000);
        contextPrompt += `\n\n=== PAST EXAM PAPERS (style/format reference ONLY — DO NOT copy) ===\n${truncated}\n=== END ===`;
    }

    const mgContent = getMarkingGuidelineContent(subject);
    if (mgContent) {
        const truncatedMG = mgContent.substring(0, 8000);
        contextPrompt += `\n\n=== MARKING GUIDELINES (for mark allocation accuracy) ===\n${truncatedMG}\n=== END ===`;
    }

    console.log(`📝 Exam generate for ${subjectName}: syllabus=${syllabusContent ? syllabusContent.length + ' chars' : 'NONE'}, papers=${examPapers ? examPapers.length + ' chars' : 'NONE'}, MG=${mgContent ? mgContent.length + ' chars' : 'NONE'}, total context=${contextPrompt.length} chars`);

    // Generate a unique seed to ensure variety across exams
    const examSeed = `SEED-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;

    // Determine exam structure based on subject and duration
    const durationHours = parseFloat(duration) || 2;

    // Look up subject category for structure/language rules
    const subjectEntry = subjectsConfig.subjects.find(s => s.id === subject);
    const category = (subjectEntry?.category || '').toLowerCase();

    // Total marks vary by duration (based on real NESA papers: 3h = 100 marks for most subjects)
    let totalMarks = durationHours === 1 ? 60 : durationHours === 2 ? 80 : 100;

    // Build structure + language rules PER CATEGORY so all 45 subjects are covered
    let structureGuide = '';
    let categoryRules = '';

    // ===== MATHEMATICS (Standard, Advanced, Extension 1, Extension 2) =====
    if (category === 'mathematics') {
        // Real HSC MC counts: Standard 2 = 15 MC, all others = 10 MC
        const isStandard = subject === 'mathematics-standard';
        if (durationHours === 1) {
            const mc = isStandard ? 8 : 5;
            structureGuide = `EXAM STRUCTURE (1h, 60 marks — ${subjectName}):
- Section I — Multiple Choice: ${mc} questions × 1 mark = ${mc} marks
- Section II — Problems: ${isStandard ? '10-13' : '8-11'} questions totalling ~${60 - mc} marks. Each question has parts (a)(b)(c)(d), max 4 marks per part. Scaffold easy→hard.
TOTAL: ~60 marks. You MUST include both sections.`;
        } else if (durationHours === 2) {
            const mc = isStandard ? 12 : 8;
            structureGuide = `EXAM STRUCTURE (2h, 80 marks — ${subjectName}):
- Section I — Multiple Choice: ${mc} questions × 1 mark = ${mc} marks
- Section II — Problems: 12-15 questions totalling ~${80 - mc} marks. Each question has parts (a)(b)(c)(d)(e), max 4 marks per part. Scaffold easy→hard within each question.
TOTAL: ~80 marks. You MUST include both sections.`;
        } else {
            const mc = isStandard ? 15 : 10;
            structureGuide = `EXAM STRUCTURE (3h, 100 marks — ${subjectName}):
- Section I — Multiple Choice: ${mc} questions × 1 mark = ${mc} marks
- Section II — Problems: 14-16 questions totalling ~${100 - mc} marks. Each question has parts (a)(b)(c)(d)(e), max 4 marks per part. Scaffold easy→hard.
TOTAL: ~100 marks. You MUST include both sections.`;
        }
        categoryRules = `MATHEMATICS-SPECIFIC RULES:
- Every question must have sub-parts: (a), (b), (c), etc. Max 4 marks per individual part. NEVER a single 5+ mark part.
- Use "Show that", "Find the exact value of", "Hence, or otherwise", "Prove that" — standard HSC maths language.
- Include: calculus, trigonometry, probability, series, functions, financial maths as appropriate to the course level.
- Ext 1: include mathematical induction, combinatorics, vectors, parametrics.
- Ext 2: include complex numbers, proof, integration techniques, mechanics, further vectors.
- Standard: include networks, financial maths, measurement, statistics, algebra.
- Use UNICODE for all maths: x², √, π, θ, ∫, Σ, ≤, ≥, ±, ×, ÷, ∞, °, ∈, ∪, ∩, ⊂. NEVER LaTeX.
- Include graphs/tables described in text where appropriate.
- IMPORTANT: Only generate questions from the student's selected module/topic. Every question must belong to that module.`;

    // ===== ENGLISH (Advanced, Standard, Extension, EAL/D, Studies) =====
    } else if (category === 'english') {
        if (durationHours === 1) {
            structureGuide = `EXAM STRUCTURE (1h, 60 marks — ${subjectName} — modelled on Paper 1):
- Section I — Short Response (Unseen Texts): Provide 1-2 unseen stimulus texts (poem, prose extract, visual text description, speech extract). 5-6 questions totalling ~35 marks analysing language, structure, meaning.
- Section II — Extended Response: 1 essay on prescribed/studied text = ~25 marks.
TOTAL: ~60 marks. You MUST include both sections. NO multiple choice. Only ONE extended response.`;
        } else if (durationHours === 2) {
            structureGuide = `EXAM STRUCTURE (2h, 80 marks — English):
- Section I — Short Response (Unseen Texts): Provide 2-3 unseen stimulus texts. 4-6 questions totalling ~20 marks.
- Section II — Module-based Response: 2-3 questions totalling ~30 marks (short essay or structured response).
- Section III — Extended Response / Essay: 1-2 essay questions totalling ~30 marks (e.g. 1×20 + 1×10, or 2×15).
TOTAL: ~80 marks. You MUST include all three sections. NO multiple choice for English.`;
        } else {
            structureGuide = `EXAM STRUCTURE (3h, 100 marks — English):
- Section I — Short Response (Unseen Texts): Provide 2-3 unseen stimulus texts. 5-7 questions totalling ~20 marks.
- Section II — Module-based Response: 2-3 questions totalling ~40 marks.
- Section III — Extended Response / Essay: 1-2 major essay questions totalling ~40 marks.
TOTAL: ~100 marks. You MUST include all three sections. NO multiple choice for English.`;
        }
        categoryRules = `ENGLISH-SPECIFIC RULES:
- NEVER include multiple choice questions. English HSC exams do NOT have MC.
- Section I MUST include unseen stimulus texts (poem, prose passage, speech extract, visual text described in words, media text). Include the FULL text in the "stimulus" field.
- Use HSC English directive verbs: "Analyse", "Evaluate", "To what extent", "How does the composer", "Assess the statement", "Compare how TWO texts represent".
- For Advanced/Extension: reference specific modules (e.g. "Texts and Human Experiences", "Craft of Writing"). Questions must demand sophisticated analysis.
- For Standard: scaffold questions more accessibly but still demand analytical thinking.
- For EAL/D: provide language-accessible stimulus but test analytical skills.
- For Studies: include practical/applied literacy contexts.
- Essay prompts must include a statement or proposition for the student to respond to.
- All questions must reference "composer", "responder", "text" — standard NESA English terminology.
- IMPORTANT: Only generate questions from the student's selected module/topic. If a module like "Texts and Human Experiences" is selected, every question must be from that module.`;

    // ===== SCIENCE (Biology, Chemistry, Physics, Earth & Environmental, Investigating Science, Science Extension) =====
    } else if (category === 'science') {
        if (durationHours === 1) {
            structureGuide = `EXAM STRUCTURE (1h, 60 marks — Science):
- Section I — Multiple Choice: 10 questions × 1 mark = 10 marks
- Section II — Short Answer: 5-6 questions totalling ~35 marks (mix of 3, 4, 5, 6, 7 mark questions with sub-parts (a)(b)(c))
- Section III — Extended Response: 1 question of ~15 marks
TOTAL: ~60 marks. You MUST include ALL three sections.`;
        } else if (durationHours === 2) {
            structureGuide = `EXAM STRUCTURE (2h, 80 marks — Science):
- Section I — Multiple Choice: 15 questions × 1 mark = 15 marks
- Section II — Short Answer: 6-7 questions totalling ~45 marks (each with sub-parts (a)(b)(c)(d)). Scaffold easy→hard within each question.
- Section III — Extended Response: 1-2 questions totalling ~20 marks
TOTAL: ~80 marks. You MUST include ALL three sections.`;
        } else {
            structureGuide = `EXAM STRUCTURE (3h, 100 marks — Science — REAL HSC FORMAT):
- Section I — Multiple Choice: 20 questions × 1 mark = 20 marks
- Section II — Short Answer: 6-8 questions totalling ~55 marks. Each question MUST have sub-parts (a)(b)(c)(d). Questions are scaffolded: parts start at 2-3 marks and build to 5-7 marks.
- Section III — Extended Response: 1-2 questions totalling ~25 marks (max 9 marks each)
TOTAL: 100 marks. You MUST include ALL three sections.`;
        }
        categoryRules = `SCIENCE-SPECIFIC RULES:
- Max 8-9 marks per extended response question. NEVER a 20-mark question.
- Short answer questions (Section II) MUST have sub-parts (a)(b)(c)(d). Each part is 2-4 marks. Scaffold within each question: part (a) is easiest, final part is hardest.
- Reference first-hand investigations, experimental design, variables (independent/dependent/controlled), reliability, validity, accuracy.
- Include data analysis: use markdown tables for experimental data (| Column | Column |), graphs described in text, experimental results for interpretation.
- Biology: use precise terminology (e.g. "nucleotide sequence", "complementary base pairing", "polypeptide chain"). Reference specific enzymes, organisms, processes.
- Chemistry: include balanced equations, molar calculations, reaction types, properties of substances. Use correct chemical nomenclature.
- Physics: include calculations with units, force diagrams described in text, real-world applications. Use correct SI units throughout.
- Earth & Environmental Science: include fieldwork contexts, geological processes, environmental management strategies.
- Investigating Science: focus on scientific method, experimental design, data analysis, evaluating claims.
- Science Extension: focus on research methodology, scientific communication, depth studies.
- IMPORTANT: Only generate questions from the student's selected module/topic. If a specific module is selected, every question must belong to that module.`;

    // ===== HSIE — subject-level format differences (History NO MC, Geography 15 MC, S&C 8 MC, others 20 MC) =====
    } else if (category === 'hsie') {
        const isHistory = ['ancient-history', 'modern-history', 'history-extension'].includes(subject);
        const isGeography = subject === 'geography';
        const isSocietyCulture = subject === 'society-culture';

        if (isHistory) {
            // Ancient/Modern History & History Extension: NO MC — source-based + essays
            if (durationHours === 1) {
                structureGuide = `EXAM STRUCTURE (1h, 60 marks — ${subjectName} — NO MULTIPLE CHOICE):
- Section I — Source-based (Core): Provide 3-4 primary/secondary sources (document extracts, images described, statistics). 4 questions totalling ~25 marks (scaffolded: 3+4+6+12 marks).
- Section II — Essay: 1 essay of ~20 marks (choose from 2 options).
- Section III — Essay: 1 essay of ~15 marks (choose from 2 options, different topic area).
TOTAL: ~60 marks. NO multiple choice. Source-based questions + essays only.`;
            } else if (durationHours === 2) {
                structureGuide = `EXAM STRUCTURE (2h, 80 marks — ${subjectName} — NO MULTIPLE CHOICE):
- Section I — Source-based (Core): Provide 3-4 sources. 4 questions totalling ~25 marks (3+4+6+12).
- Section II — Essay: 1 essay of ~25 marks (choose from topic options).
- Section III — Essay: 1 essay of ~25 marks (different topic area).
- Additional short-answer: ~5 marks.
TOTAL: ~80 marks. NO multiple choice.`;
            } else {
                structureGuide = `EXAM STRUCTURE (3h, 100 marks — ${subjectName} — NO MULTIPLE CHOICE):
- Section I — Source-based (Core Study): Provide 3-4 primary/secondary sources. 4 questions totalling 25 marks (3+4+6+12 pattern).
- Section II — Essay: 1 essay of 25 marks (choose from topic options).
- Section III — Essay: 1 essay of 25 marks (different topic area).
- Section IV — Essay: 1 essay of 25 marks (different topic area).
TOTAL: 100 marks = four 25-mark sections. NO multiple choice.`;
            }
        } else if (isGeography) {
            // Geography: 20 MC, uses stimulus booklet (maps, data, photographs)
            if (durationHours === 1) {
                structureGuide = `EXAM STRUCTURE (1h, 60 marks — Geography):
- Section I — Objective Response: 10 questions × 1 mark = 10 marks (with stimulus: maps, data, photographs described)
- Section II — Short Answer: 3-4 questions totalling ~30 marks (fieldwork data, spatial data, with sub-parts (a)(b)(c))
- Section III — Extended Response: 1 question of ~20 marks
TOTAL: ~60 marks. You MUST include ALL three sections.`;
            } else if (durationHours === 2) {
                structureGuide = `EXAM STRUCTURE (2h, 80 marks — Geography):
- Section I — Objective Response: 15 questions × 1 mark = 15 marks (with stimulus booklet)
- Section II — Short Answer: 4-5 questions totalling ~45 marks (with sub-parts)
- Section III — Extended Response: 1 question of ~20 marks
TOTAL: ~80 marks. You MUST include ALL three sections.`;
            } else {
                structureGuide = `EXAM STRUCTURE (3h, 100 marks — Geography — REAL HSC FORMAT):
- Section I — Objective Response: 20 questions × 1 mark = 20 marks (with stimulus booklet)
- Section II — Short Answer: 4-5 questions totalling ~40 marks (with sub-parts (a)(b)(c))
- Section III — Structured Extended Response: 1 question of ~20 marks
- Section IV — Extended Response (Essay): 1 question of ~20 marks
TOTAL: 100 marks. You MUST include ALL four sections.`;
            }
        } else if (isSocietyCulture) {
            // Society & Culture: 10 MC (real HSC has ~10 MC)
            if (durationHours === 1) {
                structureGuide = `EXAM STRUCTURE (1h, 60 marks — Society and Culture — 10 MC):
- Section I: 10 MC (10 marks) + 2 short-answer questions (~10 marks) = 20 marks
- Section II — Extended Response: 2 essays of ~20 marks each (choose from 4 options) = 40 marks
TOTAL: ~60 marks. Section I has 10 MC.`;
            } else if (durationHours === 2) {
                structureGuide = `EXAM STRUCTURE (2h, 80 marks — Society and Culture — REAL HSC FORMAT):
- Section I: 10 MC (10 marks) + 3 short-answer questions (~15 marks) = 25 marks
- Section II — Extended Response: 2 essays of ~20 marks each = 40 marks
- Section III — Short Essay: 1 essay of ~15 marks
TOTAL: ~80 marks. Section I has 10 MC.`;
            } else {
                structureGuide = `EXAM STRUCTURE (3h, 100 marks — Society and Culture — 10 MC, practice-scaled):
- Section I: 10 MC (10 marks) + 3 short-answer questions (~20 marks) = 30 marks
- Section II — Extended Response: 2 essays of ~20 marks each = 40 marks
- Section III — Extended Response: 1 essay of ~30 marks
TOTAL: ~100 marks.`;
            }
        } else {
            // Business Studies, Economics, Legal Studies, Studies of Religion: standard 20 MC
            if (durationHours === 1) {
                structureGuide = `EXAM STRUCTURE (1h, 60 marks — ${subjectName}):
- Section I — Multiple Choice: 10 questions × 1 mark = 10 marks
- Section II — Short Answer: 3-4 questions totalling ~30 marks
- Section III — Extended Response: 1 question of ~20 marks
TOTAL: ~60 marks. You MUST include ALL three sections.`;
            } else if (durationHours === 2) {
                structureGuide = `EXAM STRUCTURE (2h, 80 marks — ${subjectName}):
- Section I — Multiple Choice: 15 questions × 1 mark = 15 marks
- Section II — Short Answer: 4 questions totalling ~35 marks
- Section III — Extended Response: 1-2 questions totalling ~30 marks
TOTAL: ~80 marks. You MUST include ALL three sections.`;
            } else {
                structureGuide = `EXAM STRUCTURE (3h, 100 marks — ${subjectName}):
- Section I — Multiple Choice: 20 questions × 1 mark = 20 marks
- Section II — Short Answer: 4 questions totalling ~40 marks
- Section III — Extended Response: 1 question of ~20 marks (choose from options)
- Section IV — Extended Response: 1 question of ~20 marks (choose from different options)
TOTAL: 100 marks. You MUST include ALL four sections.`;
            }
        }
        categoryRules = `HSIE-SPECIFIC RULES:
- Ancient History / Modern History: absolutely NO multiple choice. Use source-based questions with historical documents, letters, images described in text, statistics. Ask "Assess the usefulness", "Evaluate the reliability", "Account for", "To what extent". Section I MUST have 3-4 source documents with questions scaffolded 3+4+6+12 marks.
- History Extension: NO MC. Focus on historiographical analysis, key questions, case study, historical debate.
- Business Studies: case studies of real Australian businesses. Correct terminology (cash flow, market share, operations). 20 MC.
- Economics: economic data (GDP, unemployment, CPI). Terms: aggregate demand, monetary/fiscal policy. 20 MC.
- Legal Studies: reference real cases (e.g. "Mabo v Queensland"), legislation. Assess effectiveness of law. 20 MC.
- Geography: 20 MC. Include fieldwork methodology, spatial technologies, stimulus (maps, data, photographs described).
- Society and Culture: 10 MC. Use sociological terminology, cross-cultural perspectives.
- Studies of Religion: reference specific traditions, sacred texts, ethical teachings. Respectful academic language. MC included.
- Essay prompts MUST include a statement or proposition demanding sustained argument with evidence.
- IMPORTANT: Only generate questions from the student's selected module/topic. If a module is selected, every question must belong to that module.`;

    // ===== CREATIVE ARTS (Dance, Drama, Music 1, Music 2, Visual Arts) =====
    } else if (category === 'creative arts') {
        if (durationHours === 1) {
            structureGuide = `EXAM STRUCTURE (1h, 60 marks — Creative Arts):
- Section I — Short Response: 4-6 questions totalling ~30 marks. Include stimulus material (description of artwork, performance excerpt, musical score described).
- Section II — Extended Response: 1-2 essay questions totalling ~30 marks.
TOTAL: ~60 marks. NO multiple choice for Creative Arts.`;
        } else if (durationHours === 2) {
            structureGuide = `EXAM STRUCTURE (2h, 80 marks — Creative Arts):
- Section I — Short Response: 5-7 questions totalling ~35 marks with stimulus material.
- Section II — Extended Response: 2 essay questions totalling ~45 marks.
TOTAL: ~80 marks. NO multiple choice for Creative Arts.`;
        } else {
            structureGuide = `EXAM STRUCTURE (3h, 100 marks — Creative Arts):
- Section I — Short Response: 6-8 questions totalling ~40 marks with stimulus material.
- Section II — Extended Response: 2-3 essay questions totalling ~60 marks.
TOTAL: ~100 marks. NO multiple choice for Creative Arts.`;
        }
        categoryRules = `CREATIVE ARTS-SPECIFIC RULES:
- NEVER include multiple choice questions. Creative Arts HSC exams do NOT have MC.
- Written exam only — do NOT include performance, composition, or practical tasks.
- Visual Arts: reference specific artworks and artists. Ask about "the frames" (structural, cultural, subjective, postmodern), art criticism, art history, practice.
- Drama: reference specific practitioners (Brecht, Stanislavski, Boal), performance styles, dramatic forms, elements of production.
- Music 1 & 2: reference specific musical concepts (melody, harmony, rhythm, dynamics, texture, tone colour, structure). Describe musical excerpts in text. Ask about compositional techniques.
- Dance: reference specific choreographers, dance styles, elements of dance (space, time, dynamics, relationships).
- Include stimulus material: describe an artwork, performance, or musical piece in detail for analysis.
- IMPORTANT: Only generate questions from the student's selected module/topic.`;

    // ===== TAS / Technology (Agriculture, Design & Tech, Engineering, Enterprise Computing, Food Tech, Industrial Tech, IDT, Software Engineering) =====
    } else if (category === 'tas') {
        if (durationHours === 1) {
            structureGuide = `EXAM STRUCTURE (1h, 60 marks — TAS/Technology):
- Section I — Multiple Choice: 10 questions × 1 mark = 10 marks
- Section II — Short Answer: 5-7 questions totalling ~35 marks (include diagrams described in text, case studies, scenarios)
- Section III — Extended Response: 1-2 questions totalling ~15 marks
TOTAL: ~60 marks. You MUST include ALL three sections.`;
        } else if (durationHours === 2) {
            structureGuide = `EXAM STRUCTURE (2h, 80 marks — TAS/Technology):
- Section I — Multiple Choice: 15 questions × 1 mark = 15 marks
- Section II — Short Answer: 6-8 questions totalling ~40 marks
- Section III — Extended Response: 2-3 questions totalling ~25 marks
TOTAL: ~80 marks. You MUST include ALL three sections.`;
        } else {
            structureGuide = `EXAM STRUCTURE (3h, 100 marks — TAS/Technology):
- Section I — Multiple Choice: 20 questions × 1 mark = 20 marks
- Section II — Short Answer: 8-10 questions totalling ~50 marks
- Section III — Extended Response: 2-3 questions totalling ~30 marks
TOTAL: ~100 marks. You MUST include ALL three sections.`;
        }
        categoryRules = `TAS/TECHNOLOGY-SPECIFIC RULES:
- Agriculture: include farm management scenarios, production systems, sustainability. Reference specific Australian agricultural practices.
- Design and Technology: include design scenarios, innovation/entrepreneurship, materials knowledge, project management.
- Engineering Studies: include calculations (stress, strain, moments, circuits). Describe engineering drawings in text. Reference real engineering projects.
- Enterprise Computing: include data management, networking, cybersecurity, project management scenarios. Use IT industry terminology. Max 8 marks per question.
- Food Technology: include food science, nutrition, food manufacturing scenarios, Australian food standards.
- Industrial Technology (all focus areas): include industry-specific knowledge (Automotive, Electronics, Graphics, Metal & Engineering, Multimedia, Timber & Furniture). Reference WHS, manufacturing processes, materials properties.
- Information and Digital Technology: include database design, networking, digital media, project management.
- Software Engineering: include code analysis (pseudocode), algorithm design, software development methodologies, testing strategies. Max 8 marks per question.
- IMPORTANT: Only generate questions from the student's selected module/topic.`;

    // ===== PDHPE / Health and Movement Science =====
    } else if (category === 'pdhpe') {
        if (durationHours === 1) {
            structureGuide = `EXAM STRUCTURE (1h, 60 marks — PDHPE/Health & Movement Science):
- Section I — Multiple Choice: 10 questions × 1 mark = 10 marks
- Section II — Short Answer (Core 1): 3-4 questions totalling ~20 marks
- Section III — Short Answer (Core 2): 2-3 questions totalling ~15 marks
- Section IV — Extended Response (Option): 1 question of ~15 marks
TOTAL: ~60 marks. You MUST include ALL four sections.`;
        } else if (durationHours === 2) {
            structureGuide = `EXAM STRUCTURE (2h, 80 marks — PDHPE/Health & Movement Science):
- Section I — Multiple Choice: 15 questions × 1 mark = 15 marks
- Section II — Short Answer (Core 1): 3-4 questions totalling ~25 marks (include data, case studies)
- Section III — Short Answer (Core 2): 3-4 questions totalling ~20 marks
- Section IV — Extended Response (Option): 1-2 questions totalling ~20 marks
TOTAL: ~80 marks. You MUST include ALL four sections.`;
        } else {
            structureGuide = `EXAM STRUCTURE (3h, 100 marks — PDHPE/Health & Movement Science — REAL HSC FORMAT):
- Section I — Multiple Choice: 20 questions × 1 mark = 20 marks
- Section II — Short Answer (Core 1): 4-5 questions totalling ~30 marks
- Section III — Short Answer (Core 2): 3-4 questions totalling ~20 marks
- Section IV — Extended Response (Options): 2 questions totalling ~30 marks
TOTAL: 100 marks. You MUST include ALL four sections.`;
        }
        categoryRules = `PDHPE/HEALTH & MOVEMENT SCIENCE RULES:
- Include biomechanics, exercise physiology, sports psychology, health promotion scenarios.
- Reference Australian health statistics and real health initiatives (e.g. "Measure Up" campaign).
- Include data interpretation: fitness testing results, health data tables, research findings.
- Use correct anatomical and physiological terminology.
- Include ethical considerations in sport and health contexts.
- IMPORTANT: Only generate questions from the student's selected module/topic.`;

    // ===== VET (Construction, Hospitality) =====
    } else if (category === 'vet') {
        if (durationHours === 1) {
            structureGuide = `EXAM STRUCTURE (1h, 60 marks — VET):
- Section I — Multiple Choice: 15 questions × 1 mark = 15 marks
- Section II — Short Answer: 6-8 questions totalling ~35 marks (workplace scenarios, WHS, industry knowledge)
- Section III — Extended Response: 1 question of ~10 marks
TOTAL: ~60 marks. You MUST include ALL three sections.`;
        } else if (durationHours === 2) {
            structureGuide = `EXAM STRUCTURE (2h, 80 marks — VET — REAL HSC FORMAT):
- Section I — Multiple Choice: 15 questions × 1 mark = 15 marks
- Section II — Short Answer: 8-10 questions totalling ~50 marks (workplace scenarios, case studies)
- Section III — Extended Response: 1-2 questions totalling ~15 marks
TOTAL: ~80 marks. You MUST include ALL three sections.`;
        } else {
            structureGuide = `EXAM STRUCTURE (3h, 100 marks — VET):
- Section I — Multiple Choice: 15 questions × 1 mark = 15 marks
- Section II — Short Answer: 10-14 questions totalling ~65 marks
- Section III — Extended Response: 1-2 questions totalling ~20 marks
TOTAL: ~100 marks. You MUST include ALL three sections.`;
        }
        categoryRules = `VET-SPECIFIC RULES:
- Construction: include WHS legislation, building codes, construction methods, materials, tools, site management. Reference Australian Standards.
- Hospitality: include food safety (FSANZ), customer service, menu planning, workplace hygiene, kitchen operations.
- Use industry-standard terminology and reference relevant Australian regulations/standards.
- Include workplace scenarios and practical problem-solving contexts.
- IMPORTANT: Only generate questions from the student's selected module/topic.`;

    // ===== FALLBACK for any uncategorised subject =====
    } else {
        if (durationHours === 1) {
            structureGuide = `EXAM STRUCTURE (1h, 60 marks):
- Section I — Multiple Choice: 10 questions × 1 mark = 10 marks
- Section II — Short Answer: 5-7 questions totalling ~35 marks
- Section III — Extended Response: 1-2 questions totalling ~15 marks
TOTAL: ~60 marks. You MUST include ALL three sections.`;
        } else if (durationHours === 2) {
            structureGuide = `EXAM STRUCTURE (2h, 80 marks):
- Section I — Multiple Choice: 15 questions × 1 mark = 15 marks
- Section II — Short Answer: 6-8 questions totalling ~40 marks
- Section III — Extended Response: 2-3 questions totalling ~25 marks
TOTAL: ~80 marks. You MUST include ALL three sections.`;
        } else {
            structureGuide = `EXAM STRUCTURE (3h, 100 marks):
- Section I — Multiple Choice: 20 questions × 1 mark = 20 marks
- Section II — Short Answer: 8-10 questions totalling ~50 marks
- Section III — Extended Response: 2-3 questions totalling ~30 marks
TOTAL: ~100 marks. You MUST include ALL three sections.`;
        }
        categoryRules = `Follow standard HSC exam conventions for this subject. Use precise academic terminology. Include stimulus material where appropriate.\n- IMPORTANT: Only generate questions from the student's selected module/topic.`;
    }

    const systemPrompt = `You are an EXPERT HSC exam paper writer who has written real NESA exam papers. Generate a COMPLETE exam paper as structured JSON.

UNIQUENESS SEED: ${examSeed}
Use this seed to ensure completely unique questions every time.

MODULE/TOPIC CONSTRAINT — THIS IS ABSOLUTE:
- The student selected: "${topics || 'All Year 12 content'}"
- If a specific module was selected (e.g. "Module 6: Genetic Change"), then EVERY SINGLE QUESTION must come EXCLUSIVELY from that module's syllabus dot points. Do NOT include ANY content from other modules. Zero exceptions.
- If "All Year 12 content" is selected, spread questions evenly across all modules.
- Before writing each question, verify it belongs to the selected module. If it doesn't, discard it.

${structureGuide}

HSC LANGUAGE & AUTHENTICITY — CRITICAL:
- Write EXACTLY like a NESA exam writer. Study the phrasing in the past papers provided.
- Use precise academic/technical terminology appropriate to the subject. NEVER use casual or simplified language.
- Short answer questions must use NESA directive verbs PRECISELY:
  * 1-2 marks: Identify, State, Define, Outline
  * 3-4 marks: Describe, Explain, Compare
  * 5-6 marks: Analyse, Assess, Explain in detail
  * 7-9 marks: Evaluate, Discuss, Assess with reference to
- Every question must test UNDERSTANDING, not just recall. Include application, analysis, or evaluation.
- Include stimulus material (data tables, experimental results, graphs described in text, source extracts, diagrams) for AT LEAST 40% of non-MC questions.
- MC distractors (where MC applies) must be PLAUSIBLE — all four options should sound reasonable.

QUESTION FORMAT RULES:
- MC options must be full sentences or precise terms. Exactly 4 options (A, B, C, D).
- Short answer: include context/scenario/data. Bare "Describe X" without context is NOT HSC-standard.
- Extended response: must include a clear directive, context, and scope.

${categoryRules}

UNICODE MATH FORMATTING (for all subjects): Use x², √, π, θ, ∫, Σ, ≤, ≥, ±, ×, ÷, ∞, ° — NEVER LaTeX.

DIFFICULTY LEVEL: ${difficulty === 'easy' ? 'EASY — Foundation/Revision level. Use simpler language, more scaffolded questions, fewer multi-step problems. Short answer questions should have clear single-concept focus. Extended responses should be more guided with specific prompts. MC distractors should be more obviously wrong. Keep questions at the lower end of Bloom\'s taxonomy (recall, understand, apply).' : difficulty === 'hard' ? 'HARD — Trial-level / Extension difficulty. Use complex multi-step problems, nuanced stimulus material, higher-order thinking throughout. Short answers should require synthesis of multiple concepts. Extended responses should demand sophisticated analysis with ambiguous/debatable propositions. MC distractors should be very close to the correct answer. Target the upper end of Bloom\'s taxonomy (analyse, evaluate, create). Include questions that would challenge Band 6 students.' : 'STANDARD — HSC exam difficulty. Follow the typical difficulty distribution of a real NESA exam: start easier and build to harder questions within each section. Match the rigour and complexity of actual past HSC papers.'}

Subject: ${subjectName}
Topics: ${topics || 'All Year 12 content'}
Duration: ${durationHours} hour(s)
Total marks: ~${totalMarks}

Return ONLY valid JSON (no markdown, no code fences) in this exact structure:
{
  "title": "2025 HSC ${subjectName} Trial Examination",
  "duration": "${durationHours} hour(s)",
  "totalMarks": ${totalMarks},
  "instructions": "Brief exam instructions string",
  "sections": [
    {
      "name": "Section name matching the structure above",
      "instructions": "Section-specific instructions",
      "questions": [
        {
          "number": 1,
          "type": "mc OR short OR extended",
          "marks": 1,
          "text": "Main question text (for multi-part questions, this is the stem/context)",
          "parts": [
            { "label": "(a)", "text": "Sub-question text", "marks": 2 },
            { "label": "(b)", "text": "Sub-question text", "marks": 3 }
          ],
          "options": ["A. option", "B. option", "C. option", "D. option"],
          "correctAnswer": "B",
          "stimulus": "Optional stimulus material or null",
          "markingCriteria": "Brief marking criteria (for non-MC)"
        }
      ]
    }
  ]
}

CRITICAL JSON RULES:
- "type": Use "mc" for multiple choice, "short" for short answer (2-6 marks), "extended" for extended response (7+ marks).
- MC questions: include "options" (array of 4 strings starting with A. B. C. D.) and "correctAnswer" (letter). No "parts" for MC.
- Short/Extended questions with 4+ marks SHOULD have "parts" — an array of sub-questions with labels like "(a)", "(b)", "(c)". Each part has its own "text" and "marks". The question's total "marks" must equal the sum of all part marks.
- Short/Extended questions with 2-3 marks can omit "parts" (single question is fine).
- For non-MC: include "markingCriteria" and optionally "stimulus".
- DATA TABLES in stimulus: Format tables as markdown tables with | separators and header row: "| Column 1 | Column 2 |\\n|---|---|\\n| data | data |"
- Match section names and structure to the EXAM STRUCTURE specified above.
- If the structure says NO multiple choice, do NOT include an MC section.
- Generate the COMPLETE exam — all questions, all sections. Do not truncate.${contextPrompt}`;

    try {
        const isGpt5 = aiSettings.model.startsWith('gpt-5');
        const tokenParam = isGpt5 ? 'max_completion_tokens' : 'max_tokens';
        const requestBody = {
            model: aiSettings.model,
            messages: [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: `Generate a complete ${durationHours}-hour HSC exam paper for ${subjectName}. Topics: ${topics || 'All Year 12 content'}. REMINDER: ${topics && topics !== 'All Year 12 content' ? `ONLY include questions from "${topics}". Do NOT include content from any other module or topic area.` : 'Spread questions EVENLY across ALL Year 12 modules for this subject. Each module must have at least one question. Do NOT focus on only one or two modules — cover the full breadth of the course.'} Use sub-parts (a)(b)(c) for questions worth 4+ marks. Return ONLY valid JSON.` }
            ],
            [tokenParam]: Math.min(aiSettings.maxTokens, 16000)
        };
        if (!isGpt5) requestBody.temperature = Math.min(aiSettings.temperature, 0.7);

        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${OPENAI_API_KEY}` },
            body: JSON.stringify(requestBody)
        });

        if (!response.ok) {
            const error = await response.json();
            console.error('OpenAI exam generate error:', error);
            return res.status(500).json({ error: 'AI service unavailable' });
        }

        const data = await response.json();
        let reply = data.choices?.[0]?.message?.content || '';

        // Robust JSON extraction — strip fences, find JSON object
        reply = reply.replace(/```(?:json)?\s*/gi, '').replace(/```/g, '').trim();
        const jsonStart = reply.indexOf('{');
        const jsonEnd = reply.lastIndexOf('}');
        if (jsonStart !== -1 && jsonEnd > jsonStart) {
            reply = reply.substring(jsonStart, jsonEnd + 1);
        }

        let exam;
        try {
            exam = JSON.parse(reply);
        } catch (parseErr) {
            console.error('Failed to parse exam JSON:', parseErr.message, 'Raw:', reply.substring(0, 500));
            return res.status(500).json({ error: 'Failed to generate valid exam structure. Please try again.' });
        }

        // Increment free tier usage
        if (!hasFull) {
            incrementExamWeeklyCount(req.session.userId);
            incrementFreeTierUsage(req.session.userId, 'practice');
        }

        res.json({ exam, isPremium: hasFull });
    } catch (error) {
        console.error('Exam generate error:', error);
        res.status(500).json({ error: 'Failed to generate exam' });
    }
});

// Mark exam — takes questions + student answers, returns scores + feedback
app.post('/api/exam/mark', express.json(), async (req, res) => {
    if (!req.session?.userId) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    const user = getUser(req.session.userId);
    if (!user) return res.status(401).json({ error: 'User not found' });

    const hasFull = hasFullAccess(user);
    const { exam, answers, subject } = req.body;

    if (!exam || !answers) return res.status(400).json({ error: 'Exam and answers are required' });

    const OPENAI_API_KEY = config.openaiApiKey;
    const aiSettings = getAISettings(user);
    const subjectName = subjectsConfig.subjects.find(s => s.id === subject)?.name || subject;

    // Build the marking request with all questions and answers
    let questionsText = '';
    let totalPossible = 0;
    const allQuestions = [];
    const unansweredQuestions = []; // Track unanswered for instant 0-mark

    for (const section of exam.sections) {
        questionsText += `\n\n--- ${section.name} ---\n`;
        for (const q of section.questions) {
            totalPossible += q.marks;
            allQuestions.push(q);

            // Check if this question has sub-parts
            if (q.parts && q.parts.length > 0) {
                // Collect answers for each sub-part
                let hasAnyPartAnswer = false;
                let partAnswersText = '';
                q.parts.forEach((part, pi) => {
                    const partKey = q.number + '_' + (pi + 1);
                    const partAnswer = answers[partKey];
                    const partLabel = part.label || '(' + String.fromCharCode(97 + pi) + ')';
                    if (partAnswer && partAnswer.toString().trim().length > 0) {
                        hasAnyPartAnswer = true;
                        partAnswersText += `  ${partLabel} [${part.marks} marks]: ${partAnswer}\n`;
                    } else {
                        partAnswersText += `  ${partLabel} [${part.marks} marks]: [No answer]\n`;
                    }
                });

                if (!hasAnyPartAnswer) {
                    unansweredQuestions.push({ number: q.number, marks: q.marks, type: q.type });
                    continue;
                }

                questionsText += `\nQ${q.number} [${q.marks} mark${q.marks > 1 ? 's' : ''}] (${q.type}, multi-part):\n${q.text}\n`;
                if (q.stimulus) questionsText += `Stimulus: ${q.stimulus}\n`;
                if (q.markingCriteria) questionsText += `Marking criteria: ${q.markingCriteria}\n`;
                questionsText += `Parts and student answers:\n${partAnswersText}`;
            } else {
                const studentAnswer = answers[q.number];
                const hasAnswer = studentAnswer && studentAnswer.toString().trim().length > 0;

                if (!hasAnswer) {
                    unansweredQuestions.push({ number: q.number, marks: q.marks, type: q.type });
                    continue;
                }

                questionsText += `\nQ${q.number} [${q.marks} mark${q.marks > 1 ? 's' : ''}] (${q.type}):\n${q.text}\n`;
                if (q.stimulus) questionsText += `Stimulus: ${q.stimulus}\n`;
                if (q.markingCriteria) questionsText += `Marking criteria: ${q.markingCriteria}\n`;
                if (q.correctAnswer) questionsText += `Correct answer: ${q.correctAnswer}\n`;
                questionsText += `Student's answer: ${studentAnswer}\n`;
            }
        }
    }

    const includeSampleAnswers = hasFull;
    const answeredCount = allQuestions.length - unansweredQuestions.length;

    // Load official marking guidelines for accurate marking
    let mgContext = '';
    const mgContent = getMarkingGuidelineContent(subject);
    if (mgContent) {
        // Use less MG context for faster marking — 20K is plenty for marking accuracy
        const truncatedMG = mgContent.substring(0, 20000);
        mgContext = `\n\n=== OFFICIAL NESA MARKING GUIDELINES FOR ${subjectName.toUpperCase()} ===\nUse these REAL marking guidelines to inform your marking. Reference the specific band descriptors, criteria, and mark allocations from these guidelines when assessing each answer.\n\n${truncatedMG}\n\n=== END OF MARKING GUIDELINES ===`;
    }

    const systemPrompt = `You are a SENIOR HSC examiner for ${subjectName} with 20 years of NESA marking experience. Mark each answer with the rigour and standards of the real HSC.${mgContext}

MARKING RULES — STRICT HSC STANDARD:
- Multiple choice: 1 mark if correct, 0 if wrong. No partial marks. No leniency.
- Short answer (2-4 marks): Award marks ONLY for demonstrated understanding. Vague or incomplete answers lose marks. Each mark requires a distinct, correct point.
  * 1 mark = one correct, specific point
  * 2 marks = two distinct points OR one well-explained point
  * 3 marks = clear explanation with depth and specificity
  * 4 marks = thorough explanation with examples, causes, effects, or links to syllabus concepts
- Extended response (5+ marks): Use HOLISTIC marking. Assess depth of understanding, use of evidence/examples, logical structure, and quality of analysis. A superficial answer should NEVER score above 50% of available marks.
- NEVER give full marks for a vague or generic answer. Real HSC markers don't.
- Deduct marks for: factual errors, irrelevant content, missing key concepts, poor structure (in extended responses).
- Be especially strict on: scientific accuracy, correct use of terminology, addressing ALL parts of the question.
- If the student restates the question without adding substance, award 0.
- Keep feedback CONCISE — 1-2 sentences per question maximum. Be direct and specific about what was missing.
- ONLY mark the ${answeredCount} questions given below. Unanswered questions are handled separately.

Return ONLY valid JSON (no markdown, no code fences):
{
  "results": [
    {
      "questionNumber": 1,
      "marksAwarded": 1,
      "marksTotal": 1,
      "feedback": "Brief feedback on the student's answer"${includeSampleAnswers ? ',\n      "sampleAnswer": "A concise model answer"' : ''}
    }
  ],
  "totalMarksAwarded": 65,
  "totalMarksPossible": ${totalPossible},
  "percentage": 81.25,
  "expectedBand": "Band 5",
  "overallFeedback": "2-3 sentences summarising overall performance, strengths, and areas to improve."
}

Band scale (percentage-based):
- Band 6: 90-100%
- Band 5: 80-89%
- Band 4: 70-79%
- Band 3: 60-69%
- Band 2: 50-59%
- Band 1: 0-49%

${includeSampleAnswers ? 'Include a concise "sampleAnswer" for EVERY question showing what a full-marks response looks like.' : 'Do NOT include sample answers — only provide feedback.'}`;

    try {
        let markingResult;

        // If ALL questions are unanswered, skip AI entirely — instant 0
        if (answeredCount === 0) {
            markingResult = {
                results: unansweredQuestions.map(uq => ({
                    questionNumber: uq.number,
                    marksAwarded: 0,
                    marksTotal: uq.marks,
                    feedback: 'No answer provided — 0 marks awarded.'
                })),
                totalMarksAwarded: 0,
                totalMarksPossible: totalPossible,
                percentage: 0,
                expectedBand: 'Band 1',
                overallFeedback: 'No answers were provided for any question. All questions received 0 marks.'
            };
        } else {
            // Call AI to mark only the answered questions
            const isGpt5 = aiSettings.model.startsWith('gpt-5');
            const tokenParam = isGpt5 ? 'max_completion_tokens' : 'max_tokens';
            const requestBody = {
                model: aiSettings.model,
                messages: [
                    { role: 'system', content: systemPrompt },
                    { role: 'user', content: `Mark the following ${subjectName} exam:\n${questionsText}\n\nReturn ONLY valid JSON.` }
                ],
                [tokenParam]: Math.min(aiSettings.maxTokens, 16000)
            };
            if (!isGpt5) requestBody.temperature = 0.3; // Low temp for consistent marking

            const response = await fetch('https://api.openai.com/v1/chat/completions', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${OPENAI_API_KEY}` },
                body: JSON.stringify(requestBody)
            });

            if (!response.ok) {
                const error = await response.json();
                console.error('OpenAI exam mark error:', error);
                return res.status(500).json({ error: 'AI service unavailable' });
            }

            const data = await response.json();
            let reply = data.choices?.[0]?.message?.content || '';

            // Robust JSON extraction — strip fences, find JSON object
            reply = reply.replace(/```(?:json)?\s*/gi, '').replace(/```/g, '').trim();
            const jsonStart = reply.indexOf('{');
            const jsonEnd = reply.lastIndexOf('}');
            if (jsonStart !== -1 && jsonEnd > jsonStart) {
                reply = reply.substring(jsonStart, jsonEnd + 1);
            }

            try {
                markingResult = JSON.parse(reply);
            } catch (parseErr) {
                console.error('Failed to parse marking JSON:', parseErr.message, 'Raw:', reply.substring(0, 500));
                return res.status(500).json({ error: 'Failed to parse marking results. Please try again.' });
            }

            // Merge unanswered question results (0 marks each)
            if (unansweredQuestions.length > 0) {
                const unansweredResults = unansweredQuestions.map(uq => ({
                    questionNumber: uq.number,
                    marksAwarded: 0,
                    marksTotal: uq.marks,
                    feedback: 'No answer provided — 0 marks awarded.'
                }));
                markingResult.results = [...(markingResult.results || []), ...unansweredResults];
                // Sort by question number for clean display
                markingResult.results.sort((a, b) => a.questionNumber - b.questionNumber);
                // Recalculate totals to include unanswered
                const aiMarks = (markingResult.results || []).reduce((sum, r) => sum + (r.marksAwarded || 0), 0);
                markingResult.totalMarksAwarded = aiMarks;
                markingResult.totalMarksPossible = totalPossible;
                markingResult.percentage = totalPossible > 0 ? Math.round((aiMarks / totalPossible) * 10000) / 100 : 0;
                // Recalculate band
                const pct = markingResult.percentage;
                markingResult.expectedBand = pct >= 90 ? 'Band 6' : pct >= 80 ? 'Band 5' : pct >= 70 ? 'Band 4' : pct >= 60 ? 'Band 3' : pct >= 50 ? 'Band 2' : 'Band 1';
            }
        }

        // Save progress
        const progress = getExamProgress(req.session.userId);
        if (!progress[subject]) {
            progress[subject] = { attempts: [], bestScore: 0 };
        }
        const attempt = {
            date: new Date().toISOString(),
            percentage: markingResult.percentage,
            band: markingResult.expectedBand,
            totalMarks: markingResult.totalMarksAwarded,
            possibleMarks: markingResult.totalMarksPossible,
            subjectName,
            duration: exam.duration || '',
            title: exam.title || ''
        };
        progress[subject].attempts.push(attempt);
        if (progress[subject].attempts.length > 20) {
            progress[subject].attempts = progress[subject].attempts.slice(-20);
        }
        progress[subject].lastScore = markingResult.percentage;
        if (markingResult.percentage > progress[subject].bestScore) {
            progress[subject].bestScore = markingResult.percentage;
        }
        saveExamProgress(req.session.userId, progress);

        // Include progress comparison
        const previousAttempts = progress[subject].attempts;
        let comparison = null;
        if (previousAttempts.length >= 2) {
            const prev = previousAttempts[previousAttempts.length - 2];
            comparison = {
                previousPercentage: prev.percentage,
                previousBand: prev.band,
                change: markingResult.percentage - prev.percentage
            };
        }

        res.json({
            marking: markingResult,
            progress: {
                subject: subjectName,
                totalAttempts: previousAttempts.length,
                bestScore: progress[subject].bestScore,
                comparison,
                canGenerateNew: hasFull || markingResult.percentage >= 80
            },
            isPremium: hasFull
        });
    } catch (error) {
        console.error('Exam mark error:', error);
        res.status(500).json({ error: 'Failed to mark exam' });
    }
});

// Get exam progress
app.get('/api/exam/progress', async (req, res) => {
    if (!req.session?.userId) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    const progress = getExamProgress(req.session.userId);
    const hasFull = hasFullAccess(getUser(req.session.userId));
    const weeklyCount = hasFull ? null : getExamWeeklyCount(req.session.userId);
    res.json({ progress, weeklyCount, maxPerWeek: hasFull ? null : 3, isPremium: hasFull });
});

// Get exam limits status for free users
app.get('/api/exam/limits', async (req, res) => {
    if (!req.session?.userId) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    const user = getUser(req.session.userId);
    const hasFull = hasFullAccess(user);
    const isOwner = user?.role === 'owner';
    if (hasFull) {
        return res.json({ isPremium: true, unlimited: true, isOwner });
    }
    const weeklyCount = getExamWeeklyCount(req.session.userId);
    const progress = getExamProgress(req.session.userId);
    res.json({
        isPremium: false,
        weeklyCount,
        maxPerWeek: 3,
        remaining: Math.max(0, 3 - weeklyCount),
        progress
    });
});

// OpenAI Chat endpoint (secured - requires authentication, allows free tier with limits)
app.post('/api/chat/:botType', express.json(), async (req, res) => {
    // Require authentication
    if (!req.session?.userId) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    const user = getUser(req.session.userId);
    if (!user) {
        return res.status(401).json({ error: 'User not found' });
    }
    
    const { botType } = req.params;
    
    // Validate bot type first (need it for per-bot limit check)
    if (!BOT_PROMPTS[botType]) {
        return res.status(400).json({ error: 'Invalid bot type' });
    }
    
    // Check access: full subscribers OR free tier with per-bot daily limit
    const hasFull = hasFullAccess(user);
    const canUseFree = canUseFreeTier(req.session.userId, botType);
    
    if (!hasFull && !canUseFree) {
        return res.status(403).json({ 
            error: 'Daily limit reached',
            freeTierExhausted: true,
            remaining: 0,
            botType: botType,
            limitType: 'global'
        });
    }
    const { messages, subject, detailLevel } = req.body;
    
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
            
            // Smart syllabus extraction: prioritize the requested topic section
            // All models (GPT-5-mini, GPT-4o, GPT-4o-mini) support 128k context
            const SYLLABUS_CHAR_LIMIT = 100000;
            let truncatedSyllabus;
            
            // Try to extract the requested topic from the user message
            const lastUserMsg = messages.length > 0 ? messages[messages.length - 1].content : '';
            const topicMatch = lastUserMsg.match(/Topic:\s*(.+?)(?:\n|$)/i);
            const requestedTopic = topicMatch ? topicMatch[1].trim() : null;
            
            if (requestedTopic && syllabusContent.length > SYLLABUS_CHAR_LIMIT) {
                // Find the topic section in the syllabus and prioritize it
                const topicLower = requestedTopic.toLowerCase();
                const contentLower = syllabusContent.toLowerCase();
                const topicIdx = contentLower.indexOf(topicLower);
                
                if (topicIdx > -1) {
                    // Find the start of the topic section (go back to find a heading)
                    const sectionStart = Math.max(0, topicIdx - 500);
                    // Take a generous chunk after the topic heading (15k chars should cover any topic)
                    const sectionEnd = Math.min(syllabusContent.length, topicIdx + 15000);
                    const topicSection = syllabusContent.substring(sectionStart, sectionEnd);
                    
                    // Combine: general syllabus context + focused topic section
                    const generalContext = syllabusContent.substring(0, Math.min(syllabusContent.length, SYLLABUS_CHAR_LIMIT - topicSection.length));
                    
                    // If topic section is already within the general context, just use the full content
                    if (topicIdx < SYLLABUS_CHAR_LIMIT) {
                        truncatedSyllabus = syllabusContent.substring(0, SYLLABUS_CHAR_LIMIT);
                    } else {
                        truncatedSyllabus = generalContext + '\n\n========== TOPIC SECTION: ' + requestedTopic.toUpperCase() + ' ==========\n\n' + topicSection;
                    }
                    console.log(`[Syllabus] Smart extraction: found "${requestedTopic}" at char ${topicIdx}, total ${truncatedSyllabus.length} chars`);
                } else {
                    truncatedSyllabus = syllabusContent.substring(0, SYLLABUS_CHAR_LIMIT);
                    console.log(`[Syllabus] Topic "${requestedTopic}" not found by index, using first ${SYLLABUS_CHAR_LIMIT} chars`);
                }
            } else {
                truncatedSyllabus = syllabusContent.substring(0, SYLLABUS_CHAR_LIMIT);
            }
            console.log(`[Syllabus] Loaded ${truncatedSyllabus.length} chars for ${subjectName}`);
            
            // For syllabus bot, add strong instruction with the content
            if (botType === 'syllabus') {
                systemPrompt += `\n\n========== SYLLABUS CONTENT FOR ${subjectName.toUpperCase()} ==========\nThis is the COMPLETE official syllabus. Search this content for the requested topic and decode it.\n\n${truncatedSyllabus}\n\n========== END SYLLABUS ==========\n\nNow decode the requested topic using the syllabus above. OUTPUT ONLY - no questions.`;
                
                // Inject detail level preference
                const level = parseInt(detailLevel) || 2;
                if (level === 1) {
                    systemPrompt += `\n\nDETAIL LEVEL: BRIEF - Keep your response concise. Provide a short overview, list the key dot points, and give only the most important exam tips. Aim for a quick summary the student can scan in under 2 minutes.`;
                } else if (level === 3) {
                    systemPrompt += `\n\nDETAIL LEVEL: DETAILED - Provide an extremely thorough breakdown. Explain every dot point in depth with examples, include detailed HSC exam analysis with past question references, provide extended study notes, and cover edge cases and common misunderstandings. Be as comprehensive as possible.`;
                }
            } else {
                systemPrompt += `\n\n=== OFFICIAL ${subjectName.toUpperCase()} SYLLABUS (NSW NESA) ===\nThe following is the official syllabus content. Use this as your ONLY source of truth for content. All questions MUST be based on this syllabus.\n\n${truncatedSyllabus}\n\n=== END OF SYLLABUS ===`;
            }
        } else {
            console.log(`[Syllabus] WARNING: No syllabus content found for ${subjectId}`);
        }
    }
    
    // Inject past paper content for practice bot (both question generation AND feedback)
    if (botType === 'practice' && subjectId) {
        const subjectName = subjectsConfig.subjects.find(s => s.id === subjectId)?.name || subjectId;
        const lastUserMessage = messages[messages.length - 1]?.content || '';
        const isFeedbackMode = lastUserMessage.includes('[FEEDBACK MODE]');
        
        if (isFeedbackMode) {
            // FEEDBACK MODE: Prioritise marking guidelines (MG files)
            const mgContent = getMarkingGuidelineContent(subjectId);
            if (mgContent) {
                const truncatedMG = mgContent.substring(0, 40000);
                systemPrompt += `\n\n=== OFFICIAL NESA MARKING GUIDELINES FOR ${subjectName.toUpperCase()} ===\nThese are the REAL marking guidelines used by HSC markers. You MUST reference these specific criteria, band descriptors, and mark allocations when assessing the student's response.\n\n⚠️ CRITICAL: You are ONLY providing feedback — NEVER reveal the correct answer or write a model response.\n\n${truncatedMG}\n\n=== END OF MARKING GUIDELINES ===`;
            }
            // Also include exam papers for context on question expectations
            const examPapers = getExamPaperContent(subjectId);
            if (examPapers) {
                const truncatedPapers = examPapers.substring(0, 15000);
                systemPrompt += `\n\n=== HSC PAST EXAM PAPERS (for question context) ===\n${truncatedPapers}\n=== END ===`;
            }
        } else {
            // STANDARD / question generation mode: past papers as the gold standard for format
            const examPapers = getExamPaperContent(subjectId);
            if (examPapers) {
                const truncated = examPapers.substring(0, 25000);
                systemPrompt += `\n\n=== REAL HSC PAST EXAM PAPERS FOR ${subjectName.toUpperCase()} ===\n⚠️ STUDY THESE CAREFULLY. Your generated questions MUST match the style, phrasing, structure, mark allocation, and command verbs used in these REAL papers. Do NOT copy questions — but your questions must be indistinguishable in format and quality from these. Pay attention to: how stimulus material is presented, how marks are allocated to sub-parts, which directive verbs appear at which mark levels, and how questions reference syllabus content.\n\n${truncated}\n\n=== END OF PAST PAPERS ===`;
            }
            // Include marking guidelines for mark allocation accuracy
            const mgContent = getMarkingGuidelineContent(subjectId);
            if (mgContent) {
                const truncatedMG = mgContent.substring(0, 15000);
                systemPrompt += `\n\n=== OFFICIAL MARKING GUIDELINES ===\nUse these to ensure your generated questions have accurate mark allocations that match real NESA standards. Reference the band descriptors to calibrate difficulty.\n${truncatedMG}\n=== END ===`;
            }
        }
    }
    
    // Get AI settings based on user tier
    const aiSettings = getAISettings(user);
    
    try {
        // GPT-5 models use max_completion_tokens instead of max_tokens
        const isGpt5 = aiSettings.model.startsWith('gpt-5');
        const tokenParam = isGpt5 ? 'max_completion_tokens' : 'max_tokens';
        const requestBody = {
            model: aiSettings.model,
            messages: [
                { role: 'system', content: systemPrompt },
                ...messages.map(m => {
                    // Support multimodal content (arrays with text + image_url for worksheet decoder)
                    if (Array.isArray(m.content)) {
                        return { role: m.role, content: m.content };
                    }
                    return { role: m.role, content: m.content };
                })
            ],
            [tokenParam]: aiSettings.maxTokens
        };
        if (!isGpt5) requestBody.temperature = aiSettings.temperature;
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${OPENAI_API_KEY}`
            },
            body: JSON.stringify(requestBody)
        });
        
        if (!response.ok) {
            const error = await response.json();
            console.error('OpenAI API error:', error);
            return res.status(500).json({ error: 'AI service unavailable' });
        }
        
        const data = await response.json();
        const reply = data.choices?.[0]?.message?.content || 'No response generated';
        
        // Increment free tier usage ONLY for free users (not paid, lifetime, or owner)
        if (!hasFull) {
            incrementFreeTierUsage(req.session.userId, botType);
        }
        
        // Include remaining questions in response for free users only
        const remaining = hasFull ? null : getFreeTierRemaining(req.session.userId, botType);
        
        res.json({ reply, freeTierRemaining: remaining });
    } catch (error) {
        console.error('Chat API error:', error);
        res.status(500).json({ error: 'Failed to process request' });
    }
});

// Junior Bot Chat endpoint (Years 7-10)
app.post('/api/junior-chat/:botType', express.json(), async (req, res) => {
    // Require authentication
    if (!req.session?.userId) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    const user = getUser(req.session.userId);
    if (!user) {
        return res.status(401).json({ error: 'User not found' });
    }
    
    const { botType } = req.params;
    const { messages, subject } = req.body;
    
    if (!JUNIOR_BOT_PROMPTS[botType]) {
        return res.status(400).json({ error: 'Invalid bot type' });
    }
    
    // Check access: full subscribers OR free tier
    const hasFull = hasFullAccess(user);
    const canUseFree = canUseFreeTier(req.session.userId, 'jr_' + botType);
    
    if (!hasFull && !canUseFree) {
        return res.status(403).json({ 
            error: 'Daily limit reached',
            freeTierExhausted: true,
            remaining: 0,
            botType: 'jr_' + botType,
            limitType: 'global'
        });
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
    
    // Get AI settings based on user tier
    const aiSettings = getAISettings(user);
    
    try {
        const isGpt5 = aiSettings.model.startsWith('gpt-5');
        const tokenParam = isGpt5 ? 'max_completion_tokens' : 'max_tokens';
        const requestBody = {
            model: aiSettings.model,
            messages: [
                { role: 'system', content: systemPrompt },
                ...messages.map(m => ({
                    role: m.role,
                    content: m.content
                }))
            ],
            [tokenParam]: aiSettings.maxTokens
        };
        if (!isGpt5) requestBody.temperature = aiSettings.temperature;
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${OPENAI_API_KEY}`
            },
            body: JSON.stringify(requestBody)
        });
        
        if (!response.ok) {
            const error = await response.json();
            console.error('OpenAI API error:', error);
            return res.status(500).json({ error: 'AI service unavailable' });
        }
        
        const data = await response.json();
        const reply = data.choices?.[0]?.message?.content || 'No response generated';
        
        // Increment free tier usage ONLY for free users
        if (!hasFull) {
            incrementFreeTierUsage(req.session.userId, 'jr_' + botType);
        }
        
        const remaining = hasFull ? null : getFreeTierRemaining(req.session.userId, 'jr_' + botType);
        
        res.json({ reply, freeTierRemaining: remaining });
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

// ==================== ERROR HANDLING ==

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
