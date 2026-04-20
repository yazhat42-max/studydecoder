/**
 * Study Decoder - Enterprise Auth Client
 * ======================================
 * Shared authentication utilities for all protected pages.
 * Include this script in any page that requires authentication.
 */

const StudyDecoderAuth = {
    // ===== LocalStorage caching for surviving server restarts =====
    _CACHE_KEY: 'sd_user_cache',

    cacheUserData(user) {
        try {
            const cached = {
                email: user.email,
                name: user.name,
                preferences: user.preferences || {},
                freeAcknowledged: user.freeAcknowledged || false,
                cachedAt: Date.now()
            };
            localStorage.setItem(this._CACHE_KEY, JSON.stringify(cached));
        } catch (e) { /* localStorage full or disabled */ }
    },

    getCachedUserData() {
        try {
            const raw = localStorage.getItem(this._CACHE_KEY);
            if (!raw) return null;
            const cached = JSON.parse(raw);
            // Expire cache after 90 days
            if (Date.now() - cached.cachedAt > 90 * 24 * 60 * 60 * 1000) {
                localStorage.removeItem(this._CACHE_KEY);
                return null;
            }
            return cached;
        } catch (e) { return null; }
    },

    // Restore cached preferences to server after re-login (server data was wiped)
    async restoreCachedData() {
        const cached = this.getCachedUserData();
        if (!cached) return;
        const prefs = cached.preferences;
        const hasPrefs = prefs && (prefs.level || (prefs.subjects && prefs.subjects.length > 0) || prefs.onboarded);
        if (hasPrefs) {
            try {
                await fetch('/api/user/preferences', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify(prefs)
                });
            } catch (e) { /* silent */ }
        }
        if (cached.freeAcknowledged) {
            try {
                await fetch('/api/acknowledge-free', { method: 'POST', credentials: 'include' });
            } catch (e) { /* silent */ }
        }
    },

    // Check if user is authenticated and has access
    async checkAuth(options = {}) {
        const { 
            requireSubscription = true, 
            redirectToLogin = true,
            onSuccess = null,
            onNoAccess = null 
        } = options;
        
        try {
            const res = await fetch('/api/subscription', {
                credentials: 'include'
            });
            
            if (!res.ok) {
                if (redirectToLogin) {
                    this.redirectToLogin();
                }
                return null;
            }
            
            const user = await res.json();

            // Cache user data to localStorage for surviving server restarts
            this.cacheUserData(user);
            
            // Check subscription if required
            // Allow through if subscribed OR if free tier acknowledged OR if onboarded
            if (requireSubscription && !user.subscribed && !user.freeAcknowledged && !user.preferences?.onboarded) {
                if (onNoAccess) {
                    onNoAccess(user);
                }
                return null;
            }
            
            if (onSuccess) {
                onSuccess(user);
            }
            
            return user;
            
        } catch (e) {
            console.error('Auth check failed:', e);
            if (redirectToLogin) {
                this.redirectToLogin();
            }
            return null;
        }
    },
    
    // Redirect to login with return URL
    redirectToLogin() {
        const returnUrl = encodeURIComponent(window.location.pathname + window.location.search);
        window.location.href = '/login.html?redirect=' + returnUrl;
    },
    
    // Logout user
    async logout() {
        try {
            await fetch('/api/logout', { 
                method: 'POST', 
                credentials: 'include' 
            });
        } catch (e) {
            console.error('Logout error:', e);
        }
        window.location.href = '/login.html';
    },
    
    // Verify payment and activate subscription
    async verifyPayment() {
        try {
            const res = await fetch('/api/verify-payment', { 
                method: 'POST', 
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' }
            });
            
            const data = await res.json();
            
            if (data.success && data.subscribed) {
                this.stopPaymentPolling();
                var statusEl = document.getElementById('sd-payment-polling-status');
                if (statusEl) {
                    statusEl.style.display = 'block';
                    statusEl.innerHTML = '<span style="font-size:0.85rem;color:#16a34a;">✅ Payment confirmed! Activating...</span>';
                }
                setTimeout(() => window.location.reload(), 1000);
            } else {
                alert(data.message || 'No payment found. Please complete payment first.');
            }
        } catch (e) {
            alert('Error verifying payment. Please try again.');
        }
    },
    
    _paymentPollInterval: null,
    
    startPaymentPolling() {
        var statusEl = document.getElementById('sd-payment-polling-status');
        var hintEl = document.getElementById('sd-activate-manual-hint');
        if (statusEl) statusEl.style.display = 'block';
        setTimeout(function() { if (hintEl) hintEl.style.display = 'block'; }, 15000);
        
        if (this._paymentPollInterval) return;
        var self = this;
        var attempts = 0;
        this._paymentPollInterval = setInterval(async function() {
            attempts++;
            if (attempts > 60) {
                self.stopPaymentPolling();
                if (statusEl) statusEl.innerHTML = '<span style="font-size:0.85rem;color:#888;">Auto-detection timed out. <a href="#" onclick="StudyDecoderAuth.verifyPayment(); return false;" style="color:#6C63FF;">Check manually</a></span>';
                return;
            }
            try {
                var res = await fetch('/api/verify-payment', {
                    method: 'POST',
                    credentials: 'include',
                    headers: { 'Content-Type': 'application/json' }
                });
                var data = await res.json();
                if (data.success && data.subscribed) {
                    self.stopPaymentPolling();
                    if (statusEl) statusEl.innerHTML = '<span style="font-size:0.85rem;color:#16a34a;">✅ Payment confirmed! Activating...</span>';
                    setTimeout(function() { window.location.reload(); }, 1200);
                }
            } catch (e) {}
        }, 5000);
    },
    
    stopPaymentPolling() {
        if (this._paymentPollInterval) {
            clearInterval(this._paymentPollInterval);
            this._paymentPollInterval = null;
        }
    },
    
    // Get role badge HTML
    getRoleBadge(role) {
        switch (role) {
            case 'owner':
                return '<span class="sd-role-badge sd-role-owner">👑 Owner</span>';
            case 'lifetime':
                return '<span class="sd-role-badge sd-role-og">⭐ Lifetime</span>';
            case 'og_tester':
                return '<span class="sd-role-badge sd-role-og">🌟 OG Tester</span>';
            default:
                return '';
        }
    },
    
    // Show standard paywall
    showPaywall(user, containerId = null) {
        var isSale = new Date() < new Date('2026-04-25T00:00:00');
        var dealCardHTML = isSale
            ? '<a href="https://buy.stripe.com/fZufZgbx32wMcqSe9R7Vm03" target="_blank" onclick="StudyDecoderAuth.startPaymentPolling()" style="flex:1.3;min-width:220px;max-width:300px;padding:24px 16px;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;text-decoration:none;border-radius:14px;display:flex;flex-direction:column;align-items:center;justify-content:center;position:relative;box-shadow:0 4px 20px rgba(102,126,234,0.35);"><span style="position:absolute;top:-12px;background:#f59e0b;color:#000;font-weight:700;font-size:0.7rem;padding:3px 12px;border-radius:20px;">🔥 LIMITED DEAL</span><span style="font-size:0.8rem;opacity:0.85;margin-top:8px;">One-Time Payment — Lifetime</span><span style="font-size:2rem;font-weight:800;margin:6px 0 2px;">$37.50</span><span style="text-decoration:line-through;opacity:0.6;font-size:0.9rem;">$75/year</span><span style="font-size:0.75rem;opacity:0.8;margin-top:6px;">Ends April 25 — pay once, use forever</span></a>'
            : '<a href="https://buy.stripe.com/fZufZgbx32wMcqSe9R7Vm03" target="_blank" onclick="StudyDecoderAuth.startPaymentPolling()" style="flex:1.3;min-width:220px;max-width:300px;padding:24px 16px;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;text-decoration:none;border-radius:14px;display:flex;flex-direction:column;align-items:center;justify-content:center;box-shadow:0 4px 20px rgba(102,126,234,0.35);"><span style="font-size:0.8rem;opacity:0.85;">Yearly Subscription</span><span style="font-size:2rem;font-weight:800;margin:6px 0 2px;">$75</span><span style="font-size:0.8rem;opacity:0.8;">/year — that\'s $6.25/mo</span></a>';
        const html = `
            <div class="sd-paywall-overlay">
                <div class="sd-paywall-card">
                    <img src="logo.png" alt="Logo" class="sd-paywall-logo">
                    <h2>Welcome to Study Decoder!</h2>
                    <p class="sd-paywall-greeting">Hey <strong>${user?.name || user?.email || 'there'}</strong>! 👋</p>
                    <p class="sd-paywall-desc" style="font-size:0.9rem;color:#aaa;">Premium gets you <strong>unlimited uses</strong>, longer & higher-quality responses.</p>
                    <button onclick="StudyDecoderAuth.closePaywall()" class="sd-paywall-btn sd-btn-success">✓ Continue with Free Plan</button>
                    <p class="sd-paywall-divider">─── or upgrade for unlimited ───</p>
                    <div style="display:flex;gap:12px;align-items:stretch;justify-content:center;flex-wrap:wrap;margin:16px 0;">
                        ${dealCardHTML}
                        <a href="https://buy.stripe.com/eVq14masZ0oEbmO1n57Vm00" target="_blank" onclick="StudyDecoderAuth.startPaymentPolling()" style="flex:0.9;min-width:180px;max-width:240px;padding:20px 14px;background:#1e1e2e;color:#fff;text-decoration:none;border-radius:14px;border:2px solid #333;display:flex;flex-direction:column;align-items:center;justify-content:center;">
                            <span style="font-size:0.8rem;color:#aaa;">Monthly</span>
                            <span style="font-size:1.6rem;font-weight:700;margin:6px 0 2px;color:#6C63FF;">$7.50</span>
                            <span style="font-size:0.8rem;color:#aaa;">/month</span>
                            <span style="font-size:0.7rem;color:#666;margin-top:6px;">Cancel anytime</span>
                        </a>
                    </div>
                    <div id="sd-payment-polling-status" style="display:none;text-align:center;margin:12px 0;padding:10px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;">
                        <span style="font-size:0.85rem;color:#16a34a;">⏳ Waiting for payment... This will activate automatically.</span>
                    </div>
                    <p id="sd-activate-manual-hint" style="color:#999;font-size:0.8rem;margin:8px 0;display:none;">Payment not detected? <a href="#" onclick="StudyDecoderAuth.verifyPayment(); return false;" style="color:#6C63FF;text-decoration:underline;">Check manually</a></p>
                    <button onclick="StudyDecoderAuth.logout()" class="sd-paywall-btn sd-btn-outline">Sign Out</button>
                </div>
            </div>
        `;
        
        if (containerId) {
            document.getElementById(containerId).innerHTML = html;
        } else {
            document.body.insertAdjacentHTML('beforeend', html);
        }
    },
    
    // Close paywall (continue with free) - saves acknowledgment to backend
    async closePaywall() {
        try {
            await fetch('/api/acknowledge-free', {
                method: 'POST',
                credentials: 'include'
            });
            // Update localStorage cache with freeAcknowledged = true
            try {
                const raw = localStorage.getItem(this._CACHE_KEY);
                if (raw) {
                    const cached = JSON.parse(raw);
                    cached.freeAcknowledged = true;
                    localStorage.setItem(this._CACHE_KEY, JSON.stringify(cached));
                }
            } catch (e) { /* silent */ }
            // Reload page so checkAuth runs again with freeAcknowledged = true
            window.location.reload();
        } catch (e) {
            console.error('Failed to save free acknowledgment:', e);
            // Still try to reload
            window.location.reload();
        }
    },
    
    // Inject auth styles
    injectStyles() {
        if (document.getElementById('sd-auth-styles')) return;
        
        const styles = document.createElement('style');
        styles.id = 'sd-auth-styles';
        styles.textContent = `
            .sd-role-badge {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                padding: 6px 14px;
                border-radius: 20px;
                font-size: 0.85rem;
                font-weight: 600;
            }
            .sd-role-owner {
                background: linear-gradient(135deg, #ffd700, #ffb300);
                color: #7c5e00;
            }
            .sd-role-og {
                background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                color: white;
            }
            .sd-paywall-overlay {
                position: fixed;
                top: 0;
                left: 0;
                width: 100vw;
                height: 100vh;
                background: rgba(245,247,255,0.98);
                z-index: 9998;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .sd-paywall-card {
                background: #fff;
                padding: 48px 32px;
                border-radius: 24px;
                box-shadow: 0 8px 40px rgba(108,99,255,0.18);
                max-width: 400px;
                width: 90vw;
                text-align: center;
            }
            .sd-paywall-logo {
                width: 54px;
                height: 54px;
                margin-bottom: 18px;
            }
            .sd-paywall-card h2 {
                font-size: 1.8rem;
                font-weight: 700;
                color: #4f8cff;
                margin-bottom: 10px;
            }
            .sd-paywall-greeting {
                font-size: 1rem;
                color: #444;
                margin-bottom: 8px;
            }
            .sd-paywall-desc {
                font-size: 1rem;
                color: #666;
                margin-bottom: 28px;
            }
            .sd-paywall-note {
                font-size: 0.95rem;
                color: #666;
                margin: 16px 0;
            }
            .sd-paywall-btn {
                display: block;
                width: 100%;
                padding: 14px 0;
                border-radius: 12px;
                font-weight: 600;
                font-size: 1rem;
                text-decoration: none;
                margin-bottom: 12px;
                border: none;
                cursor: pointer;
                transition: all 0.2s;
            }
            .sd-btn-primary {
                background: #6C63FF;
                color: #fff;
            }
            .sd-btn-secondary {
                background: #4f8cff;
                color: #fff;
            }
            .sd-btn-success {
                background: #10b981;
                color: #fff;
            }
            .sd-btn-activate {
                background: #6366f1;
                color: #fff;
            }
            .sd-btn-outline {
                background: #f1f5f9;
                color: #64748b;
            }
            .sd-paywall-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            }
            .sd-paywall-divider {
                color: #94a3b8;
                font-size: 0.85rem;
                margin: 16px 0;
            }
            .sd-save-badge {
                background: rgba(255,255,255,0.2);
                padding: 2px 8px;
                border-radius: 10px;
                font-size: 0.75rem;
                margin-left: 6px;
            }
            .sd-loading-screen {
                position: fixed;
                top: 0;
                left: 0;
                width: 100vw;
                height: 100vh;
                background: linear-gradient(135deg, #667eea 0%, #6C63FF 100%);
                z-index: 9999;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .sd-loading-content {
                text-align: center;
                color: white;
            }
            .sd-loading-content img {
                width: 80px;
                height: 80px;
                margin-bottom: 20px;
                border-radius: 16px;
            }
            .sd-user-bar {
                display: flex;
                align-items: center;
                justify-content: space-between;
                background: rgba(255,255,255,0.95);
                padding: 12px 24px;
                border-radius: 12px;
                margin-bottom: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.08);
            }
            .sd-user-info {
                display: flex;
                align-items: center;
                gap: 12px;
            }
            .sd-user-email {
                font-weight: 500;
                color: #333;
            }
            .sd-logout-btn {
                background: #f1f5f9;
                color: #64748b;
                border: none;
                padding: 8px 16px;
                border-radius: 8px;
                font-size: 0.9rem;
                cursor: pointer;
                transition: all 0.2s;
            }
            .sd-logout-btn:hover {
                background: #e2e8f0;
                color: #334155;
            }
        `;
        document.head.appendChild(styles);
    }
};

// Auto-inject styles when script loads
StudyDecoderAuth.injectStyles();
