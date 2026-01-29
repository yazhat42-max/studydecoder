/**
 * Study Decoder - Enterprise Auth Client
 * ======================================
 * Shared authentication utilities for all protected pages.
 * Include this script in any page that requires authentication.
 */

const StudyDecoderAuth = {
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
            
            // Check subscription if required
            if (requireSubscription && !user.subscribed) {
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
    
    // Get role badge HTML
    getRoleBadge(role) {
        switch (role) {
            case 'owner':
                return '<span class="sd-role-badge sd-role-owner">👑 Owner</span>';
            case 'og_tester':
                return '<span class="sd-role-badge sd-role-og">🌟 OG Tester</span>';
            default:
                return '';
        }
    },
    
    // Show standard paywall
    showPaywall(user, containerId = null) {
        const html = `
            <div class="sd-paywall-overlay">
                <div class="sd-paywall-card">
                    <img src="logo.png" alt="Logo" class="sd-paywall-logo">
                    <h2>Unlock Full Access</h2>
                    <p class="sd-paywall-greeting">Hey <strong>${user?.name || user?.email || 'there'}</strong>! 👋</p>
                    <p class="sd-paywall-desc">Subscribe to access all Study Decoder tools.</p>
                    <a href="https://buy.stripe.com/eVq14masZ0oEbmO1n57Vm00" target="_blank" class="sd-paywall-btn sd-btn-primary">Monthly - $9.99/mo</a>
                    <a href="https://buy.stripe.com/9B6dR89oV5IYaiKghZ7Vm01" target="_blank" class="sd-paywall-btn sd-btn-secondary">Yearly - $79.99/yr (Save 33%)</a>
                    <p class="sd-paywall-note">After payment, click below to activate:</p>
                    <button onclick="window.location.reload()" class="sd-paywall-btn sd-btn-success">✓ I've Paid - Activate Now</button>
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
            .sd-btn-outline {
                background: #f1f5f9;
                color: #64748b;
            }
            .sd-paywall-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
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
