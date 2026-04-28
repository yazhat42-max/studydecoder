/**
 * upsell.js — Dynamic, benefit-stacked upsell copy for Study Decoder
 * Consumed by all tool pages when freeTierExhausted fires.
 * Usage:
 *   const msg = window.Upsell.get('practice', 'exam');
 *   // msg: { emoji, headline, body, ctaLabel, softCta }
 */

window.Upsell = (function () {
    const COPY = {
        practice: {
            exam: {
                emoji: '✏️',
                headline: 'You\'ve seen what Band 6 looks like.',
                body: 'Premium gives you unlimited full exams across all 45 subjects — plus score history so you can track exactly which modules you\'re improving in.',
                ctaLabel: 'Unlock Unlimited Exams →',
            },
            quick: {
                emoji: '⚡',
                headline: 'Quick Exam uses are up for today.',
                body: 'With premium you can drill as many quick questions as you need — any subject, any time. No daily cap, no waiting.',
                ctaLabel: 'Go Unlimited →',
            }
        },
        'learn-irl': {
            default: {
                emoji: '🌍',
                headline: 'Your real-life scenario just ended.',
                body: 'Premium unlocks all 45 subject scenarios with harder difficulty modes and your full game history — plus you keep earning streak shields.',
                ctaLabel: 'Unlock All Scenarios →',
            }
        },
        worksheet: {
            default: {
                emoji: '📄',
                headline: 'That took 3 seconds to decode.',
                body: 'Premium removes the daily cap so you can decode every worksheet in your folder — plus a "Show Working" toggle for step-by-step maths solutions.',
                ctaLabel: 'Remove the Cap →',
            }
        },
        'notes-transcriber': {
            default: {
                emoji: '📝',
                headline: 'Notes transcription used for today.',
                body: 'Premium lets you transcribe as many pages as you need. Pair it with the Syllabus Decoder to turn your notes into a proper study guide.',
                ctaLabel: 'Keep Transcribing →',
            }
        },
        syllabus: {
            default: {
                emoji: '📘',
                headline: 'Daily syllabus decodes reached.',
                body: 'Premium gives you unlimited decodes — tick off every dot point and watch your coverage tracker fill up module by module.',
                ctaLabel: 'Unlock Full Syllabus →',
            }
        },
        timetable: {
            default: {
                emoji: '📅',
                headline: 'Timetable uses up for today.',
                body: 'Premium lets you regenerate your timetable any time your schedule changes — no limits, no waiting until tomorrow.',
                ctaLabel: 'Go Unlimited →',
            }
        },
        'subject-advisor': {
            default: {
                emoji: '🎯',
                headline: 'Subject advice limit reached.',
                body: 'Get unlimited personalised subject advice and subject-swap comparisons with premium — useful as you lock in your Year 11 choices.',
                ctaLabel: 'Get Unlimited Advice →',
            }
        },
        default: {
            default: {
                emoji: '🚀',
                headline: 'You\'ve hit your free limit for today.',
                body: 'Upgrade to premium for unlimited access to all tools — no caps, no daily resets, better AI quality.',
                ctaLabel: 'Upgrade to Premium →',
            }
        }
    };

    function get(botType, mode) {
        const botCopy = COPY[botType] || COPY.default;
        return botCopy[mode] || botCopy.default || COPY.default.default;
    }

    /**
     * Render the upsell modal into a given container element.
     * container: DOM element to inject HTML into
     * botType: string e.g. 'practice'
     * mode: string e.g. 'exam' or 'default'
     * onUpgrade: callback when upgrade button is clicked
     * onRemind: callback when "Remind me tomorrow" is clicked
     */
    function renderModal(container, botType, mode, onUpgrade, onRemind) {
        const msg = get(botType, mode);
        const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' ? 'http://localhost:3001' : '';
        container.innerHTML = `
            <div style="background:#16202a;border:1px solid #2f3336;border-radius:20px;padding:32px;max-width:440px;width:92%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.5);">
                <div style="font-size:2.5rem;margin-bottom:12px;">${msg.emoji}</div>
                <h2 style="color:#e7e9ea;font-size:1.3rem;font-weight:700;margin-bottom:10px;font-family:inherit;">${msg.headline}</h2>
                <p style="color:#71767b;font-size:0.95rem;line-height:1.65;margin-bottom:24px;">${msg.body}</p>
                <button id="upsellUpgradeBtn" style="display:block;width:100%;padding:14px;border:none;border-radius:12px;background:linear-gradient(135deg,#6C63FF,#8b5cf6);color:#fff;font-size:1rem;font-weight:700;cursor:pointer;margin-bottom:10px;font-family:inherit;">${msg.ctaLabel}</button>
                <button id="upsellDayPassBtn" style="display:block;width:100%;padding:12px;border:1px solid rgba(251,191,36,0.35);border-radius:12px;background:rgba(251,191,36,0.07);color:#fbbf24;font-size:0.92rem;font-weight:600;cursor:pointer;margin-bottom:10px;font-family:inherit;">⚡ Day Pass — $1.99 for 24 hours</button>
                <div style="display:flex;gap:8px;justify-content:center;margin-top:6px;">
                    <button id="upsellRemindBtn" style="background:none;border:none;color:#4f8cff;font-size:0.85rem;cursor:pointer;font-family:inherit;padding:6px 12px;border-radius:8px;">🔔 Remind me tomorrow</button>
                    <button id="upsellDismissBtn" style="background:none;border:none;color:#71767b;font-size:0.85rem;cursor:pointer;font-family:inherit;padding:6px 12px;border-radius:8px;">Dismiss</button>
                </div>
            </div>
        `;

        container.querySelector('#upsellUpgradeBtn').onclick = onUpgrade;

        const dayPassBtn = container.querySelector('#upsellDayPassBtn');
        dayPassBtn.onclick = async () => {
            dayPassBtn.textContent = '⏳ Redirecting…';
            dayPassBtn.disabled = true;
            try {
                const r = await fetch(API_BASE + '/api/create-daypass-session', { method: 'POST', credentials: 'include' });
                const d = await r.json();
                if (d.alreadySubscribed) {
                    dayPassBtn.textContent = '✓ You already have full access';
                } else if (d.url) {
                    window.location.href = d.url;
                } else {
                    throw new Error(d.error || 'Unknown error');
                }
            } catch (e) {
                dayPassBtn.textContent = '⚡ Day Pass — $1.99 for 24 hours';
                dayPassBtn.disabled = false;
            }
        };

        container.querySelector('#upsellRemindBtn').onclick = () => {
            // Flag for tomorrow's visit
            const tomorrow = new Date();
            tomorrow.setDate(tomorrow.getDate() + 1);
            localStorage.setItem('upsellRemindDate', tomorrow.toISOString().split('T')[0]);
            if (onRemind) onRemind();
        };
        container.querySelector('#upsellDismissBtn').onclick = () => {
            container.style.display = 'none';
        };
    }

    /**
     * Show a "notify me when uses reset" option in the existing upsell UI.
     * Calls POST /api/notify/reset server-side.
     */
    async function notifyOnReset(buttonEl) {
        try {
            const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' ? 'http://localhost:3001' : '';
            await fetch(API_BASE + '/api/notify/reset', { method: 'POST', credentials: 'include' });
            if (buttonEl) {
                buttonEl.textContent = '✓ We\'ll email you when your uses reset';
                buttonEl.disabled = true;
                buttonEl.style.color = '#22c55e';
            }
        } catch (e) {
            console.warn('Could not set notify flag:', e);
        }
    }

    /**
     * Check localStorage for pending remind flag and show reminder banner if due.
     * Call on page load.
     */
    function checkReminder() {
        const remindDate = localStorage.getItem('upsellRemindDate');
        if (!remindDate) return;
        const today = new Date().toISOString().split('T')[0];
        if (today >= remindDate) {
            localStorage.removeItem('upsellRemindDate');
            const banner = document.createElement('div');
            banner.style.cssText = 'position:fixed;bottom:20px;right:20px;background:#16202a;border:1px solid rgba(108,99,255,0.4);border-radius:14px;padding:16px 20px;max-width:320px;z-index:9990;box-shadow:0 8px 32px rgba(0,0,0,0.4);animation:fadeIn 0.3s ease;';
            banner.innerHTML = `
                <p style="color:#e7e9ea;font-size:0.9rem;margin-bottom:10px;">🔔 Your free uses have reset — ready to keep studying?</p>
                <div style="display:flex;gap:8px;">
                    <button onclick="this.closest('div[style]').remove()" style="flex:1;padding:8px;border:none;border-radius:8px;background:linear-gradient(135deg,#6C63FF,#8b5cf6);color:#fff;font-size:0.85rem;font-weight:600;cursor:pointer;font-family:inherit;">Let's go →</button>
                    <button onclick="this.closest('div[style]').remove()" style="padding:8px 12px;border:1px solid #2f3336;border-radius:8px;background:transparent;color:#71767b;font-size:0.85rem;cursor:pointer;font-family:inherit;">✕</button>
                </div>`;
            document.body.appendChild(banner);
        }
    }

    /**
     * Check if grace period is ending (day 3) and show one-time banner.
     * freeTierData: the freeTier object from /api/subscription response.
     */
    function checkGracePeriodEnding(freeTierData) {
        if (!freeTierData || !freeTierData.gracePeriodEnding) return;
        if (localStorage.getItem('gracePeriodBannerShown')) return;
        localStorage.setItem('gracePeriodBannerShown', '1');
        const banner = document.createElement('div');
        banner.style.cssText = 'position:fixed;top:0;left:0;width:100%;background:linear-gradient(135deg,#6C63FF,#FF6584);color:#fff;text-align:center;padding:10px 20px;z-index:9999;font-size:0.9rem;font-family:inherit;';
        banner.innerHTML = `
            🔥 Your 3-day unlimited trial ends today — upgrade now to keep going.
            <button onclick="showUpgradeModal && showUpgradeModal()" style="margin-left:12px;background:#fff;color:#6C63FF;border:none;border-radius:8px;padding:4px 14px;font-weight:700;font-size:0.85rem;cursor:pointer;">Upgrade →</button>
            <button onclick="this.parentElement.remove()" style="margin-left:8px;background:none;border:none;color:rgba(255,255,255,0.8);font-size:1rem;cursor:pointer;">✕</button>
        `;
        document.body.prepend(banner);
    }

    /**
     * Show a full upgrade modal — works on any page (tool pages don't have #upgradeModalOverlay).
     * Falls back to window.showUpgradeModal() if available (index.html).
     */
    function showPageUpgradeModal() {
        // On index.html, use the built-in modal
        if (typeof window.showUpgradeModal === 'function' && document.getElementById('upgradeModalOverlay')) {
            window.showUpgradeModal();
            return;
        }
        const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' ? 'http://localhost:3001' : '';
        let overlay = document.getElementById('sdUpgradeModalOverlay');
        if (!overlay) {
            overlay = document.createElement('div');
            overlay.id = 'sdUpgradeModalOverlay';
            overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.85);backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;z-index:99999;padding:16px;';
            overlay.onclick = e => { if (e.target === overlay) overlay.style.display = 'none'; };
            overlay.innerHTML = `
                <div style="background:#1a1a26;border:1px solid rgba(108,99,255,0.3);border-radius:20px;padding:28px 28px 22px;max-width:480px;width:100%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.7);">
                    <h2 style="color:#a78bfa;font-size:1.3rem;margin-bottom:4px;">Upgrade to Premium</h2>
                    <p style="color:rgba(255,255,255,0.4);font-size:0.82rem;margin-bottom:20px;">Unlimited uses &middot; Better AI quality &middot; All 7 tools</p>

                    <!-- LIFETIME HERO (full width) -->
                    <div style="position:relative;margin-bottom:10px;">
                        <div style="position:absolute;top:-13px;left:50%;transform:translateX(-50%);white-space:nowrap;background:linear-gradient(135deg,#f59e0b,#d97706);color:#000;font-weight:800;font-size:0.68rem;padding:3px 14px;border-radius:20px;letter-spacing:0.5px;">
                            ⭐ FOUNDING OFFER — FIRST 100 USERS ONLY &nbsp;·&nbsp; <span id="sdUMSpotsLeft">?? spots</span> left
                        </div>
                        <button id="sdUMLifetimeBtn" style="width:100%;padding:28px 20px 22px;background:linear-gradient(135deg,#4f3dc4,#7c3aed);color:#fff;border:2px solid rgba(167,139,250,0.4);border-radius:16px;display:flex;flex-direction:column;align-items:center;cursor:pointer;font-family:inherit;box-shadow:0 6px 30px rgba(102,126,234,0.4);transition:transform .15s,box-shadow .15s;" onmouseover="this.style.transform='translateY(-2px)';this.style.boxShadow='0 10px 40px rgba(102,126,234,0.55)'" onmouseout="this.style.transform='none';this.style.boxShadow='0 6px 30px rgba(102,126,234,0.4)'">
                            <span style="font-size:0.78rem;opacity:0.7;letter-spacing:0.5px;text-transform:uppercase;">One-Time Payment &nbsp;&middot;&nbsp; Lifetime Access</span>
                            <span style="font-size:2.8rem;font-weight:900;margin:6px 0 0;line-height:1;">$37.50</span>
                            <span style="font-size:0.8rem;opacity:0.55;text-decoration:line-through;margin-bottom:6px;">$60/yr if you paid monthly</span>
                            <span style="background:rgba(255,255,255,0.12);border-radius:8px;padding:5px 14px;font-size:0.8rem;font-weight:600;">Pay once. Use through all of Year 11 &amp; 12. ✓</span>
                        </button>
                    </div>

                    <!-- MONTHLY FOOTNOTE (not a card) -->
                    <p style="color:rgba(255,255,255,0.3);font-size:0.78rem;margin-bottom:14px;">
                        Not sure yet? <button id="sdUMMonthlyBtn" style="background:none;border:none;color:#6C63FF;font-size:0.78rem;font-weight:600;cursor:pointer;font-family:inherit;padding:0;text-decoration:underline;">$5/month</button> — cancel anytime.
                    </p>

                    <!-- DAY PASS -->
                    <button id="sdUMDayPassBtn" style="display:block;width:100%;background:rgba(251,191,36,0.07);border:1px solid rgba(251,191,36,0.25);border-radius:10px;color:#fbbf24;padding:10px 20px;font-size:0.85rem;font-weight:600;cursor:pointer;font-family:inherit;margin-bottom:14px;">⚡ Just need today? Day Pass — $1.99</button>

                    <div id="sdUMPollingStatus" style="display:none;text-align:center;margin-bottom:10px;padding:10px;background:rgba(22,163,74,0.1);border:1px solid rgba(34,197,94,0.3);border-radius:8px;color:#22c55e;font-size:0.85rem;">⏳ Waiting for payment... Will activate automatically.</div>
                    <p id="sdUMManualHint" style="color:rgba(255,255,255,0.3);font-size:0.75rem;margin-bottom:10px;display:none;">Not detected? <a href="#" id="sdUMManualCheck" style="color:#6C63FF;">Check manually</a></p>
                    <button id="sdUMCloseBtn" style="width:100%;padding:11px;background:rgba(255,255,255,0.04);color:rgba(255,255,255,0.35);border:1px solid rgba(255,255,255,0.07);border-radius:10px;font-weight:600;cursor:pointer;font-family:inherit;font-size:0.85rem;">Close</button>
                </div>
            `;
            document.body.appendChild(overlay);

            // Fetch and display live spot count
            fetch(API_BASE + '/api/spots-left')
                .then(r => r.json())
                .then(d => {
                    const el = document.getElementById('sdUMSpotsLeft');
                    if (el && d.spotsLeft !== undefined) {
                        el.textContent = d.spotsLeft + ' spot' + (d.spotsLeft !== 1 ? 's' : '');
                        // If sold out, hide lifetime and swap hero to sprint
                        if (d.spotsLeft <= 0) {
                            const lifetimeBtn = document.getElementById('sdUMLifetimeBtn');
                            if (lifetimeBtn) lifetimeBtn.closest('div').style.display = 'none';
                        }
                    }
                }).catch(() => {});

            let sdPollInterval = null;
            const startPoll = () => {
                const s = document.getElementById('sdUMPollingStatus');
                const h = document.getElementById('sdUMManualHint');
                if (s) s.style.display = 'block';
                setTimeout(() => { if (h) h.style.display = 'block'; }, 15000);
                if (sdPollInterval) return;
                let att = 0;
                sdPollInterval = setInterval(async () => {
                    if (++att > 60) { clearInterval(sdPollInterval); sdPollInterval = null; return; }
                    try {
                        const r = await fetch(API_BASE + '/api/verify-payment', { method: 'POST', credentials: 'include' });
                        const d = await r.json();
                        if (d.success && d.subscribed) {
                            clearInterval(sdPollInterval); sdPollInterval = null;
                            const s = document.getElementById('sdUMPollingStatus');
                            if (s) s.innerHTML = '✅ Payment confirmed! Activating...';
                            setTimeout(() => window.location.reload(), 1200);
                        }
                    } catch(e) {}
                }, 5000);
            };
            const checkout = async (plan) => {
                try {
                    const r = await fetch(API_BASE + '/api/create-checkout-session', {
                        method: 'POST', credentials: 'include',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ plan })
                    });
                    const d = await r.json();
                    if (d.url) { startPoll(); window.open(d.url, '_blank'); }
                    else if (d.error === 'Not authenticated') { window.location.href = '/login.html'; }
                    else alert(d.error || 'Could not start checkout. Please try again.');
                } catch(e) { alert('Error starting checkout. Please try again.'); }
            };
            document.getElementById('sdUMLifetimeBtn').onclick = () => checkout('lifetime');
            document.getElementById('sdUMMonthlyBtn').onclick = () => checkout('monthly');
            document.getElementById('sdUMDayPassBtn').onclick = async () => {
                const btn = document.getElementById('sdUMDayPassBtn');
                btn.textContent = '⏳ Redirecting…'; btn.disabled = true;
                try {
                    const r = await fetch(API_BASE + '/api/create-daypass-session', { method: 'POST', credentials: 'include' });
                    const d = await r.json();
                    if (d.url) window.location.href = d.url;
                    else if (d.error === 'Not authenticated') window.location.href = '/login.html';
                    else { btn.textContent = '⚡ Just need today? Day Pass — $1.99'; btn.disabled = false; }
                } catch(e) { btn.textContent = '⚡ Just need today? Day Pass — $1.99'; btn.disabled = false; }
            };
            document.getElementById('sdUMManualCheck').onclick = async (e) => {
                e.preventDefault();
                try {
                    const r = await fetch(API_BASE + '/api/verify-payment', { method: 'POST', credentials: 'include' });
                    const d = await r.json();
                    if (d.success && d.subscribed) window.location.reload();
                    else alert(d.message || 'No payment found yet.');
                } catch(e) {}
            };
            document.getElementById('sdUMCloseBtn').onclick = () => { overlay.style.display = 'none'; };
        } else {
            // Already in DOM — refresh spot count
            fetch(API_BASE + '/api/spots-left')
                .then(r => r.json())
                .then(d => {
                    const el = document.getElementById('sdUMSpotsLeft');
                    if (el && d.spotsLeft !== undefined) el.textContent = d.spotsLeft + ' spot' + (d.spotsLeft !== 1 ? 's' : '');
                }).catch(() => {});
        }
        overlay.style.display = 'flex';
    }

    return { get, renderModal, notifyOnReset, checkReminder, checkGracePeriodEnding, showPageUpgradeModal };
})();
