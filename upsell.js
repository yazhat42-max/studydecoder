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
                body: 'Premium runs on smarter <strong>GPT-5</strong> and gives you unlimited full exams across all 45 subjects — plus Band 6 model answers on every question and your predicted ATAR.',
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
                body: 'Upgrade to premium for unlimited access to all tools — no caps, no daily resets, and smarter <strong>GPT-5</strong> answers (Free runs on GPT-4o mini).',
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
        container.innerHTML = `
            <div style="background:#16202a;border:1px solid #2f3336;border-radius:20px;padding:32px;max-width:440px;width:92%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.5);">
                <div style="font-size:2.5rem;margin-bottom:12px;">${msg.emoji}</div>
                <h2 style="color:#e7e9ea;font-size:1.3rem;font-weight:700;margin-bottom:10px;font-family:inherit;">${msg.headline}</h2>
                <p style="color:#71767b;font-size:0.95rem;line-height:1.65;margin-bottom:24px;">${msg.body}</p>
                <button id="upsellUpgradeBtn" style="display:block;width:100%;padding:14px;border:none;border-radius:12px;background:linear-gradient(135deg,#6C63FF,#8b5cf6);color:#fff;font-size:1rem;font-weight:700;cursor:pointer;margin-bottom:10px;font-family:inherit;">${msg.ctaLabel}</button>
                <a id="upsellTeacherBtn" href="/teacher-pricing.html" style="display:block;width:100%;padding:12px;border:1px solid rgba(34,197,94,0.35);border-radius:12px;background:rgba(34,197,94,0.07);color:#4ade80;font-size:0.92rem;font-weight:600;cursor:pointer;margin-bottom:10px;font-family:inherit;text-decoration:none;">🎓 Are you a teacher? Get the classroom plan →</a>
                <div style="display:flex;gap:8px;justify-content:center;margin-top:6px;">
                    <button id="upsellRemindBtn" style="background:none;border:none;color:#4f8cff;font-size:0.85rem;cursor:pointer;font-family:inherit;padding:6px 12px;border-radius:8px;">🔔 Remind me tomorrow</button>
                    <button id="upsellDismissBtn" style="background:none;border:none;color:#71767b;font-size:0.85rem;cursor:pointer;font-family:inherit;padding:6px 12px;border-radius:8px;">Dismiss</button>
                </div>
            </div>
        `;

        container.querySelector('#upsellUpgradeBtn').onclick = onUpgrade;

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

    // Cached user role + classroom flag so we don't refetch /api/subscription
    // every time the upsell pops. Populated by auth.js after its check; if
    // it hasn't fired yet we fall back to the sd_user_cache localStorage
    // entry that auth.js writes on every load.
    let cachedUser = null;
    function setCachedUser(u) { cachedUser = u || null; }
    function getCurrentUser() {
        if (cachedUser) return cachedUser;
        try {
            const raw = localStorage.getItem('sd_user_cache');
            if (raw) {
                const parsed = JSON.parse(raw);
                if (parsed && parsed.email) return parsed;
            }
        } catch (e) { /* ignore */ }
        return null;
    }

    /**
     * Show a full upgrade modal — works on any page (tool pages don't have #upgradeModalOverlay).
     * Falls back to window.showUpgradeModal() if available (index.html).
     * Teachers are routed to the teacher seat pricing page instead of the
     * consumer student tier modal.
     */
    function showPageUpgradeModal() {
        if (window.sdTrack) window.sdTrack('paywall_hit', { kind: 'free_tier' });
        // Teacher accounts: don't show the student $5/mo modal — route to
        // teacher-pricing.html where the actual classroom plans live.
        const u = getCurrentUser();
        if (u && u.role === 'teacher') {
            window.location.href = '/teacher-pricing.html';
            return;
        }
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
                    <p style="color:rgba(255,255,255,0.4);font-size:0.82rem;margin-bottom:16px;">Powered by GPT-5 &middot; Unlimited uses &middot; All tools</p>

                    <!-- VALUE STACK -->
                    <div style="text-align:left;background:rgba(255,255,255,0.03);border:1px solid rgba(167,139,250,0.18);border-radius:12px;padding:13px 16px;margin-bottom:16px;font-size:0.85rem;color:rgba(255,255,255,0.82);line-height:1.95;">
                        <div><span style="color:#a78bfa;">✦</span> <strong>Smarter GPT-5 answers</strong> <span style="color:rgba(255,255,255,0.4);">— Free runs on GPT-4o mini</span></div>
                        <div><span style="color:#a78bfa;">✦</span> <strong>Unlimited</strong> exams, worksheets, flashcards &amp; tutor chat</div>
                        <div><span style="color:#a78bfa;">✦</span> Band 6 model answers + your predicted ATAR</div>
                        <div><span style="color:#a78bfa;">✦</span> All 45 subjects &amp; every tool unlocked</div>
                    </div>

                    <!-- LIFETIME HERO (full width) — shown only while founding is open -->
                    <div id="sdUMLifetimeWrap" style="position:relative;margin-bottom:14px;">
                        <div style="position:absolute;top:-13px;left:50%;transform:translateX(-50%);white-space:nowrap;background:linear-gradient(135deg,#f59e0b,#d97706);color:#000;font-weight:800;font-size:0.68rem;padding:3px 14px;border-radius:20px;letter-spacing:0.5px;">
                            ⭐ FOUNDING OFFER — LIMITED RELEASE &nbsp;·&nbsp; <span id="sdUMSpotsLeft">?? spots</span> left
                        </div>
                        <button id="sdUMLifetimeBtn" style="width:100%;padding:28px 20px 22px;background:linear-gradient(135deg,#4f3dc4,#7c3aed);color:#fff;border:2px solid rgba(167,139,250,0.4);border-radius:16px;display:flex;flex-direction:column;align-items:center;cursor:pointer;font-family:inherit;box-shadow:0 6px 30px rgba(102,126,234,0.4);transition:transform .15s,box-shadow .15s;" onmouseover="this.style.transform='translateY(-2px)';this.style.boxShadow='0 10px 40px rgba(102,126,234,0.55)'" onmouseout="this.style.transform='none';this.style.boxShadow='0 6px 30px rgba(102,126,234,0.4)'">
                            <span style="font-size:0.78rem;opacity:0.7;letter-spacing:0.5px;text-transform:uppercase;">One-Time Payment &nbsp;&middot;&nbsp; Lifetime Access</span>
                            <span style="font-size:2.8rem;font-weight:900;margin:6px 0 0;line-height:1;" id="sdUMLifetimePrice">$14.99</span>
                            <span style="background:rgba(255,255,255,0.12);border-radius:8px;padding:5px 14px;font-size:0.8rem;font-weight:600;margin-top:8px;">Pay once. Use through all of Year 11 &amp; 12. ✓</span>
                        </button>
                    </div>

                    <!-- MONTHLY TIERS — populated from /api/spots-left once founding closes -->
                    <div id="sdUMMonthlyTiers" style="display:none;"></div>

                    <div id="sdUMPollingStatus" style="display:none;text-align:center;margin-bottom:10px;padding:10px;background:rgba(22,163,74,0.1);border:1px solid rgba(34,197,94,0.3);border-radius:8px;color:#22c55e;font-size:0.85rem;">⏳ Waiting for payment... Will activate automatically.</div>
                    <p id="sdUMManualHint" style="color:rgba(255,255,255,0.3);font-size:0.75rem;margin-bottom:10px;display:none;">Not detected? <a href="#" id="sdUMManualCheck" style="color:#6C63FF;">Check manually</a></p>
                    <button id="sdUMCloseBtn" style="width:100%;padding:11px;background:rgba(255,255,255,0.04);color:rgba(255,255,255,0.35);border:1px solid rgba(255,255,255,0.07);border-radius:10px;font-weight:600;cursor:pointer;font-family:inherit;font-size:0.85rem;">Close</button>
                </div>
            `;
            document.body.appendChild(overlay);

            // Fetch live offer state: while founding is open, show the lifetime
            // hero; once it closes, hide lifetime and render the monthly tiers.
            fetch(API_BASE + '/api/spots-left')
                .then(r => r.json())
                .then(d => {
                    if (d.foundingActive === false) {
                        renderMonthlyTiers(d.monthlyTiers || []);
                        return;
                    }
                    const el = document.getElementById('sdUMSpotsLeft');
                    if (el && d.spotsLeft !== undefined) {
                        el.textContent = d.spotsLeft + ' spot' + (d.spotsLeft !== 1 ? 's' : '');
                    }
                    if (d.lifetimePriceLabel) {
                        const p = document.getElementById('sdUMLifetimePrice');
                        if (p) p.textContent = d.lifetimePriceLabel;
                    }
                }).catch(() => {});

            // Render the three monthly tier cards in place of the lifetime hero.
            function renderMonthlyTiers(tiers) {
                const wrap = document.getElementById('sdUMLifetimeWrap');
                if (wrap) wrap.style.display = 'none';
                const box = document.getElementById('sdUMMonthlyTiers');
                if (!box || !tiers.length) return;
                box.style.display = 'block';
                box.innerHTML = tiers.map((t, i) => {
                    const featured = t.id === 'plus';
                    const uses = t.dailyUses === null ? 'Unlimited uses' : t.dailyUses + ' uses/day';
                    return '<button data-plan="' + t.id + '" style="width:100%;text-align:left;padding:14px 16px;margin-bottom:8px;border-radius:12px;cursor:pointer;font-family:inherit;'
                        + 'border:' + (featured ? '2px solid rgba(167,139,250,0.6)' : '1px solid rgba(255,255,255,0.12)') + ';'
                        + 'background:' + (featured ? 'rgba(124,58,237,0.18)' : 'rgba(255,255,255,0.03)') + ';color:#fff;display:flex;justify-content:space-between;align-items:center;">'
                        + '<span><strong style="font-size:0.98rem;">' + t.label + '</strong>'
                        + (featured ? ' <span style="font-size:0.62rem;background:#7c3aed;border-radius:6px;padding:2px 6px;vertical-align:middle;">POPULAR</span>' : '')
                        + '<br><span style="font-size:0.78rem;color:rgba(255,255,255,0.55);">' + uses + '</span></span>'
                        + '<span style="font-size:1.15rem;font-weight:800;">' + t.priceLabel + '<span style="font-size:0.72rem;font-weight:500;color:rgba(255,255,255,0.5);">/mo</span></span>'
                        + '</button>';
                }).join('');
                box.querySelectorAll('button[data-plan]').forEach(b => {
                    b.onclick = () => checkout(b.getAttribute('data-plan'));
                });
            }

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

    /**
     * Show a subject-locked modal when an AI endpoint returns 402 with
     * code SUBJECT_LOCKED. `data` is the parsed JSON body from that response.
     * Fetches /api/classroom-pricing on first call to compute the discount.
     */
    function showSubjectLockedModal(data) {
        if (window.sdTrack) window.sdTrack('paywall_hit', { kind: 'subject_locked' });
        const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' ? 'http://localhost:3001' : '';
        const subjectName = (data && (data.requestedSubjectName || data.subject)) || 'this subject';
        const enrolled = (data && Array.isArray(data.enrolledSubjects)) ? data.enrolledSubjects : [];
        const enrolledLine = enrolled.length
            ? 'Your class only covers <strong>' + enrolled.map(escAttr).join(', ') + '</strong>.'
            : 'Your class hasn\'t set a subject yet — ask your teacher to set one.';

        let overlay = document.getElementById('sdSubjectLockedOverlay');
        if (overlay) overlay.remove();
        overlay = document.createElement('div');
        overlay.id = 'sdSubjectLockedOverlay';
        overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.85);backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;z-index:99999;padding:16px;';
        overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
        overlay.innerHTML = `
            <div style="background:#1a1a26;border:1px solid rgba(167,139,250,0.35);border-radius:20px;padding:30px 28px 22px;max-width:480px;width:100%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.7);">
                <div style="font-size:2.4rem;margin-bottom:12px;">🔒</div>
                <h2 style="color:#a78bfa;font-size:1.3rem;font-weight:800;margin-bottom:6px;">Locked: ${escAttr(subjectName)}</h2>
                <p style="color:rgba(255,255,255,0.65);font-size:0.92rem;line-height:1.55;margin-bottom:18px;">${enrolledLine}<br/>Unlock every subject across Study Decoder with the classroom discount.</p>

                <div id="sdSLPricing" style="margin-bottom:14px;color:rgba(255,255,255,0.5);font-size:0.85rem;">Loading discounted pricing…</div>

                <button id="sdSLUnlockBtn" disabled style="display:block;width:100%;padding:16px 20px;background:linear-gradient(135deg,#4f3dc4,#7c3aed);color:#fff;border:2px solid rgba(167,139,250,0.4);border-radius:14px;font-size:1rem;font-weight:800;cursor:pointer;margin-bottom:10px;font-family:inherit;box-shadow:0 6px 24px rgba(102,126,234,0.4);opacity:0.5;">Unlock Every Subject →</button>

                <p style="color:rgba(255,255,255,0.4);font-size:0.78rem;margin-bottom:10px;">Or stick with <strong>${enrolled.length ? enrolled.map(escAttr).join(' / ') : 'your class subject'}</strong> for free as long as your teacher's seat is active.</p>

                <button id="sdSLCloseBtn" style="width:100%;padding:10px;background:rgba(255,255,255,0.04);color:rgba(255,255,255,0.5);border:1px solid rgba(255,255,255,0.08);border-radius:10px;font-weight:600;cursor:pointer;font-family:inherit;font-size:0.85rem;">Close</button>
            </div>
        `;
        document.body.appendChild(overlay);
        document.getElementById('sdSLCloseBtn').onclick = () => overlay.remove();

        fetch(API_BASE + '/api/classroom-pricing')
            .then(r => r.json())
            .then(p => {
                const priceEl = document.getElementById('sdSLPricing');
                const btn = document.getElementById('sdSLUnlockBtn');
                if (!priceEl || !btn) return;
                const showLifetime = p.foundingActive;
                const plan = showLifetime ? 'classroom-lifetime' : 'classroom-monthly';
                if (showLifetime) {
                    priceEl.innerHTML = '<div style="font-size:0.72rem;color:#fbbf24;letter-spacing:0.5px;text-transform:uppercase;font-weight:700;margin-bottom:6px;">⚡ FOUNDING CLASSROOM DEAL — 20% OFF</div>'
                        + '<div style="font-size:2.4rem;font-weight:900;color:#fff;line-height:1;">' + escAttr(p.lifetimePriceLabel) + '</div>'
                        + '<div style="font-size:0.85rem;color:rgba(255,255,255,0.45);text-decoration:line-through;margin-top:4px;">' + escAttr(p.standardLifetimePriceLabel) + ' regular</div>'
                        + '<div style="font-size:0.8rem;color:rgba(255,255,255,0.55);margin-top:6px;">One-time payment · lifetime access · every subject</div>';
                    btn.textContent = 'Unlock Lifetime — ' + p.lifetimePriceLabel + ' →';
                } else {
                    priceEl.innerHTML = '<div style="font-size:2.4rem;font-weight:900;color:#fff;line-height:1;">' + escAttr(p.monthlyPriceLabel) + '<span style="font-size:1rem;font-weight:600;color:rgba(255,255,255,0.5);"> / month</span></div>'
                        + '<div style="font-size:0.85rem;color:rgba(255,255,255,0.45);text-decoration:line-through;margin-top:4px;">' + escAttr(p.standardMonthlyPriceLabel) + '/mo regular</div>'
                        + '<div style="font-size:0.8rem;color:rgba(255,255,255,0.55);margin-top:6px;">Cancel anytime · every subject unlocked</div>';
                    btn.textContent = 'Unlock — ' + p.monthlyPriceLabel + '/mo →';
                }
                btn.disabled = false;
                btn.style.opacity = '1';
                btn.onclick = () => startCheckout(plan, btn);
            })
            .catch(() => {
                const priceEl = document.getElementById('sdSLPricing');
                if (priceEl) priceEl.textContent = 'Pricing temporarily unavailable.';
            });
    }

    function startCheckout(plan, btn) {
        if (window.sdTrack) window.sdTrack('checkout_start', { plan: plan });
        const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' ? 'http://localhost:3001' : '';
        const orig = btn.textContent;
        btn.disabled = true; btn.textContent = 'Opening checkout…';
        fetch(API_BASE + '/api/create-checkout-session', {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ plan })
        })
            .then(async r => {
                const d = await r.json().catch(() => ({}));
                if (!r.ok) {
                    alert(d.error || 'Could not start checkout.');
                    btn.disabled = false; btn.textContent = orig;
                    return;
                }
                if (d.url) window.location.href = d.url;
                else { btn.disabled = false; btn.textContent = orig; }
            })
            .catch(() => {
                alert('Network error. Please try again.');
                btn.disabled = false; btn.textContent = orig;
            });
    }

    function escAttr(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

    /**
     * Helpers for subject-lock UI on tool pages.
     *
     * isSubjectLocked(subjectId, subjectName?) → true if the current user is
     *   a class-linked-only student and the subject isn't in their enrolled
     *   class subjects. Returns false for paid users / free-tier / teachers.
     *
     * decorateSubjectSelect(selectEl, getName?) → walks a <select>'s options,
     *   prefixes locked ones with 🔒 and remembers the lock state so
     *   onSubjectChange() can intercept selection.
     *
     * onSubjectChange(selectEl) → if the picked option is locked, reverts the
     *   selection and pops the unlock modal. Returns true if the change was
     *   intercepted, false otherwise — tool pages should `if (onSubjectChange(s)) return;`
     *   inside their own change handlers.
     */
    function getEnrolledSubjects() {
        const u = getCurrentUser();
        if (!u || !Array.isArray(u.enrolledSubjects)) return null;
        // Empty array means "no restriction" (paid user); a non-empty array means
        // "only these subjects are unlocked". Null = unknown (not yet hydrated).
        return u.enrolledSubjects;
    }
    function isSubjectLocked(subjectId, subjectName) {
        const enrolled = getEnrolledSubjects();
        if (!enrolled || !enrolled.length) return false; // unknown or unrestricted
        if (enrolled.includes(subjectId)) return false;
        if (subjectName && enrolled.includes(subjectName)) return false;
        return true;
    }
    function decorateSubjectSelect(selectEl, getName) {
        if (!selectEl) return;
        const enrolled = getEnrolledSubjects();
        if (!enrolled || !enrolled.length) return; // nothing to lock
        for (let i = 0; i < selectEl.options.length; i++) {
            const opt = selectEl.options[i];
            const id = opt.value;
            const name = (typeof getName === 'function') ? getName(opt) : opt.textContent;
            if (!id) continue;
            if (isSubjectLocked(id, name)) {
                opt.dataset.sdLocked = '1';
                if (!opt.dataset.sdLockedOriginal) {
                    opt.dataset.sdLockedOriginal = opt.textContent;
                    opt.textContent = '🔒 ' + opt.textContent;
                }
            }
        }
    }
    function onSubjectChange(selectEl) {
        if (!selectEl) return false;
        const opt = selectEl.options[selectEl.selectedIndex];
        if (!opt || opt.dataset.sdLocked !== '1') return false;
        const original = opt.dataset.sdLockedOriginal || opt.textContent.replace(/^🔒 /, '');
        showSubjectLockedModal({
            subject: opt.value,
            requestedSubjectName: original,
            enrolledSubjects: getEnrolledSubjects() || []
        });
        // Revert to the first non-locked option (or to a blank if there isn't one).
        let fallbackIdx = -1;
        for (let i = 0; i < selectEl.options.length; i++) {
            if (selectEl.options[i].dataset.sdLocked !== '1') { fallbackIdx = i; break; }
        }
        selectEl.selectedIndex = fallbackIdx >= 0 ? fallbackIdx : -1;
        return true;
    }

    return { get, renderModal, notifyOnReset, checkReminder, checkGracePeriodEnding, showPageUpgradeModal, showSubjectLockedModal, handleApiError, setCachedUser, isSubjectLocked, decorateSubjectSelect, onSubjectChange };
})();
