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

    return { get, renderModal, notifyOnReset, checkReminder, checkGracePeriodEnding };
})();
