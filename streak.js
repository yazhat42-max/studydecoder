/**
 * streak.js — Study Decoder shared streak manager
 * Features: shields, levels, themes, milestone overlays, heatmap data
 */
(function () {
    'use strict';

    var MILESTONES = [7, 30, 60, 100];

    var LEVELS = [
        { min: 100, name: 'Platinum', color: '#a855f7', bg: 'rgba(168,85,247,0.12)', emoji: '💎', theme: 'platinum' },
        { min: 60,  name: 'Gold',     color: '#f7c948', bg: 'rgba(247,201,72,0.12)',  emoji: '🥇', theme: 'gold' },
        { min: 30,  name: 'Silver',   color: '#94a3b8', bg: 'rgba(148,163,184,0.12)', emoji: '🥈', theme: 'silver' },
        { min: 7,   name: 'Bronze',   color: '#fb923c', bg: 'rgba(251,146,60,0.12)',  emoji: '🥉', theme: 'bronze' },
    ];

    var THEME_VARS = {
        default:  { '--streak-fire': '#ff6b35', '--streak-glow': 'rgba(255,107,53,0.22)',  '--streak-bg-tint': 'transparent' },
        bronze:   { '--streak-fire': '#fb923c', '--streak-glow': 'rgba(251,146,60,0.22)',  '--streak-bg-tint': 'rgba(251,146,60,0.015)' },
        silver:   { '--streak-fire': '#94a3b8', '--streak-glow': 'rgba(148,163,184,0.22)', '--streak-bg-tint': 'rgba(148,163,184,0.015)' },
        gold:     { '--streak-fire': '#f7c948', '--streak-glow': 'rgba(247,201,72,0.28)',  '--streak-bg-tint': 'rgba(247,201,72,0.018)' },
        platinum: { '--streak-fire': '#a855f7', '--streak-glow': 'rgba(168,85,247,0.28)',  '--streak-bg-tint': 'rgba(168,85,247,0.018)' },
    };

    /* ─── Data layer ─────────────────────────────────────────────── */
    var _API_BASE = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
        ? 'http://localhost:3001' : '';

    var StreakManager = {
        KEY: 'sd_study_streak',

        load: function () {
            try {
                var d = JSON.parse(localStorage.getItem(this.KEY) || '{}');
                return {
                    count:           d.count           || 0,
                    lastDate:        d.lastDate        || '',
                    shields:         d.shields         !== undefined ? d.shields : 0,
                    shieldsEarned:   d.shieldsEarned   || 0,   // multiples of 7 already awarded
                    days:            d.days            || {},   // { "YYYY-MM-DD": 1 }
                    milestonesShown: d.milestonesShown || [],
                    theme:           d.theme           || 'default',
                    totalDays:       d.totalDays       || 0,    // all-time study days
                };
            } catch (e) {
                return { count:0, lastDate:'', shields:0, shieldsEarned:0, days:{}, milestonesShown:[], theme:'default', totalDays:0 };
            }
        },

        save: function (s) {
            try { localStorage.setItem(this.KEY, JSON.stringify(s)); } catch (e) {}
        },

        today:  function () { return new Date().toISOString().slice(0, 10); },
        yday:   function () { return new Date(Date.now() - 864e5).toISOString().slice(0, 10); },
        twoAgo: function () { return new Date(Date.now() - 2 * 864e5).toISOString().slice(0, 10); },

        getLevel: function (count) {
            for (var i = 0; i < LEVELS.length; i++) {
                if (count >= LEVELS[i].min) return LEVELS[i];
            }
            return null;
        },

        /**
         * Purely-local streak roll-over. Used as the offline fallback when the
         * server can't be reached. NOT the source of truth — see track().
         */
        _trackLocal: function () {
            var today  = this.today();
            var s      = this.load();

            if (s.lastDate === today) {
                this.applyTheme(s.theme);
                return { s: s, isNew: false, newMilestone: null, shieldEarned: false, shieldUsed: false };
            }

            var yday   = this.yday();
            var twoAgo = this.twoAgo();
            var shieldUsed = false;

            if (s.lastDate === yday) {
                s.count += 1;
            } else if (s.lastDate === twoAgo && s.shields > 0) {
                s.shields  -= 1;
                s.count    += 1;
                shieldUsed  = true;
            } else {
                s.count = 1;
            }

            s.lastDate = today;
            s.days[today] = 1;
            s.totalDays = (s.totalDays || 0) + 1;

            var newThreshold = Math.floor(s.count / 7);
            var shieldEarned = false;
            if (newThreshold > s.shieldsEarned) {
                s.shields       += (newThreshold - s.shieldsEarned);
                s.shieldsEarned  = newThreshold;
                shieldEarned     = true;
            }

            if      (s.count >= 100) s.theme = 'platinum';
            else if (s.count >= 60)  s.theme = 'gold';
            else if (s.count >= 30)  s.theme = 'silver';
            else if (s.count >= 7)   s.theme = 'bronze';
            else                      s.theme = 'default';

            var newMilestone = null;
            for (var i = 0; i < MILESTONES.length; i++) {
                var m = MILESTONES[i];
                if (s.count === m && s.milestonesShown.indexOf(m) === -1) {
                    newMilestone = m;
                    s.milestonesShown.push(m);
                    break;
                }
            }

            this.save(s);
            this.applyTheme(s.theme);
            return { s: s, isNew: true, newMilestone: newMilestone, shieldEarned: shieldEarned, shieldUsed: shieldUsed };
        },

        /**
         * Fold a server streak response back into local storage. The server
         * owns count/lastDate/shields/theme/milestones; the local-only `days`
         * heatmap is preserved (the server doesn't store it).
         */
        _applyServerResult: function (result) {
            var local = this.load();
            var srv = result.streak || {};
            var merged = {
                count:           typeof srv.count === 'number' ? srv.count : local.count,
                lastDate:        srv.lastDate || local.lastDate,
                shields:         typeof srv.shields === 'number' ? srv.shields : local.shields,
                shieldsEarned:   typeof srv.shieldsEarned === 'number' ? srv.shieldsEarned : local.shieldsEarned,
                totalDays:       typeof srv.totalDays === 'number' ? srv.totalDays : local.totalDays,
                theme:           srv.theme || local.theme || 'default',
                milestonesShown: Array.isArray(srv.milestonesShown) ? srv.milestonesShown : (local.milestonesShown || []),
                days:            local.days || {}
            };
            if (result.isNew && merged.lastDate) merged.days[merged.lastDate] = 1;
            this.save(merged);
            this.applyTheme(merged.theme);
            return { s: merged, isNew: !!result.isNew, newMilestone: result.newMilestone || null,
                     shieldEarned: !!result.shieldEarned, shieldUsed: !!result.shieldUsed };
        },

        /**
         * Call this every time a user completes a study action.
         *
         * Server-authoritative: the day-rollover is computed on the server so
         * two devices / tabs with divergent localStorage can't make the streak
         * flicker. Pass a callback to receive the result:
         *     StreakManager.track(function (result) { sdHandleTracking(result); });
         *
         * If no callback is given it falls back to the legacy synchronous
         * local-only behaviour (kept so older call sites don't break).
         */
        track: function (cb) {
            var self = this;
            if (typeof cb !== 'function') {
                // Legacy path — synchronous local roll-over + fire-and-forget sync.
                var r = self._trackLocal();
                if (r.isNew) self.syncToServer(self.load());
                return r;
            }
            var local = self.load();
            var done = false;
            var finish = function (result) {
                if (done) return;
                done = true;
                try { cb(result); } catch (e) {}
            };
            try {
                fetch(_API_BASE + '/api/streak/track', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ streak: local })
                }).then(function (res) {
                    if (!res.ok) throw new Error('streak track failed');
                    return res.json();
                }).then(function (result) {
                    finish(self._applyServerResult(result));
                }).catch(function () {
                    // Offline / server error — fall back to local roll-over.
                    var r = self._trackLocal();
                    finish(r);
                });
            } catch (e) {
                finish(self._trackLocal());
            }
        },

        applyTheme: function (theme) {
            var vars = THEME_VARS[theme] || THEME_VARS['default'];
            var root = document.documentElement;
            for (var k in vars) {
                root.style.setProperty(k, vars[k]);
            }
        },

        syncToServer: function (s) {
            try {
                fetch(_API_BASE + '/api/streak/sync', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ streak: s })
                }).catch(function () {}); // fire-and-forget
            } catch (e) {}
        },

        mergeFromServer: function (serverStreak) {
            if (!serverStreak) return;
            try {
                var local = this.load();
                var useServer = !local.count ||
                    serverStreak.count > local.count ||
                    (serverStreak.count === local.count && (serverStreak.lastDate || '') >= (local.lastDate || ''));
                if (useServer) {
                    var merged = Object.assign({}, local, serverStreak);
                    this.save(merged);
                    this.applyTheme(merged.theme || 'default');
                }
            } catch (e) {}
        },
    };

    /* ─── Milestone overlay ──────────────────────────────────────── */
    function showMilestoneOverlay(milestone, streakCount) {
        var level = StreakManager.getLevel(streakCount);
        var MSGS = {
            7:   { title: "7 days straight. The streak is real. 🔥",  sub: "You've unlocked your first Streak Shield — one missed day won't reset your progress. Keep going.", badge: 'Bronze' },
            30:  { title: "30 days. That's commitment. 🥈",           sub: "Silver status unlocked + a new Streak Shield. You're in the top tier of consistent students.",        badge: 'Silver' },
            60:  { title: "60 days. You're built different. 🥇",      sub: "Gold status unlocked. Two months of showing up every day — most students never get here.",           badge: 'Gold' },
            100: { title: "100 days. Absolute legend. 💎",            sub: "Platinum status. You have done something most people only talk about. Respect.",                       badge: 'Platinum' },
        };
        var msg = MSGS[milestone];
        if (!msg) return;

        var BADGE_COLORS = { Bronze:'#fb923c', Silver:'#94a3b8', Gold:'#f7c948', Platinum:'#a855f7' };
        var color = BADGE_COLORS[msg.badge] || '#6C63FF';
        var levelEmoji = level ? level.emoji : '⭐';

        var overlay = document.createElement('div');
        overlay.id = 'sdMilestoneOverlay';
        overlay.innerHTML = [
            '<style>',
            '@keyframes _sdFadeIn{from{opacity:0}to{opacity:1}}',
            '@keyframes _sdPopIn{from{opacity:0;transform:scale(0.82) translateY(28px)}to{opacity:1;transform:scale(1) translateY(0)}}',
            '@keyframes _sdConfetti{0%{transform:translateY(-30px) rotate(0deg);opacity:1}100%{transform:translateY(110vh) rotate(800deg);opacity:0}}',
            '.sd-mo-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.88);z-index:999999;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);animation:_sdFadeIn .35s ease;}',
            '.sd-mo-card{background:#111118;border:1px solid ' + color + '40;border-radius:24px;padding:3rem 2.5rem;max-width:480px;width:90%;text-align:center;box-shadow:0 0 80px ' + color + '1a,0 24px 60px rgba(0,0,0,0.6);animation:_sdPopIn .55s cubic-bezier(0.34,1.56,0.64,1);}',
            '.sd-mo-fire{font-size:3.5rem;display:block;margin-bottom:0.4rem;}',
            '.sd-mo-count{font-size:5.5rem;font-weight:900;line-height:1;color:' + color + ';text-shadow:0 0 50px ' + color + '80;letter-spacing:-3px;}',
            '.sd-mo-days{font-size:0.85rem;font-weight:700;color:rgba(255,255,255,0.35);text-transform:uppercase;letter-spacing:2.5px;margin-bottom:1.4rem;}',
            '.sd-mo-badge{display:inline-flex;align-items:center;gap:8px;padding:7px 20px;border-radius:50px;background:' + color + '18;border:1px solid ' + color + '44;color:' + color + ';font-weight:700;font-size:0.9rem;margin-bottom:1.6rem;}',
            '.sd-mo-title{font-size:1.35rem;font-weight:700;color:#fff;margin-bottom:0.6rem;font-family:Poppins,sans-serif;}',
            '.sd-mo-sub{font-size:0.92rem;color:rgba(255,255,255,0.52);line-height:1.65;margin-bottom:2rem;font-family:Poppins,sans-serif;}',
            '.sd-mo-btn{background:' + color + ';color:#fff;border:none;padding:0.9rem 2.6rem;border-radius:50px;font-size:1rem;font-weight:700;cursor:pointer;font-family:Poppins,sans-serif;box-shadow:0 0 28px ' + color + '55;transition:all .2s;}',
            '.sd-mo-btn:hover{transform:translateY(-2px);box-shadow:0 8px 36px ' + color + '77;}',
            '.sd-mo-piece{position:fixed;border-radius:2px;animation:_sdConfetti linear forwards;pointer-events:none;}',
            '</style>',
            '<div class="sd-mo-overlay" id="_sdMoInner">',
            '<div class="sd-mo-card">',
            '<span class="sd-mo-fire">🔥</span>',
            '<div class="sd-mo-count">' + milestone + '</div>',
            '<div class="sd-mo-days">Day Streak</div>',
            '<div class="sd-mo-badge">' + levelEmoji + ' ' + msg.badge + ' Status Unlocked</div>',
            '<div class="sd-mo-title">' + msg.title + '</div>',
            '<p class="sd-mo-sub">' + msg.sub + '</p>',
            '<button class="sd-mo-btn" id="_sdMoDismiss">Keep Going \u2192</button>',
            '</div>',
            '</div>',
        ].join('');

        // Confetti pieces
        var CONFETTI_COLORS = [color, '#ff6b35', '#f7c948', '#6C63FF', '#FF6584', '#4ade80', '#38bdf8'];
        for (var i = 0; i < 55; i++) {
            var c = document.createElement('div');
            c.className = 'sd-mo-piece';
            var w = 7 + Math.random() * 9;
            c.style.cssText = [
                'left:' + (Math.random() * 100) + '%',
                'top:-30px',
                'width:' + w + 'px',
                'height:' + w + 'px',
                'background:' + CONFETTI_COLORS[Math.floor(Math.random() * CONFETTI_COLORS.length)],
                'border-radius:' + (Math.random() > 0.45 ? '50%' : '2px'),
                'animation-duration:' + (2.2 + Math.random() * 3.2) + 's',
                'animation-delay:' + (Math.random() * 1.8) + 's',
                'opacity:' + (0.55 + Math.random() * 0.45),
            ].join(';');
            overlay.appendChild(c);
        }

        document.body.appendChild(overlay);

        document.getElementById('_sdMoDismiss').addEventListener('click', function () {
            overlay.remove();
        });

        // Auto-dismiss after 9 seconds
        setTimeout(function () { if (overlay.parentNode) overlay.remove(); }, 9000);
    }

    /* ─── Toasts ─────────────────────────────────────────────────── */
    function showToast(html, borderColor) {
        var n = document.createElement('div');
        n.style.cssText = [
            'position:fixed', 'bottom:28px', 'right:28px',
            'background:#111118', 'border:1px solid ' + borderColor,
            'border-radius:14px', 'padding:16px 22px', 'z-index:99998',
            'font-family:Poppins,sans-serif', 'font-size:0.9rem', 'font-weight:600',
            'box-shadow:0 8px 36px rgba(0,0,0,0.45)',
            'animation:_sdSlideIn .35s ease', 'max-width:320px',
        ].join(';');
        var style = document.createElement('style');
        style.textContent = '@keyframes _sdSlideIn{from{opacity:0;transform:translateX(110px)}to{opacity:1;transform:translateX(0)}}';
        n.appendChild(style);
        var span = document.createElement('span');
        span.innerHTML = html;
        n.appendChild(span);
        document.body.appendChild(n);
        setTimeout(function () { if (n.parentNode) n.remove(); }, 4500);
    }

    /* ─── Public API ─────────────────────────────────────────────── */
    window.StreakManager = StreakManager;

    window.sdHandleTracking = function (result) {
        if (!result.isNew) return;
        if (result.shieldUsed) {
            showToast('🛡️ <span style="color:#fb923c;">Streak Shield used!</span> Your streak stayed alive.', 'rgba(251,146,60,0.35)');
        }
        if (result.shieldEarned) {
            showToast('🛡️ <span style="color:#4f8cff;">Streak Shield earned!</span> You now have ' + result.s.shields + ' shield' + (result.s.shields !== 1 ? 's' : '') + '.', 'rgba(79,140,255,0.35)');
        }
        if (result.newMilestone) {
            // Small delay so any page transition settles first
            setTimeout(function () {
                showMilestoneOverlay(result.newMilestone, result.s.count);
            }, 600);
        }
    };

    /* ─── Auto-apply theme immediately on load ───────────────────── */
    try {
        var _s = StreakManager.load();
        StreakManager.applyTheme(_s.theme);
    } catch (e) {}

})();
