/* retention.js — shared client for the daily-habit loop (Today plan, XP, readiness,
 * leaderboard). Renders into the dashboard if the matching containers exist.
 * Endpoints: GET /api/today, GET /api/leaderboard, POST /api/games/score.
 * Self-contained, defensive: every render no-ops when its container is absent. */
(function () {
  if (window.SDRetention) return;

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c];
    });
  }
  function el(id) { return document.getElementById(id); }
  function getJSON(path) {
    return fetch(path, { credentials: 'include' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .catch(function () { return null; });
  }

  var BAND_COLOR = { weak: '#ef4444', medium: '#fbbf24', developing: '#fbbf24', strong: '#22c55e' };

  function renderXp(xp) {
    var bar = el('xpBar');
    if (!bar || !xp) return;
    var span = Math.max(1, xp.nextLevelXp - xp.levelFloor);
    var prog = Math.max(0, Math.min(1, (xp.xp - xp.levelFloor) / span));
    bar.innerHTML =
      '<div class="xp-head"><span class="xp-lvl">Level ' + xp.level + '</span>' +
      '<span class="xp-num">' + xp.xp + ' XP' + (xp.weeklyXp ? ' · ' + xp.weeklyXp + ' this week' : '') + '</span></div>' +
      '<div class="xp-track"><div class="xp-fill" style="width:' + (prog * 100).toFixed(1) + '%"></div></div>' +
      '<div class="xp-foot">' + (xp.nextLevelXp - xp.xp) + ' XP to level ' + (xp.level + 1) + '</div>';
  }

  function renderPlan(plan) {
    var box = el('planList');
    if (!box) return;
    if (!plan || !plan.tasks || !plan.tasks.length) {
      box.innerHTML = '<div class="plan-empty">Pick your subjects in Profile to get a tailored daily plan.</div>';
      return;
    }
    var done = plan.doneIds || [];
    var html = '';
    for (var i = 0; i < plan.tasks.length; i++) {
      var t = plan.tasks[i];
      var isDone = done.indexOf(t.id) !== -1;
      html += '<a class="plan-task' + (isDone ? ' done' : '') + '" href="' + esc(t.href) + '">' +
        '<span class="pt-check">' + (isDone ? '✅' : '<span class="pt-circle"></span>') + '</span>' +
        '<span class="pt-ic">' + esc(t.icon || '•') + '</span>' +
        '<span class="pt-label">' + esc(t.label) + '</span>' +
        (isDone ? '' : '<span class="pt-go">→</span>') + '</a>';
    }
    if (plan.complete) {
      html = '<div class="plan-complete">🎉 Today\'s plan complete — streak secured. Keep the momentum!</div>' + html;
    }
    box.innerHTML = html;
  }

  function renderReadiness(bySubject) {
    var row = el('readinessRow');
    var sec = el('readinessSection');
    if (!row) return;
    var subjects = bySubject ? Object.keys(bySubject) : [];
    if (!subjects.length) { if (sec) sec.classList.add('hidden'); return; }
    if (sec) sec.classList.remove('hidden');
    subjects.sort(function (a, b) { return bySubject[a].pct - bySubject[b].pct; }); // weakest first
    var html = '';
    for (var i = 0; i < subjects.length; i++) {
      var s = subjects[i], r = bySubject[s];
      var col = BAND_COLOR[r.band] || '#a78bfa';
      html += '<div class="rd-chip">' +
        '<div class="rd-top"><span class="rd-name">' + esc(s) + '</span><span class="rd-pct" style="color:' + col + '">' + r.pct + '%</span></div>' +
        '<div class="rd-track"><div class="rd-fill" style="width:' + r.pct + '%;background:' + col + '"></div></div>' +
        '<div class="rd-band">Tracking ~' + esc(r.predictedBand) + '</div></div>';
    }
    row.innerHTML = html;
    var note = el('readinessNote');
    if (note) note.textContent = 'Estimated from the content you’ve practised — a guide, not a guarantee. Keep practising to lift it (it eases down when you’re away).';
  }

  function renderLeaderboard(data) {
    var panel = el('leaderboardPanel');
    if (!panel) return;
    if (!data || !data.hasClass || !data.rows || !data.rows.length) { panel.classList.add('hidden'); return; }
    panel.classList.remove('hidden');
    var rows = data.rows.slice(0, 10);
    var meId = data.me && data.me.userId;
    var html = '<h2 class="dash-h2">This week’s class leaderboard</h2><ul class="lb-list">';
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      var mine = r.userId === meId;
      html += '<li class="lb-row' + (mine ? ' me' : '') + '">' +
        '<span class="lb-rank">' + (r.rank <= 3 ? ['🥇', '🥈', '🥉'][r.rank - 1] : r.rank) + '</span>' +
        '<span class="lb-name">' + esc(r.name) + (mine ? ' (you)' : '') + '</span>' +
        '<span class="lb-xp">' + r.weeklyXp + ' XP</span></li>';
    }
    html += '</ul>';
    if (data.me && data.me.rank > 10) {
      html += '<div class="lb-you">You’re #' + data.me.rank + ' with ' + data.me.weeklyXp + ' XP this week.</div>';
    }
    panel.innerHTML = html;
  }

  function renderEvent(ev) {
    var box = el('seasonalBanner');
    if (!box) return;
    if (!ev) { box.innerHTML = ''; return; }
    var mult = ev.xpMultiplier > 1 ? (ev.xpMultiplier + '× XP on everything right now') : 'Limited-time event';
    box.innerHTML = '<div class="seasonal-banner"><span class="sb-ico">' + esc(ev.emoji || '🔥') + '</span>' +
      '<span><span class="sb-text">' + esc(ev.label) + '</span><br><span class="sb-sub">' + esc(mult) + '</span></span></div>';
  }

  function init(auth) {
    getJSON('/api/today').then(function (d) {
      if (!d) return;
      renderEvent(d.event);
      renderXp(d.xp);
      renderPlan(d.plan);
      renderReadiness(d.readiness);
      if (window.SDShareCard && auth && auth.streak && auth.streak.count > 0) {
        var btn = el('shareStreakBtn');
        if (btn) {
          btn.classList.remove('hidden');
          btn.addEventListener('click', function () {
            window.SDShareCard.share({
              title: 'My study streak', bigValue: auth.streak.count + ' 🔥',
              subtitle: 'day study streak on Study Decoder', accent: '#6C63FF'
            });
          });
        }
      }
    });
    getJSON('/api/leaderboard').then(renderLeaderboard);
  }

  window.SDRetention = { init: init };
})();
