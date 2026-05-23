/**
 * Study Decoder — Student App Shell.
 * Injects a persistent left sidebar on the dashboard + every student tool
 * page so learners can switch tools without going home. Framework-free,
 * idempotent, and never throws. Pairs with app-shell.css.
 *
 * Reads /api/subscription exactly once and memoises it on window.__sdAuth
 * (a promise) so pages can await the same call instead of firing a second.
 */
(function () {
  'use strict';
  if (window.__sdShellInstalled) return;
  window.__sdShellInstalled = true;

  // ── Single, shared auth read (relative URL + cookies; avoids API_BASE) ──
  window.__sdAuth = window.__sdAuth || fetch('/api/subscription', { credentials: 'include' })
    .then(function (r) { return r.ok ? r.json() : null; })
    .catch(function () { return null; });

  function cachedLevel() {
    try {
      var c = JSON.parse(localStorage.getItem('sd_user_cache') || 'null');
      return c && c.preferences ? c.preferences.level : null;
    } catch (e) { return null; }
  }

  // ── Navigation model ──
  var NAV = [
    { sec: null, items: [
      { label: 'Dashboard', icon: '🏠', href: 'dashboard.html' }
    ] },
    { sec: 'Study', items: [
      { label: 'Syllabus Decoder', icon: '📖', href: 'syllabus.html', jr: 'syllabus-jr.html' },
      { label: 'Practice Questions', icon: '📝', href: 'practice.html', jr: 'practice-jr.html' },
      { label: 'Full Exam', icon: '🎓', href: 'practice.html?mode=exam', jr: 'practice-jr.html?mode=exam' },
      { label: 'Learn IRL', icon: '🎮', href: 'learn-irl.html' },
      { label: 'Flashcards', icon: '🃏', href: 'flashcards.html' },
      { label: 'Chat Tutor', icon: '🤖', href: 'chat-tutor.html' }
    ] },
    { sec: 'Create & revise', items: [
      { label: 'Documents', icon: '📂', href: 'documents.html' },
      { label: 'Study Games', icon: '🎯', href: 'games.html' }
    ] },
    { sec: 'Class', items: [
      { label: 'Join a Class', icon: '➕', href: 'join-class.html' },
      { label: 'Assignments', icon: '📌', href: 'student-assignments.html', need: 'linked' }
    ] },
    { sec: 'Account', items: [
      { label: 'Admin', icon: '🛠️', href: 'admin.html', need: 'owner' },
      { label: 'Manage subscription', icon: '⚙️', href: 'index.html?stay=1#manage', need: 'managesub' },
      { label: 'Profile', icon: '👤', href: 'profile.html' },
      { label: 'Sign out', icon: '↩️', href: '#', action: 'logout' }
    ] }
  ];

  function resolveHref(item, isJr) {
    return (isJr && item.jr) ? item.jr : item.href;
  }

  function markActive(root, isJr) {
    var path = (location.pathname.split('/').pop() || 'index.html');
    var curExam = location.search.indexOf('mode=exam') > -1;
    var links = root.querySelectorAll('.sd-nav-item[data-href]');
    for (var i = 0; i < links.length; i++) {
      var href = links[i].getAttribute('data-href');
      var page = href.split('?')[0];
      var itemExam = href.indexOf('mode=exam') > -1;
      var on = page === path && itemExam === curExam;
      links[i].classList.toggle('active', on);
      if (on) links[i].setAttribute('aria-current', 'page');
      else links[i].removeAttribute('aria-current');
    }
  }

  function build() {
    if (document.querySelector('.sd-sidebar')) return;
    var body = document.body;
    if (!body) return;
    var isJr = cachedLevel() === 'junior';

    var aside = document.createElement('aside');
    aside.className = 'sd-sidebar';
    aside.id = 'sdSidebar';
    aside.setAttribute('role', 'navigation');
    aside.setAttribute('aria-label', 'Primary');

    var html = '';
    html += '<div class="sd-sb-top">'
      + '<a class="sd-sb-brand" href="dashboard.html"><img src="/logo.png" alt=""><b>Study Decoder</b></a>'
      + '<button class="sd-collapse" id="sdCollapse" type="button" title="Hide sidebar" aria-label="Hide sidebar">«</button>'
      + '</div>';
    html += '<div class="sd-streak-chip" id="sdStreakChip"><span>🔥</span><span class="n" id="sdStreakNum">0</span><span>day streak</span></div>';
    html += '<nav class="sd-sb-nav">';
    for (var s = 0; s < NAV.length; s++) {
      var grp = NAV[s];
      if (grp.sec) html += '<div class="sd-sb-sec">' + grp.sec + '</div>';
      for (var i = 0; i < grp.items.length; i++) {
        var it = grp.items[i];
        var href = resolveHref(it, isJr);
        var attrs = 'class="sd-nav-item" data-href="' + href + '" href="' + (it.action ? '#' : href) + '"';
        if (it.action) attrs += ' data-action="' + it.action + '"';
        if (it.need) attrs += ' data-need="' + it.need + '" hidden';
        html += '<a ' + attrs + '><span class="ic">' + it.icon + '</span><span>' + it.label + '</span></a>';
      }
    }
    html += '</nav>';
    html += '<div class="sd-sb-foot">';
    html += '<a class="sd-upgrade" id="sdUpgrade" href="index.html?stay=1#pricing"><b>Upgrade to Pro</b><span>Unlock every tool, unlimited</span></a>';
    html += '<button class="sd-nav-item" id="sdThemeToggle" type="button" data-sd-theme-toggle hidden style="width:100%;background:none;border:none;cursor:pointer;font:inherit;text-align:left;"><span class="ic tt-ic">☀️</span><span class="tt-label">Light mode</span></button>';
    html += '</div>';
    aside.innerHTML = html;

    var hamb = document.createElement('button');
    hamb.className = 'sd-hamb';
    hamb.id = 'sdHamb';
    hamb.type = 'button';
    hamb.setAttribute('aria-label', 'Open menu');
    hamb.setAttribute('aria-controls', 'sdSidebar');
    hamb.setAttribute('aria-expanded', 'false');
    hamb.textContent = '☰';

    var scrim = document.createElement('div');
    scrim.className = 'sd-scrim';
    scrim.id = 'sdScrim';

    // Apply persisted desktop-collapsed state before the sidebar paints so it
    // doesn't flash open on every page load.
    var collapsed = false;
    try { collapsed = localStorage.getItem('sd_shell_collapsed') === '1'; } catch (e) {}
    body.classList.add('sd-shell-shifted');
    if (collapsed) body.classList.add('sd-shell-collapsed');

    body.appendChild(aside);
    body.appendChild(scrim);
    body.appendChild(hamb);

    // Theme toggle: only surface it where theme.js (light mode) is loaded.
    if (window.SDTheme) {
      var tt = aside.querySelector('#sdThemeToggle');
      if (tt) { tt.removeAttribute('hidden'); window.SDTheme.refresh(); }
    }

    markActive(aside, isJr);
    wireInteractions(aside, hamb, scrim);
    hydrate(aside);
  }

  // ── Mobile drawer + accessibility ──
  function wireInteractions(aside, hamb, scrim) {
    var lastFocus = null;

    function focusables() {
      return aside.querySelectorAll('a[href], button:not([disabled])');
    }
    function open() {
      lastFocus = document.activeElement;
      aside.classList.add('open');
      scrim.classList.add('open');
      hamb.setAttribute('aria-expanded', 'true');
      document.body.style.overflow = 'hidden';
      var f = focusables();
      if (f.length) f[0].focus();
      document.addEventListener('keydown', onKey);
    }
    function close() {
      aside.classList.remove('open');
      scrim.classList.remove('open');
      hamb.setAttribute('aria-expanded', 'false');
      document.body.style.overflow = '';
      document.removeEventListener('keydown', onKey);
      if (lastFocus && lastFocus.focus) lastFocus.focus();
    }
    function isOpen() { return aside.classList.contains('open'); }
    function onKey(e) {
      if (e.key === 'Escape') { close(); return; }
      if (e.key !== 'Tab') return;
      var f = focusables();
      if (!f.length) return;
      var first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }

    function isDesktop() { return window.matchMedia('(min-width: 1025px)').matches; }
    function setCollapsed(val) {
      document.body.classList.toggle('sd-shell-collapsed', val);
      try { localStorage.setItem('sd_shell_collapsed', val ? '1' : '0'); } catch (e) {}
      hamb.setAttribute('aria-expanded', String(!val));
    }
    hamb.setAttribute('aria-expanded', String(!document.body.classList.contains('sd-shell-collapsed')));

    hamb.addEventListener('click', function () {
      // Desktop: the hamburger only shows while collapsed, so it re-opens the
      // sidebar. Mobile: it toggles the off-canvas drawer.
      if (isDesktop()) setCollapsed(!document.body.classList.contains('sd-shell-collapsed') ? true : false);
      else { isOpen() ? close() : open(); }
    });
    scrim.addEventListener('click', close);
    var collapseBtn = aside.querySelector('#sdCollapse');
    if (collapseBtn) collapseBtn.addEventListener('click', function () {
      if (isDesktop()) setCollapsed(true);
      else close();
    });

    aside.addEventListener('click', function (e) {
      var link = e.target.closest ? e.target.closest('.sd-nav-item') : null;
      if (!link) return;
      if (link.getAttribute('data-action') === 'logout') {
        e.preventDefault();
        if (window.StudyDecoderAuth && window.StudyDecoderAuth.logout) window.StudyDecoderAuth.logout();
        else { fetch('/api/logout', { method: 'POST', credentials: 'include' }).finally(function () { location.href = '/login.html'; }); }
        return;
      }
      if (isOpen()) close();
    });
  }

  // ── Fill in auth-dependent bits once /api/subscription resolves ──
  function hydrate(aside) {
    window.__sdAuth.then(function (auth) {
      if (!auth) return;
      try {
        var isJr = auth.preferences && auth.preferences.level === 'junior';
        if (isJr) {
          // Re-resolve hrefs for junior variants then re-mark the active item.
          var links = aside.querySelectorAll('.sd-nav-item[data-href]');
          for (var i = 0; i < links.length; i++) {
            var label = links[i].textContent.trim();
            for (var s = 0; s < NAV.length; s++) {
              for (var j = 0; j < NAV[s].items.length; j++) {
                var it = NAV[s].items[j];
                if (it.label === label && it.jr) {
                  links[i].setAttribute('data-href', it.jr);
                  links[i].setAttribute('href', it.jr);
                }
              }
            }
          }
          markActive(aside, true);
        }

        // Assignments only when actually linked to a teacher's class.
        if (auth.linkedToTeacher) {
          var as = aside.querySelector('.sd-nav-item[data-need="linked"]');
          if (as) as.removeAttribute('hidden');
        }

        // Admin link only for the owner account.
        if (auth.role === 'owner') {
          var adm = aside.querySelector('.sd-nav-item[data-need="owner"]');
          if (adm) adm.removeAttribute('hidden');
        }

        // Manage subscription only for a self-managed paid plan (mirrors the
        // condition index.html uses for its "Manage Sub" button).
        var classLinkedOnly = auth.linkedToTeacher && !auth.plan && !auth.dayPassActive;
        if (auth.subscribed && !classLinkedOnly && auth.role !== 'owner' && auth.role !== 'lifetime' && auth.role !== 'og_tester') {
          var msEl = aside.querySelector('.sd-nav-item[data-need="managesub"]');
          if (msEl) msEl.removeAttribute('hidden');
        }

        // Upgrade CTA only for free users.
        var paid = auth.subscribed || auth.role === 'owner' || auth.role === 'teacher'
          || auth.role === 'lifetime' || auth.role === 'og_tester';
        if (!paid) {
          var up = aside.querySelector('#sdUpgrade');
          if (up) up.classList.add('show');
        }

        // Streak chip (keep local streak store in sync first).
        var count = 0;
        if (window.StreakManager && auth.streak) {
          try { window.StreakManager.mergeFromServer(auth.streak); } catch (e) {}
        }
        if (auth.streak && typeof auth.streak.count === 'number') count = auth.streak.count;
        else { try { count = (JSON.parse(localStorage.getItem('sd_study_streak') || '{}').count) || 0; } catch (e) {} }
        if (count > 0) {
          var chip = aside.querySelector('#sdStreakChip');
          var num = aside.querySelector('#sdStreakNum');
          if (num) num.textContent = count;
          if (chip) chip.classList.add('show');
        }
      } catch (e) { /* shell must never break the page */ }
    });
  }

  if (document.body) build();
  else document.addEventListener('DOMContentLoaded', build);
})();
