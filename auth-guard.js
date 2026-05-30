/**
 * Study Decoder — Shared auth-guard helper.
 *
 * Every tool page (worksheet decoder, practice, syllabus, timetable, ...)
 * previously shipped its own copy of the auth check that:
 *   1. Showed an "auth-loading-overlay" spinner.
 *   2. Called GET /api/subscription with credentials.
 *   3. Hid the overlay and revealed #mainContent on success.
 *
 * Drawbacks of the per-page implementation:
 *   - No fetch timeout — a hung /api/subscription left users staring at
 *     "Checking access..." forever with no way out (the bug the user
 *     reported as 'stuck on auth' on worksheet-decoder).
 *   - No retry on transient network failure.
 *   - Errors silently redirected to login, masking real backend
 *     problems and making debugging impossible.
 *   - Subtle drift between pages: some pages used different access
 *     conditions, opening accidental loopholes or false 'no access'
 *     redirects.
 *
 * This module fixes all four by centralising the logic.
 *
 * Public API:
 *   SDAuthGuard.run(opts?)
 *     -> Promise<{ data, hasAccess, hasFullAccess } | null>
 *
 *     Resolves with the subscription payload once access is confirmed,
 *     OR redirects the user (and never resolves) on 401 / no-access,
 *     OR shows a visible error inside the auth overlay (and resolves
 *     to null) on timeout / 5xx.
 *
 *   Options:
 *     - overlayId       (default 'authOverlay')      element to hide
 *     - mainContentId   (default 'mainContent')      element to reveal
 *     - timeoutMs       (default 8000)               per-attempt timeout
 *     - maxAttempts     (default 2)                  attempts on transient err
 *     - onSuccess(data)                               called once with payload
 *     - noAccessRedirect (default 'index.html')      where to send no-access
 *     - loginRedirect    (default 'login.html')      where to send unauth'd
 */
(function () {
  'use strict';
  if (window.SDAuthGuard) return;

  function defaultApiBase() {
    return (typeof API_BASE !== 'undefined' && API_BASE != null) ? API_BASE : '';
  }

  function fetchWithTimeout(url, timeoutMs) {
    var init = { credentials: 'include' };
    // AbortSignal.timeout works in all browsers Render serves; if missing
    // we fall back to a manual AbortController so very old browsers don't
    // break the helper outright.
    if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
      init.signal = AbortSignal.timeout(timeoutMs);
    } else if (typeof AbortController !== 'undefined') {
      var ctrl = new AbortController();
      setTimeout(function () { ctrl.abort(); }, timeoutMs);
      init.signal = ctrl.signal;
    }
    return fetch(url, init);
  }

  function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c];
    });
  }

  function showOverlayError(overlay, message, retryLabel) {
    if (!overlay) return;
    overlay.classList.remove('hidden');
    overlay.style.flexDirection = 'column';
    overlay.innerHTML = ''
      + '<div style="max-width:380px;padding:0 20px;text-align:center;">'
      +   '<div style="font-size:28px;margin-bottom:8px;">\u26A0\uFE0F</div>'
      +   '<div style="color:#e7e9ea;font-weight:600;font-size:1.05rem;margin-bottom:6px;">Couldn\u2019t verify your session</div>'
      +   '<div style="color:#9aa0a6;font-size:0.9rem;line-height:1.5;margin-bottom:18px;">' + escapeHtml(message) + '</div>'
      +   '<button id="sdAuthRetryBtn" type="button" style="background:#6C63FF;color:#fff;border:none;padding:10px 20px;border-radius:8px;font-weight:600;font-size:0.9rem;cursor:pointer;margin-right:8px;">' + escapeHtml(retryLabel || 'Retry') + '</button>'
      +   '<a href="login.html?redirect=' + encodeURIComponent(window.location.pathname) + '" style="color:#71767b;font-size:0.9rem;text-decoration:underline;">Sign in instead</a>'
      + '</div>';
    var btn = document.getElementById('sdAuthRetryBtn');
    if (btn) {
      btn.addEventListener('click', function () { window.location.reload(); });
    }
  }

  function hasAccess(data) {
    if (!data) return false;
    if (data.role === 'owner' || data.role === 'lifetime' || data.role === 'og_tester') return true;
    if (data.subscribed) return true;
    if (data.dayPassActive) return true;
    if (data.teacherSubscribed) return true;
    if (data.teacherTrialActive) return true;
    // Free tier: onboarded students can still use limited tools.
    if (data.freeAcknowledged) return true;
    if (data.preferences && data.preferences.onboarded) return true;
    return false;
  }

  async function run(opts) {
    opts = opts || {};
    var overlayId = opts.overlayId || 'authOverlay';
    var mainId = opts.mainContentId || 'mainContent';
    var timeoutMs = opts.timeoutMs || 8000;
    var maxAttempts = opts.maxAttempts || 2;
    var noAccess = opts.noAccessRedirect || 'index.html';
    var loginPath = opts.loginRedirect || 'login.html';
    var overlay = document.getElementById(overlayId);
    var main = document.getElementById(mainId);
    var url = defaultApiBase() + '/api/subscription';

    var attempt = 0;
    var lastErr = null;
    var res = null;
    while (attempt < maxAttempts) {
      attempt++;
      try {
        res = await fetchWithTimeout(url, timeoutMs);
        break;
      } catch (e) {
        lastErr = e;
        if (attempt >= maxAttempts) break;
        // brief backoff between attempts
        await new Promise(function (r) { setTimeout(r, 400); });
      }
    }

    if (!res) {
      var msg = (lastErr && lastErr.name === 'TimeoutError' || lastErr && lastErr.name === 'AbortError')
        ? 'The server didn\u2019t respond in time. Check your connection and try again.'
        : 'Couldn\u2019t reach the server. Check your connection and try again.';
      showOverlayError(overlay, msg);
      return null;
    }

    if (res.status === 401) {
      window.location.href = loginPath + '?redirect=' + encodeURIComponent(window.location.pathname);
      return null;
    }

    if (!res.ok) {
      showOverlayError(overlay, 'Server returned status ' + res.status + '. The site may be having a hiccup \u2014 try again in a moment.');
      return null;
    }

    var data;
    try {
      data = await res.json();
    } catch (e) {
      showOverlayError(overlay, 'Got a malformed response from the server. Please retry in a moment.');
      return null;
    }

    if (!hasAccess(data)) {
      window.location.href = noAccess;
      return null;
    }

    if (overlay) overlay.classList.add('hidden');
    if (main) main.classList.remove('hidden');

    if (typeof opts.onSuccess === 'function') {
      try { opts.onSuccess(data); } catch (e) { console.error('[SDAuthGuard.onSuccess]', e); }
    }

    return {
      data: data,
      hasAccess: true,
      hasFullAccess:
        data.role === 'owner' ||
        data.role === 'lifetime' ||
        data.role === 'og_tester' ||
        data.subscribed === true ||
        data.dayPassActive === true ||
        data.teacherSubscribed === true
    };
  }

  window.SDAuthGuard = { run: run, hasAccess: hasAccess };
})();
