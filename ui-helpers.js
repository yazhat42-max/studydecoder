/**
 * Study Decoder — small global UI helpers.
 * Loaded on every page. Intentionally framework-free and side-effect-light.
 *
 *   showToast(message, type='info', durationMs=4000)
 *     type ∈ 'info' | 'success' | 'error' | 'warn'
 *
 *   safeFetch(url, opts)
 *     wraps fetch(); on network failure, shows an error toast and returns null.
 *     Otherwise returns the Response (callers still inspect res.ok / res.json()).
 *
 *   lockButton(buttonEl, labelWhileLocked='Loading…')
 *     disables the button and swaps its text. Returns an unlock() function.
 *     Use:  const unlock = lockButton(btn);  try { ... } finally { unlock(); }
 */
(function () {
    'use strict';
    if (window.__sdUiHelpersInstalled) return;
    window.__sdUiHelpersInstalled = true;

    // ── Toast container + styles ────────────────────────────────────────
    function ensureToastHost() {
        let host = document.getElementById('sd-toast-host');
        if (host) return host;
        host = document.createElement('div');
        host.id = 'sd-toast-host';
        host.setAttribute('role', 'status');
        host.setAttribute('aria-live', 'polite');
        host.style.cssText =
            'position:fixed;bottom:20px;left:50%;transform:translateX(-50%);' +
            'display:flex;flex-direction:column;gap:8px;align-items:center;' +
            'z-index:99999;pointer-events:none;max-width:90vw;';
        document.body.appendChild(host);

        const style = document.createElement('style');
        style.textContent =
            '.sd-toast{pointer-events:auto;padding:12px 18px;border-radius:10px;' +
            'font:500 14px/1.4 -apple-system,Segoe UI,Roboto,sans-serif;color:#fff;' +
            'box-shadow:0 8px 24px rgba(0,0,0,0.18);max-width:480px;' +
            'opacity:0;transform:translateY(8px);transition:opacity .2s,transform .2s;}' +
            '.sd-toast.show{opacity:1;transform:translateY(0);}' +
            '.sd-toast.error{background:#dc2626;}' +
            '.sd-toast.success{background:#16a34a;}' +
            '.sd-toast.warn{background:#d97706;}' +
            '.sd-toast.info{background:#4f46e5;}';
        document.head.appendChild(style);
        return host;
    }

    function showToast(message, type, durationMs) {
        type = type || 'info';
        durationMs = typeof durationMs === 'number' ? durationMs : 4000;
        const host = ensureToastHost();
        const el = document.createElement('div');
        el.className = 'sd-toast ' + type;
        el.textContent = String(message || '').slice(0, 240);
        host.appendChild(el);
        // Force reflow so the transition runs
        // eslint-disable-next-line no-unused-expressions
        el.offsetHeight;
        el.classList.add('show');
        setTimeout(function () {
            el.classList.remove('show');
            setTimeout(function () { el.remove(); }, 250);
        }, durationMs);
    }

    function describeFetchError(err, res) {
        if (err) {
            if (err.name === 'AbortError') return 'Request timed out. Please try again.';
            return 'Connection problem. Please check your internet and try again.';
        }
        if (res) {
            if (res.status === 429) return 'You\u2019re going a bit fast \u2014 please wait a moment and try again.';
            if (res.status === 401) return 'Your session expired. Please sign in again.';
            if (res.status === 403) return 'You don\u2019t have access to this action.';
            if (res.status >= 500) return 'Server error. Please try again in a moment.';
            if (res.status === 404) return 'That endpoint isn\u2019t available right now.';
        }
        return 'Something went wrong. Please try again.';
    }

    async function safeFetch(url, opts) {
        try {
            const res = await fetch(url, opts);
            if (!res.ok && res.status >= 500) {
                showToast(describeFetchError(null, res), 'error');
            }
            return res;
        } catch (err) {
            console.warn('[safeFetch]', url, err);
            showToast(describeFetchError(err), 'error');
            return null;
        }
    }

    function lockButton(btn, labelWhileLocked) {
        if (!btn) return function () {};
        const originalDisabled = btn.disabled;
        const originalAriaBusy = btn.getAttribute('aria-busy');
        const originalLabel = btn.dataset.sdOriginalLabel || btn.innerHTML;
        if (!btn.dataset.sdOriginalLabel) btn.dataset.sdOriginalLabel = originalLabel;
        btn.disabled = true;
        btn.setAttribute('aria-busy', 'true');
        if (labelWhileLocked) btn.innerHTML = labelWhileLocked;
        return function unlock() {
            btn.disabled = originalDisabled;
            if (originalAriaBusy === null) btn.removeAttribute('aria-busy');
            else btn.setAttribute('aria-busy', originalAriaBusy);
            if (labelWhileLocked) btn.innerHTML = originalLabel;
        };
    }

    window.showToast = showToast;
    window.safeFetch = safeFetch;
    window.lockButton = lockButton;
    window.describeFetchError = describeFetchError;
})();
