/**
 * pwa.js — PWA install prompt handler
 * Include on all pages. Shows a dismissable install bar after first tool use.
 * Works on Android Chrome (beforeinstallprompt). Shows manual instructions on iOS.
 */
(function () {
    let _deferredPrompt = null;
    const STORAGE_KEY = 'pwaInstallDismissed';
    const INSTALL_EVENT_KEY = 'pwaFirstToolUse';

    // ── Detect iOS ──
    function isIOS() {
        return /iphone|ipad|ipod/i.test(navigator.userAgent) && !window.MSStream;
    }

    // ── Already installed ──
    function isInstalled() {
        return window.matchMedia('(display-mode: standalone)').matches
            || window.navigator.standalone === true;
    }

    // ── Capture the prompt ──
    window.addEventListener('beforeinstallprompt', function (e) {
        e.preventDefault();
        _deferredPrompt = e;
        // Show bar if user hasn't dismissed it and has used a tool
        if (!localStorage.getItem(STORAGE_KEY) && localStorage.getItem(INSTALL_EVENT_KEY)) {
            showInstallBar();
        }
    });

    // ── Public: call this after a user completes their first tool use ──
    window.pwaMarkFirstToolUse = function () {
        localStorage.setItem(INSTALL_EVENT_KEY, '1');
        if (_deferredPrompt && !localStorage.getItem(STORAGE_KEY) && !isInstalled()) {
            showInstallBar();
        } else if (isIOS() && !localStorage.getItem(STORAGE_KEY) && !isInstalled()) {
            showIOSBanner();
        }
    };

    function showInstallBar() {
        if (document.getElementById('pwaInstallBar')) return;
        const bar = document.createElement('div');
        bar.id = 'pwaInstallBar';
        bar.style.cssText = [
            'position:fixed', 'bottom:0', 'left:0', 'width:100%',
            'background:#16202a', 'border-top:1px solid rgba(108,99,255,0.3)',
            'padding:14px 20px', 'display:flex', 'align-items:center', 'gap:12px',
            'z-index:9990', 'box-shadow:0 -4px 20px rgba(0,0,0,0.4)',
            'animation:pwaSlideUp 0.3s ease'
        ].join(';');
        bar.innerHTML = `
            <style>@keyframes pwaSlideUp{from{transform:translateY(100%)}to{transform:translateY(0)}}</style>
            <span style="font-size:1.4rem;flex-shrink:0;">📲</span>
            <div style="flex:1;min-width:0;">
                <div style="font-size:0.9rem;font-weight:700;color:#e7e9ea;">Add Study Decoder to your home screen</div>
                <div style="font-size:0.78rem;color:#71767b;margin-top:2px;">Get faster access and offline mode</div>
            </div>
            <button id="pwaInstallBtn" style="flex-shrink:0;padding:9px 18px;border:none;border-radius:10px;background:linear-gradient(135deg,#6C63FF,#8b5cf6);color:#fff;font-size:0.85rem;font-weight:700;cursor:pointer;font-family:inherit;">Install</button>
            <button id="pwaInstallDismiss" style="flex-shrink:0;padding:8px;border:none;background:none;color:#71767b;font-size:1.1rem;cursor:pointer;line-height:1;">✕</button>
        `;
        document.body.appendChild(bar);

        document.getElementById('pwaInstallBtn').onclick = function () {
            if (_deferredPrompt) {
                _deferredPrompt.prompt();
                _deferredPrompt.userChoice.then(function (result) {
                    if (result.outcome === 'accepted') {
                        bar.remove();
                        localStorage.setItem(STORAGE_KEY, '1');
                    }
                    _deferredPrompt = null;
                });
            }
        };
        document.getElementById('pwaInstallDismiss').onclick = function () {
            bar.remove();
            localStorage.setItem(STORAGE_KEY, '1');
        };
    }

    function showIOSBanner() {
        if (document.getElementById('pwaIOSBanner')) return;
        const bar = document.createElement('div');
        bar.id = 'pwaIOSBanner';
        bar.style.cssText = [
            'position:fixed', 'bottom:0', 'left:0', 'width:100%',
            'background:#16202a', 'border-top:1px solid rgba(108,99,255,0.3)',
            'padding:16px 20px',
            'z-index:9990', 'box-shadow:0 -4px 20px rgba(0,0,0,0.4)',
            'animation:pwaSlideUp 0.3s ease'
        ].join(';');
        bar.innerHTML = `
            <style>@keyframes pwaSlideUp{from{transform:translateY(100%)}to{transform:translateY(0)}}</style>
            <div style="display:flex;align-items:flex-start;gap:12px;">
                <span style="font-size:1.4rem;flex-shrink:0;">📲</span>
                <div style="flex:1;min-width:0;">
                    <div style="font-size:0.9rem;font-weight:700;color:#e7e9ea;margin-bottom:6px;">Add to Home Screen</div>
                    <div style="font-size:0.82rem;color:#71767b;line-height:1.55;">
                        Tap <strong style="color:#e7e9ea;">Share</strong> <span style="font-size:0.9rem;">⬆️</span> then
                        <strong style="color:#e7e9ea;">"Add to Home Screen"</strong> for faster access.
                    </div>
                </div>
                <button id="pwaIOSDismiss" style="padding:6px 8px;border:none;background:none;color:#71767b;font-size:1.1rem;cursor:pointer;line-height:1;flex-shrink:0;">✕</button>
            </div>
        `;
        document.body.appendChild(bar);
        document.getElementById('pwaIOSDismiss').onclick = function () {
            bar.remove();
            localStorage.setItem(STORAGE_KEY, '1');
        };
    }

    // ── Handle post-install ──
    window.addEventListener('appinstalled', function () {
        const bar = document.getElementById('pwaInstallBar');
        if (bar) bar.remove();
        localStorage.setItem(STORAGE_KEY, '1');
    });
})();
