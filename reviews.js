/* reviews.js — the "Leave a review" prompt, as a self-contained module so it can
 * live on the dashboard (logged-in users land there now, not index.html). Injects
 * its own toast + modal + styles, reuses the existing endpoints
 * (/api/reviews/prompt-eligible, /api/reviews/dismiss, /api/reviews), and themes
 * via the --tool-* tokens (light/dark aware). Safe to include once per page. */
(function () {
  if (window.__sdReviewsInstalled) return;
  window.__sdReviewsInstalled = true;

  var SURFACE = 'var(--tool-surface, #14121f)';
  var INK = 'var(--tool-ink, #fff)';
  var MUTED = 'rgba(var(--tool-ink-rgb, 255,255,255), 0.6)';
  var BORDER = 'rgba(var(--tool-ink-rgb, 255,255,255), 0.14)';

  function injectStyles() {
    if (document.getElementById('sdReviewStyles')) return;
    var s = document.createElement('style');
    s.id = 'sdReviewStyles';
    s.textContent =
      '#sdReviewToast{position:fixed;bottom:24px;right:24px;z-index:9000;background:' + SURFACE + ';border:1px solid rgba(108,99,255,0.35);border-radius:16px;padding:16px 18px;max-width:300px;box-shadow:0 8px 32px rgba(0,0,0,0.4);transform:translateY(120px);opacity:0;transition:transform .4s cubic-bezier(0.34,1.56,0.64,1),opacity .4s ease;pointer-events:none;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;}' +
      '#sdReviewToast.show{transform:translateY(0);opacity:1;pointer-events:auto;}' +
      '#sdReviewToast .tdismiss{position:absolute;top:8px;right:10px;background:none;border:none;color:' + MUTED + ';cursor:pointer;font-size:1rem;line-height:1;}' +
      '#sdReviewOverlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.7);backdrop-filter:blur(6px);z-index:10000;align-items:center;justify-content:center;}' +
      '#sdReviewOverlay .box{background:' + SURFACE + ';border:1px solid ' + BORDER + ';border-radius:20px;padding:2rem;width:90%;max-width:420px;position:relative;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:' + INK + ';}' +
      '#sdReviewOverlay .rclose{position:absolute;top:14px;right:16px;background:none;border:none;color:' + MUTED + ';cursor:pointer;font-size:1.2rem;}' +
      '#sdReviewOverlay h3{font-size:1.1rem;font-weight:700;color:' + INK + ';margin:0 0 .3rem;}' +
      '#sdReviewOverlay p.sub{font-size:.82rem;color:' + MUTED + ';margin:0 0 1.4rem;}' +
      '#sdStarRow{display:flex;gap:10px;justify-content:center;font-size:2rem;margin-bottom:1.2rem;cursor:pointer;}' +
      '#sdStarRow .star{transition:transform .15s;color:rgba(var(--tool-ink-rgb,255,255,255),0.25);user-select:none;}' +
      '#sdStarRow .star.lit{color:#f59e0b;}#sdStarRow .star:hover{transform:scale(1.2);}' +
      '#sdReviewOverlay textarea,#sdReviewOverlay input[type=text]{width:100%;background:rgba(var(--tool-ink-rgb,255,255,255),0.05);border:1px solid ' + BORDER + ';border-radius:10px;color:' + INK + ';padding:10px 12px;font-size:.9rem;font-family:inherit;outline:none;margin-bottom:.7rem;box-sizing:border-box;}' +
      '#sdReviewOverlay textarea{resize:none;min-height:80px;}' +
      '#sdReviewOverlay label.consent{display:flex;align-items:flex-start;gap:8px;font-size:.8rem;color:' + MUTED + ';margin-bottom:1.2rem;cursor:pointer;}' +
      '#sdReviewBtn{display:block;width:100%;padding:11px;background:linear-gradient(135deg,#6C63FF,#8b5cf6);color:#fff;border:none;border-radius:12px;font-size:.95rem;font-weight:700;cursor:pointer;font-family:inherit;}' +
      '#sdReviewErr{display:none;color:#ef4444;font-size:.82rem;margin-bottom:.8rem;}';
    document.head.appendChild(s);
  }

  function injectDom() {
    if (document.getElementById('sdReviewToast')) return;
    var toast = document.createElement('div');
    toast.id = 'sdReviewToast';
    toast.setAttribute('role', 'dialog');
    toast.setAttribute('aria-label', 'Leave a review');
    toast.innerHTML =
      '<button class="tdismiss" aria-label="Dismiss">✕</button>' +
      '<div style="font-size:.9rem;font-weight:700;color:' + INK + ';margin-bottom:6px;">⭐ Enjoying Study Decoder?</div>' +
      '<div style="font-size:.82rem;color:' + MUTED + ';margin-bottom:12px;line-height:1.45;">Takes 30 seconds — helps other students find us.</div>' +
      '<button class="open" style="display:block;width:100%;padding:9px 0;background:#6C63FF;color:#fff;border:none;border-radius:10px;font-size:.88rem;font-weight:700;cursor:pointer;font-family:inherit;">Leave a quick review →</button>';

    var overlay = document.createElement('div');
    overlay.id = 'sdReviewOverlay';
    overlay.innerHTML =
      '<div class="box">' +
      '<button class="rclose" aria-label="Close">✕</button>' +
      '<h3>Share your experience</h3>' +
      '<p class="sub">100% anonymous by default — your name and email are optional.</p>' +
      '<div id="sdStarRow" role="group" aria-label="Star rating">' +
      '<span class="star" data-val="1">☆</span><span class="star" data-val="2">☆</span><span class="star" data-val="3">☆</span><span class="star" data-val="4">☆</span><span class="star" data-val="5">☆</span></div>' +
      '<textarea id="sdReviewText" placeholder="What helped most? (optional)" maxlength="500"></textarea>' +
      '<input id="sdReviewName" type="text" placeholder="First name (optional)" maxlength="40">' +
      '<label class="consent"><input type="checkbox" id="sdReviewConsent" style="margin-top:2px;accent-color:#6C63FF;"> I consent to Study Decoder displaying my first name alongside this review.</label>' +
      '<p id="sdReviewErr"></p>' +
      '<button id="sdReviewBtn">Submit Review</button>' +
      '</div>';

    document.body.appendChild(toast);
    document.body.appendChild(overlay);
    wire(toast, overlay);
  }

  var rating = 0;
  function highlight(n) {
    var stars = document.querySelectorAll('#sdStarRow .star');
    for (var i = 0; i < stars.length; i++) stars[i].classList.toggle('lit', (+stars[i].dataset.val) <= n);
  }
  function showToast() { var t = document.getElementById('sdReviewToast'); if (t) t.classList.add('show'); }
  function hideToast() { var t = document.getElementById('sdReviewToast'); if (t) t.classList.remove('show'); }
  function openModal() { hideToast(); rating = 0; highlight(0); var o = document.getElementById('sdReviewOverlay'); o.querySelector('#sdReviewText').value = ''; o.querySelector('#sdReviewName').value = ''; o.querySelector('#sdReviewConsent').checked = false; o.querySelector('#sdReviewErr').style.display = 'none'; o.style.display = 'flex'; }
  function closeModal() { document.getElementById('sdReviewOverlay').style.display = 'none'; }

  function wire(toast, overlay) {
    toast.querySelector('.tdismiss').addEventListener('click', function () {
      hideToast();
      try { fetch('/api/reviews/dismiss', { method: 'POST', credentials: 'include' }); } catch (e) {}
    });
    toast.querySelector('.open').addEventListener('click', openModal);
    overlay.querySelector('.rclose').addEventListener('click', closeModal);
    overlay.addEventListener('click', function (e) { if (e.target === overlay) closeModal(); });
    var stars = overlay.querySelectorAll('#sdStarRow .star');
    for (var i = 0; i < stars.length; i++) {
      (function (star) {
        star.addEventListener('mouseover', function () { highlight(+star.dataset.val); });
        star.addEventListener('mouseout', function () { highlight(rating); });
        star.addEventListener('click', function () { rating = +star.dataset.val; highlight(rating); });
      })(stars[i]);
    }
    overlay.querySelector('#sdReviewBtn').addEventListener('click', submit);
  }

  function submit() {
    var err = document.getElementById('sdReviewErr');
    err.style.display = 'none';
    if (!rating) { err.textContent = 'Please select a star rating.'; err.style.display = 'block'; return; }
    var btn = document.getElementById('sdReviewBtn');
    btn.disabled = true; btn.textContent = 'Submitting…';
    fetch('/api/reviews', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include',
      body: JSON.stringify({
        rating: rating,
        text: document.getElementById('sdReviewText').value.trim(),
        displayName: document.getElementById('sdReviewName').value.trim(),
        emailConsent: document.getElementById('sdReviewConsent').checked
      })
    }).then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
      .then(function (res) {
        if (!res.ok) { err.textContent = res.d.error || 'Submission failed. Please try again.'; err.style.display = 'block'; btn.disabled = false; btn.textContent = 'Submit Review'; return; }
        closeModal();
        var t = document.getElementById('sdReviewToast');
        if (t) { t.innerHTML = '<div style="font-size:.9rem;font-weight:700;color:' + INK + ';">✅ Thanks for your review!</div><div style="font-size:.82rem;color:' + MUTED + ';margin-top:4px;">It’ll appear once approved.</div>'; t.classList.add('show'); setTimeout(function () { t.classList.remove('show'); }, 4000); }
      }).catch(function () { err.textContent = 'Network error. Please try again.'; err.style.display = 'block'; btn.disabled = false; btn.textContent = 'Submit Review'; });
  }

  function maybeShow() {
    fetch('/api/reviews/prompt-eligible', { credentials: 'include' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) { if (d && d.eligible) setTimeout(showToast, 1200); })
      .catch(function () {});
  }

  function start() { injectStyles(); injectDom(); maybeShow(); }
  if (document.body) start();
  else document.addEventListener('DOMContentLoaded', start);
})();
