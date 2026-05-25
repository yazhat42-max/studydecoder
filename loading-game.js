/* loading-game.js — a quick syllabus quiz to play WHILE a big thing generates
 * (full exam, quick paper, worksheet). Reusable across tools.
 *
 *   SDLoadingGame.prefetch(subject)        // call when the tool opens (preload)
 *   var g = SDLoadingGame.start(hostEl, { subject, label })  // show during gen
 *   g.stop()                               // call when generation finishes
 *
 * Uses /api/loading-quiz (quota-free), caches per subject in sessionStorage so
 * repeated waits don't re-generate. Never throws; degrades to a tidy spinner. */
(function () {
  if (window.SDLoadingGame) return;
  var API = (location.hostname === 'localhost' || location.hostname === '127.0.0.1') ? 'http://localhost:3001' : '';
  var mem = {}; // subject -> questions[]
  var pending = {}; // subject -> promise

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]; }); }

  function injectCss() {
    if (document.getElementById('sdLgCss')) return;
    var s = document.createElement('style'); s.id = 'sdLgCss';
    s.textContent =
      '.sd-lg{max-width:520px;margin:0 auto;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;}' +
      '.sd-lg-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px;}' +
      '.sd-lg-head .t{display:flex;align-items:center;gap:10px;font-weight:700;font-size:15px;color:var(--text,#fff);}' +
      '.sd-lg-ring{width:18px;height:18px;border:2px solid rgba(108,99,255,0.25);border-top-color:#6C63FF;border-radius:50%;animation:sdLgSpin .8s linear infinite;flex:none;}' +
      '@keyframes sdLgSpin{to{transform:rotate(360deg)}}' +
      '.sd-lg-score{font-size:13px;font-weight:700;color:#a78bfa;}' +
      '.sd-lg-sub{font-size:12.5px;color:rgba(160,160,180,0.9);margin-bottom:14px;}' +
      '.sd-lg-card{background:var(--tool-surface,#14121f);border:1px solid rgba(127,127,140,0.22);border-radius:16px;padding:18px;}' +
      '.sd-lg-q{font-size:15.5px;font-weight:600;line-height:1.45;margin-bottom:14px;color:var(--text,#fff);}' +
      '.sd-lg-opt{display:block;width:100%;text-align:left;padding:12px 14px;border-radius:11px;background:rgba(127,127,140,0.10);border:1px solid rgba(127,127,140,0.22);color:var(--text,#e8e8ef);font-size:14px;margin-bottom:9px;cursor:pointer;font-family:inherit;transition:border-color .15s;}' +
      '.sd-lg-opt:hover:not(:disabled){border-color:rgba(108,99,255,0.5);}' +
      '.sd-lg-opt.correct{background:rgba(34,197,94,0.18);border-color:#22c55e;}' +
      '.sd-lg-opt.wrong{background:rgba(239,68,68,0.16);border-color:#ef4444;}' +
      '.sd-lg-ex{font-size:13px;line-height:1.5;color:rgba(160,160,180,0.95);background:rgba(108,99,255,0.10);border:1px solid rgba(108,99,255,0.22);border-radius:10px;padding:11px 13px;margin-top:6px;}' +
      '.sd-lg-wait{color:rgba(160,160,180,0.9);font-size:14px;text-align:center;padding:24px 8px;}';
    document.head.appendChild(s);
  }

  function fetchQuiz(subject) {
    var key = 'sd_lq_' + subject;
    try { var ss = sessionStorage.getItem(key); if (ss) { var arr = JSON.parse(ss); if (Array.isArray(arr) && arr.length) { mem[subject] = arr; return Promise.resolve(arr); } } } catch (e) {}
    if (mem[subject]) return Promise.resolve(mem[subject]);
    if (pending[subject]) return pending[subject];
    pending[subject] = fetch(API + '/api/loading-quiz', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ subject: subject }) })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        var qs = (d && Array.isArray(d.questions)) ? d.questions : [];
        mem[subject] = qs;
        try { if (qs.length) sessionStorage.setItem(key, JSON.stringify(qs)); } catch (e) {}
        return qs;
      })
      .catch(function () { mem[subject] = []; return []; })
      .finally ? null : null;
    // .finally not chained above to keep older browsers happy; clear pending on settle:
    pending[subject].then(function () { pending[subject] = null; }, function () { pending[subject] = null; });
    return pending[subject];
  }

  function prefetch(subject) { if (subject) { try { fetchQuiz(subject); } catch (e) {} } }

  function start(hostEl, opts) {
    opts = opts || {};
    injectCss();
    var ctrl = { _stopped: false, score: 0 };
    if (!hostEl) return ctrl;
    var label = opts.label || 'your content';
    hostEl.innerHTML =
      '<div class="sd-lg">' +
      '<div class="sd-lg-head"><span class="t"><span class="sd-lg-ring"></span> Building ' + esc(label) + '…</span><span class="sd-lg-score" id="sdLgScore"></span></div>' +
      '<div class="sd-lg-sub">While you wait — a few quick questions to warm up. 🔥</div>' +
      '<div class="sd-lg-card" id="sdLgBody"><div class="sd-lg-wait">Loading a quick warm-up…</div></div></div>';
    var body = hostEl.querySelector('#sdLgBody');
    var scoreEl = hostEl.querySelector('#sdLgScore');
    var qs = [], idx = 0;

    fetchQuiz(opts.subject).then(function (list) {
      if (ctrl._stopped) return;
      qs = (list || []).slice();
      if (!qs.length) { body.innerHTML = '<div class="sd-lg-wait">Hang tight — building ' + esc(label) + '. This can take a moment for long papers.</div>'; return; }
      show();
    });

    function show() {
      if (ctrl._stopped) return;
      if (idx >= qs.length) idx = 0; // loop until generation finishes
      var q = qs[idx];
      var h = '<div class="sd-lg-q">' + esc(q.question) + '</div>';
      q.options.forEach(function (o, i) { h += '<button class="sd-lg-opt" data-i="' + i + '">' + esc(o) + '</button>'; });
      body.innerHTML = h;
      Array.prototype.forEach.call(body.querySelectorAll('.sd-lg-opt'), function (b) {
        b.addEventListener('click', function () {
          if (ctrl._stopped) return;
          var i = +b.getAttribute('data-i'), correct = i === q.answer;
          Array.prototype.forEach.call(body.querySelectorAll('.sd-lg-opt'), function (x, j) { x.disabled = true; if (j === q.answer) x.classList.add('correct'); });
          if (!correct) b.classList.add('wrong'); else ctrl.score++;
          if (scoreEl) scoreEl.textContent = ctrl.score + ' correct';
          var ex = document.createElement('div'); ex.className = 'sd-lg-ex'; ex.textContent = (correct ? '✅ ' : '❌ ') + (q.explanation || ''); body.appendChild(ex);
          idx++;
          ctrl._timer = setTimeout(show, 1300);
        });
      });
    }

    ctrl.stop = function () { ctrl._stopped = true; if (ctrl._timer) clearTimeout(ctrl._timer); };
    return ctrl;
  }

  window.SDLoadingGame = { prefetch: prefetch, start: start };
})();
