/* theme.js — light/dark theme state, persistence, and toggle API.
 * Applies data-theme to <html> immediately, persists to localStorage, and
 * exposes window.SDTheme. UI buttons (sidebar / inline) call SDTheme.toggle()
 * and carry a [data-sd-theme-toggle] attribute so their label/icon auto-update.
 * Pair with theme.css. For zero flash, also drop the tiny inline <head> snippet
 * (see dashboard.html) before stylesheets load. */
(function () {
  if (window.SDTheme) return;
  var KEY = 'sd_theme';

  function preferred() {
    try { var t = localStorage.getItem(KEY); if (t === 'light' || t === 'dark') return t; } catch (e) {}
    try { if (window.matchMedia && matchMedia('(prefers-color-scheme: light)').matches) return 'light'; } catch (e) {}
    return 'dark';
  }
  function apply(t) { document.documentElement.setAttribute('data-theme', t === 'light' ? 'light' : 'dark'); }

  var current = preferred();
  apply(current);

  function updateButtons() {
    // Reveal the app-shell sidebar toggle once theme support is present,
    // regardless of whether theme.js loaded before or after app-shell.js.
    var st = document.getElementById('sdThemeToggle');
    if (st) st.removeAttribute('hidden');
    var btns = document.querySelectorAll('[data-sd-theme-toggle]');
    var icon = current === 'light' ? '🌙' : '☀️';
    var label = current === 'light' ? 'Dark mode' : 'Light mode';
    for (var i = 0; i < btns.length; i++) {
      var b = btns[i];
      var ic = b.querySelector('.tt-ic');
      var tx = b.querySelector('.tt-label');
      if (ic) ic.textContent = icon; else if (!tx) b.textContent = icon;
      if (tx) tx.textContent = label;
      b.setAttribute('aria-label', label);
      b.setAttribute('aria-pressed', current === 'light' ? 'true' : 'false');
    }
  }
  function set(t) {
    current = (t === 'light') ? 'light' : 'dark';
    apply(current);
    try { localStorage.setItem(KEY, current); } catch (e) {}
    try { document.dispatchEvent(new CustomEvent('sd-theme-change', { detail: current })); } catch (e) {}
    updateButtons();
  }
  function toggle() { set(current === 'light' ? 'dark' : 'light'); }

  window.SDTheme = { get: function () { return current; }, set: set, toggle: toggle, refresh: updateButtons };

  // Delegated: any element carrying [data-sd-theme-toggle] toggles the theme.
  document.addEventListener('click', function (e) {
    var t = e.target.closest ? e.target.closest('[data-sd-theme-toggle]') : null;
    if (t) { e.preventDefault(); toggle(); }
  });

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', updateButtons);
  else updateButtons();
})();
