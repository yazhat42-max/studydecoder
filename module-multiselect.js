/**
 * Study Decoder — shared multi-module selector.
 * A dropdown of checkboxes letting a student pick ONE, SEVERAL, or ALL modules
 * of a subject. Empty selection means "all modules".
 *
 *   const ms = SDModuleSelect.create(containerEl, { onChange: list => {...} });
 *   ms.setModules(['Module 1: ...', 'Module 2: ...']);
 *   ms.getSelected();   // [] = all modules, else array of module names
 *   ms.setSelected(['Module 1: ...']);
 */
(function () {
    if (window.SDModuleSelect) return;

    function esc(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    }

    function injectStyles() {
        if (document.getElementById('sd-ms-styles')) return;
        const s = document.createElement('style');
        s.id = 'sd-ms-styles';
        s.textContent = `
.sd-ms { position: relative; width: 100%; font-family: inherit; }
.sd-ms-btn {
  width: 100%; display: flex; align-items: center; justify-content: space-between; gap: 10px;
  background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.14); border-radius: 10px;
  color: inherit; padding: 12px 14px; font-size: 14px; font-family: inherit; cursor: pointer; text-align: left;
  transition: border-color .15s, background .15s;
}
.sd-ms-btn:hover { border-color: rgba(108,99,255,0.5); }
.sd-ms-btn.open { border-color: #6C63FF; box-shadow: 0 0 0 3px rgba(108,99,255,0.18); }
.sd-ms-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sd-ms-caret { opacity: .6; font-size: 11px; flex-shrink: 0; }
.sd-ms-panel {
  position: absolute; top: calc(100% + 6px); left: 0; right: 0; z-index: 200;
  background: #15131f; border: 1px solid rgba(255,255,255,0.14); border-radius: 12px;
  box-shadow: 0 18px 48px rgba(0,0,0,0.5); max-height: 320px; overflow-y: auto; padding: 6px;
}
.sd-ms-opt {
  display: flex; align-items: center; gap: 10px; padding: 10px 12px; border-radius: 8px;
  font-size: 14px; cursor: pointer; color: rgba(255,255,255,0.86); user-select: none;
}
.sd-ms-opt:hover { background: rgba(255,255,255,0.05); }
.sd-ms-opt input { width: 16px; height: 16px; accent-color: #6C63FF; flex-shrink: 0; cursor: pointer; }
.sd-ms-all { border-bottom: 1px solid rgba(255,255,255,0.08); margin-bottom: 4px; font-weight: 700; color: #fff; }
.sd-ms-empty { padding: 12px; font-size: 13px; color: rgba(255,255,255,0.5); }
`;
        document.head.appendChild(s);
    }

    function create(container, opts) {
        opts = opts || {};
        injectStyles();
        let modules = [];
        const selected = new Set();
        let allMode = true;

        const root = document.createElement('div'); root.className = 'sd-ms';
        const btn = document.createElement('button'); btn.type = 'button'; btn.className = 'sd-ms-btn';
        const panel = document.createElement('div'); panel.className = 'sd-ms-panel'; panel.style.display = 'none';
        root.appendChild(btn); root.appendChild(panel);
        container.appendChild(root);

        function label() {
            if (allMode || selected.size === 0) return 'All modules';
            if (selected.size === 1) return [...selected][0];
            return selected.size + ' modules selected';
        }
        function renderBtn() {
            btn.innerHTML = `<span class="sd-ms-label">${esc(label())}</span><span class="sd-ms-caret">▾</span>`;
        }
        function renderPanel() {
            if (!modules.length) { panel.innerHTML = '<div class="sd-ms-empty">Pick a subject first.</div>'; return; }
            let html = `<label class="sd-ms-opt sd-ms-all"><input type="checkbox" ${allMode ? 'checked' : ''} data-all> <span>All modules</span></label>`;
            html += modules.map((m, i) => `<label class="sd-ms-opt"><input type="checkbox" data-i="${i}" ${(!allMode && selected.has(m)) ? 'checked' : ''}> <span>${esc(m)}</span></label>`).join('');
            panel.innerHTML = html;
            const allCb = panel.querySelector('[data-all]');
            if (allCb) allCb.addEventListener('change', e => {
                if (e.target.checked) { allMode = true; selected.clear(); } else { allMode = false; }
                renderPanel(); renderBtn(); fire();
            });
            panel.querySelectorAll('[data-i]').forEach(cb => cb.addEventListener('change', () => {
                const m = modules[+cb.dataset.i];
                if (cb.checked) { allMode = false; selected.add(m); }
                else { selected.delete(m); if (selected.size === 0) allMode = true; }
                renderPanel(); renderBtn(); fire();
            }));
        }
        function fire() { if (opts.onChange) opts.onChange(getSelected()); }
        function getSelected() { return allMode ? [] : [...selected]; }
        function setSelected(list) {
            selected.clear();
            (list || []).forEach(m => selected.add(m));
            allMode = selected.size === 0;
            renderBtn(); renderPanel();
        }
        function setModules(list) {
            modules = Array.isArray(list) ? list.slice() : [];
            selected.clear(); allMode = true;
            renderBtn(); renderPanel();
        }

        btn.addEventListener('click', e => {
            e.stopPropagation();
            const open = panel.style.display === 'none';
            panel.style.display = open ? 'block' : 'none';
            btn.classList.toggle('open', open);
        });
        document.addEventListener('click', e => {
            if (!root.contains(e.target)) { panel.style.display = 'none'; btn.classList.remove('open'); }
        });

        renderBtn(); renderPanel();
        return { setModules, getSelected, setSelected, el: root };
    }

    window.SDModuleSelect = { create };
})();
