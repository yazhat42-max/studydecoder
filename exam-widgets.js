/* exam-widgets.js — vanilla JS exam input widgets for StudyDecoder
 * Widgets: calculator (FAB), drawing canvas, table editor, graph plotter,
 * code editor, sql editor (with schema panel), spreadsheet (formula grid),
 * diagram builder (DFD / class-diagram / flowchart — node/edge graph).
 *
 * Public API:
 *   ExamWidgets.render(inputType, container, qNumber, options) → renders widget
 *   ExamWidgets.getValue(inputType, qNumber) → returns serialised value (string for AI marker)
 *   ExamWidgets.setValue(inputType, qNumber, value) → restore from saved
 *   ExamWidgets.mountCalculator()  → adds FAB + popup to the page (call once)
 *   ExamWidgets.SUPPORTED → array of inputType strings
 */
(function () {
    'use strict';

    const SUPPORTED = ['draw', 'graph', 'table', 'spreadsheet', 'code', 'sql', 'diagram'];

    // -- per-question state (so we can read out values on submit) ----------
    const state = {}; // { [qNumber]: { type, getValue, setValue } }

    function register(qNumber, type, getValue, setValue) {
        state[qNumber] = { type, getValue, setValue };
    }
    function getValue(qNumber) {
        const s = state[qNumber];
        if (!s) return null;
        try { return s.getValue(); } catch (e) { console.warn('widget getValue error', e); return null; }
    }
    function setValue(qNumber, value) {
        const s = state[qNumber];
        if (!s || !s.setValue || value == null) return;
        try { s.setValue(value); } catch (e) { console.warn('widget setValue error', e); }
    }

    // -- styles --------------------------------------------------------------
    function injectStyles() {
        if (document.getElementById('exam-widgets-styles')) return;
        const css = `
        .ew-wrap { margin: 14px 0 4px; border:1px solid rgba(79,140,255,0.25); border-radius:12px; background:rgba(79,140,255,0.04); padding:10px 12px; }
        .ew-toolbar { display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-bottom:8px; }
        .ew-btn { background:rgba(79,140,255,0.15); border:1px solid rgba(79,140,255,0.3); color:#cfd8e3; padding:5px 10px; border-radius:6px; font-size:12px; cursor:pointer; font-family:inherit; }
        .ew-btn:hover { background:rgba(79,140,255,0.25); }
        .ew-btn.active { background:#4f8cff; color:#fff; border-color:#4f8cff; }
        .ew-btn.danger { background:rgba(239,68,68,0.15); border-color:rgba(239,68,68,0.35); color:#f99; }
        .ew-label { font-size:11px; color:#8899a6; text-transform:uppercase; letter-spacing:0.5px; }
        /* Calculator */
        .ew-calc-fab { position:fixed; bottom:18px; right:18px; width:54px; height:54px; border-radius:50%; background:#4f8cff; color:#fff; border:none; font-size:22px; cursor:pointer; box-shadow:0 6px 20px rgba(79,140,255,0.4); z-index:9998; transition:transform 0.15s; }
        .ew-calc-fab:hover { transform:scale(1.06); }
        .ew-calc-panel { position:fixed; bottom:84px; right:18px; width:280px; background:#15191e; border:1px solid #2f3336; border-radius:14px; padding:12px; box-shadow:0 12px 40px rgba(0,0,0,0.5); z-index:9999; display:none; }
        .ew-calc-display { background:#0a0d11; color:#e7e9ea; padding:10px 12px; border-radius:8px; font-family:'JetBrains Mono', monospace; font-size:18px; text-align:right; min-height:50px; word-break:break-all; margin-bottom:8px; border:1px solid #2f3336; }
        .ew-calc-grid { display:grid; grid-template-columns:repeat(5, 1fr); gap:5px; }
        .ew-calc-key { background:#1f242b; color:#e7e9ea; border:1px solid #2f3336; border-radius:7px; padding:9px 0; font-size:13px; cursor:pointer; font-family:inherit; }
        .ew-calc-key:hover { background:#2a2f37; }
        .ew-calc-key.op { background:rgba(79,140,255,0.18); color:#4f8cff; }
        .ew-calc-key.eq { background:#4f8cff; color:#fff; grid-column:span 2; }
        .ew-calc-key.fn { background:rgba(168, 85, 247, 0.15); color:#c084fc; font-size:11px; }
        .ew-calc-key.clr { background:rgba(239,68,68,0.15); color:#ef4444; }
        /* Drawing */
        .ew-canvas-wrap { background:#fff; border-radius:8px; overflow:hidden; }
        .ew-canvas { display:block; width:100%; height:auto; cursor:crosshair; touch-action:none; background:#fff; }
        /* Table */
        .ew-table { width:100%; border-collapse:collapse; background:rgba(0,0,0,0.2); border-radius:6px; overflow:hidden; font-size:13px; }
        .ew-table th, .ew-table td { border:1px solid #2f3336; padding:0; }
        .ew-table th { background:rgba(79,140,255,0.12); color:#cfd8e3; font-weight:600; padding:6px 8px; text-align:left; }
        .ew-table input { width:100%; background:transparent; border:none; padding:7px 8px; color:#e7e9ea; font-family:inherit; font-size:13px; outline:none; box-sizing:border-box; }
        .ew-table input:focus { background:rgba(79,140,255,0.08); }
        /* Graph */
        .ew-graph-wrap { background:#fff; border-radius:8px; overflow:hidden; position:relative; }
        .ew-graph-canvas { display:block; width:100%; height:auto; cursor:crosshair; }
        .ew-graph-info { font-size:11px; color:#8899a6; margin-top:6px; }
        /* Code editor */
        .ew-code-wrap { background:#0a0d11; border:1px solid #2f3336; border-radius:8px; overflow:hidden; }
        .ew-code-tabs { display:flex; gap:0; background:#0a0d11; border-bottom:1px solid #2f3336; padding:4px 8px 0; align-items:center; flex-wrap:wrap; }
        .ew-code-tab { padding:5px 10px; font-size:11px; color:#8899a6; }
        .ew-code-textarea { width:100%; background:#0a0d11; color:#e7e9ea; border:none; padding:12px; font-family:'JetBrains Mono', 'Consolas', monospace; font-size:13px; line-height:1.55; min-height:180px; outline:none; resize:vertical; box-sizing:border-box; tab-size:4; -moz-tab-size:4; white-space:pre; }
        .ew-code-textarea::placeholder { color:#4a5460; }
        /* SQL schema */
        .ew-sql-schema { background:rgba(168, 85, 247, 0.06); border:1px solid rgba(168, 85, 247, 0.25); border-radius:8px; padding:10px 12px; margin-bottom:8px; font-size:12px; color:#cfd8e3; }
        .ew-sql-schema h4 { margin:0 0 6px; font-size:11px; text-transform:uppercase; letter-spacing:0.5px; color:#c084fc; font-weight:600; }
        .ew-sql-table { font-family:'JetBrains Mono', monospace; margin-bottom:4px; }
        .ew-sql-table strong { color:#e7e9ea; }
        /* Spreadsheet */
        .ew-sheet { width:100%; border-collapse:collapse; font-size:12px; background:#fff; color:#1a1a1a; border-radius:6px; overflow:hidden; }
        .ew-sheet th, .ew-sheet td { border:1px solid #d0d7de; padding:0; min-width:60px; }
        .ew-sheet th { background:#f5f7fa; padding:5px; font-weight:600; text-align:center; color:#444; font-size:11px; }
        .ew-sheet input { width:100%; background:transparent; border:none; padding:5px 7px; font-family:inherit; font-size:12px; outline:none; box-sizing:border-box; }
        .ew-sheet input:focus { background:#e7f0ff; }
        /* Diagram */
        .ew-diagram-wrap { background:#fafbfc; border-radius:8px; min-height:340px; position:relative; overflow:auto; border:1px dashed #c0c8d0; }
        .ew-diagram-canvas { width:100%; height:340px; position:relative; }
        .ew-diagram-node { position:absolute; min-width:90px; min-height:42px; background:#fff; border:2px solid #4f8cff; border-radius:6px; padding:6px 10px; font-size:12px; cursor:move; user-select:none; box-shadow:0 2px 6px rgba(0,0,0,0.08); display:flex; align-items:center; justify-content:center; text-align:center; color:#1a1a1a; }
        .ew-diagram-node.shape-circle { border-radius:50%; min-width:80px; min-height:80px; }
        .ew-diagram-node.shape-diamond { transform:rotate(45deg); width:80px; height:80px; min-width:0; min-height:0; padding:0; }
        .ew-diagram-node.shape-diamond span { transform:rotate(-45deg); display:block; }
        .ew-diagram-node.shape-store { border-left:none; border-right:none; }
        .ew-diagram-node.shape-class { flex-direction:column; align-items:stretch; padding:0; min-width:130px; }
        .ew-diagram-node.shape-class .cls-name { background:#4f8cff; color:#fff; padding:5px 8px; font-weight:600; text-align:center; }
        .ew-diagram-node.shape-class .cls-body { padding:5px 8px; font-family:monospace; font-size:11px; white-space:pre-wrap; min-height:30px; }
        .ew-diagram-node.selected { box-shadow:0 0 0 3px rgba(79,140,255,0.4); }
        .ew-diagram-svg { position:absolute; top:0; left:0; width:100%; height:100%; pointer-events:none; }
        .ew-diagram-svg line { stroke:#4f8cff; stroke-width:2; }
        .ew-diagram-svg polygon { fill:#4f8cff; }
        .ew-diagram-hint { position:absolute; bottom:8px; left:8px; right:8px; font-size:11px; color:#8899a6; background:rgba(0,0,0,0.04); padding:4px 8px; border-radius:4px; }
        `;
        const style = document.createElement('style');
        style.id = 'exam-widgets-styles';
        style.textContent = css;
        document.head.appendChild(style);
    }

    // ====================================================================
    //  CALCULATOR (FAB + popup)
    // ====================================================================
    function mountCalculator() {
        injectStyles();
        if (document.getElementById('ew-calc-fab')) return;
        const fab = document.createElement('button');
        fab.id = 'ew-calc-fab';
        fab.className = 'ew-calc-fab';
        fab.title = 'Calculator';
        fab.innerHTML = '🧮';
        document.body.appendChild(fab);
        const panel = document.createElement('div');
        panel.id = 'ew-calc-panel';
        panel.className = 'ew-calc-panel';
        panel.innerHTML = `
            <div class="ew-calc-display" id="ew-calc-disp">0</div>
            <div class="ew-calc-grid">
                <button class="ew-calc-key fn" data-k="sin(">sin</button>
                <button class="ew-calc-key fn" data-k="cos(">cos</button>
                <button class="ew-calc-key fn" data-k="tan(">tan</button>
                <button class="ew-calc-key fn" data-k="ln(">ln</button>
                <button class="ew-calc-key fn" data-k="log(">log</button>
                <button class="ew-calc-key fn" data-k="sqrt(">√</button>
                <button class="ew-calc-key fn" data-k="^">x^y</button>
                <button class="ew-calc-key fn" data-k="pi">π</button>
                <button class="ew-calc-key fn" data-k="e">e</button>
                <button class="ew-calc-key clr" data-k="bs">⌫</button>
                <button class="ew-calc-key" data-k="7">7</button>
                <button class="ew-calc-key" data-k="8">8</button>
                <button class="ew-calc-key" data-k="9">9</button>
                <button class="ew-calc-key op" data-k="/">÷</button>
                <button class="ew-calc-key clr" data-k="ac">AC</button>
                <button class="ew-calc-key" data-k="4">4</button>
                <button class="ew-calc-key" data-k="5">5</button>
                <button class="ew-calc-key" data-k="6">6</button>
                <button class="ew-calc-key op" data-k="*">×</button>
                <button class="ew-calc-key op" data-k="(">(</button>
                <button class="ew-calc-key" data-k="1">1</button>
                <button class="ew-calc-key" data-k="2">2</button>
                <button class="ew-calc-key" data-k="3">3</button>
                <button class="ew-calc-key op" data-k="-">−</button>
                <button class="ew-calc-key op" data-k=")">)</button>
                <button class="ew-calc-key" data-k="0">0</button>
                <button class="ew-calc-key" data-k=".">.</button>
                <button class="ew-calc-key op" data-k="+">+</button>
                <button class="ew-calc-key eq" data-k="=">=</button>
            </div>`;
        document.body.appendChild(panel);

        let expr = '';
        const disp = panel.querySelector('#ew-calc-disp');
        function update() { disp.textContent = expr || '0'; }
        function evaluate() {
            try {
                let safe = expr
                    .replace(/π|pi/g, '(Math.PI)')
                    .replace(/(?<![a-z])e(?![a-z])/g, '(Math.E)')
                    .replace(/sin\(/g, 'Math.sin(')
                    .replace(/cos\(/g, 'Math.cos(')
                    .replace(/tan\(/g, 'Math.tan(')
                    .replace(/ln\(/g, 'Math.log(')
                    .replace(/log\(/g, 'Math.log10(')
                    .replace(/sqrt\(/g, 'Math.sqrt(')
                    .replace(/\^/g, '**');
                if (!/^[\d+\-*/().,\s\w]+$/.test(safe)) throw new Error('invalid');
                /* eslint-disable no-new-func */
                const result = Function('"use strict"; return (' + safe + ')')();
                if (typeof result === 'number' && isFinite(result)) {
                    expr = String(Math.round(result * 1e10) / 1e10);
                } else { expr = 'Error'; }
            } catch { expr = 'Error'; }
            update();
        }
        panel.addEventListener('click', e => {
            const btn = e.target.closest('.ew-calc-key');
            if (!btn) return;
            const k = btn.dataset.k;
            if (expr === 'Error') expr = '';
            if (k === 'ac') { expr = ''; }
            else if (k === 'bs') { expr = expr.slice(0, -1); }
            else if (k === '=') { evaluate(); return; }
            else { expr += k; }
            update();
        });
        fab.addEventListener('click', () => {
            panel.style.display = panel.style.display === 'none' || !panel.style.display ? 'block' : 'none';
        });
    }

    // ====================================================================
    //  DRAWING CANVAS
    // ====================================================================
    function renderDrawing(container, qNumber, opts) {
        injectStyles();
        opts = opts || {};
        const w = opts.width || 700, h = opts.height || 400;
        const wrap = document.createElement('div');
        wrap.className = 'ew-wrap';
        wrap.innerHTML = `
            <div class="ew-toolbar">
                <span class="ew-label">✏️ Drawing</span>
                <button type="button" class="ew-btn active" data-tool="pen">Pen</button>
                <button type="button" class="ew-btn" data-tool="erase">Eraser</button>
                <button type="button" class="ew-btn" data-tool="grid">Grid</button>
                <button type="button" class="ew-btn" data-tool="undo">Undo</button>
                <button type="button" class="ew-btn danger" data-tool="clear">Clear</button>
                <span style="flex:1;"></span>
                <input type="color" value="#1a1a1a" class="ew-color" style="width:32px; height:24px; border:none; background:transparent; cursor:pointer;">
            </div>
            <div class="ew-canvas-wrap"><canvas class="ew-canvas" width="${w}" height="${h}"></canvas></div>
            <div style="font-size:11px; color:#8899a6; margin-top:6px;">Use this canvas to draw your answer. The marker will inspect your drawing.</div>
        `;
        container.appendChild(wrap);
        const canvas = wrap.querySelector('canvas');
        const ctx = canvas.getContext('2d');
        ctx.lineCap = 'round'; ctx.lineJoin = 'round'; ctx.lineWidth = 2;
        let drawing = false, tool = 'pen', showGrid = false, color = '#1a1a1a';
        const history = []; // dataURL stack for undo (limited to 20)
        function snapshot() {
            history.push(canvas.toDataURL('image/png'));
            if (history.length > 20) history.shift();
        }
        function paintGrid() {
            if (!showGrid) return;
            ctx.save();
            ctx.strokeStyle = '#e0e6ed';
            ctx.lineWidth = 0.5;
            for (let x = 0; x < canvas.width; x += 25) {
                ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, canvas.height); ctx.stroke();
            }
            for (let y = 0; y < canvas.height; y += 25) {
                ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(canvas.width, y); ctx.stroke();
            }
            ctx.restore();
        }
        function clearCanvas() {
            ctx.fillStyle = '#fff';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            paintGrid();
        }
        clearCanvas();
        function pointerPos(e) {
            const r = canvas.getBoundingClientRect();
            const cx = (e.touches ? e.touches[0].clientX : e.clientX) - r.left;
            const cy = (e.touches ? e.touches[0].clientY : e.clientY) - r.top;
            return { x: cx * (canvas.width / r.width), y: cy * (canvas.height / r.height) };
        }
        function start(e) {
            e.preventDefault();
            drawing = true;
            snapshot();
            const p = pointerPos(e);
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.strokeStyle = tool === 'erase' ? '#fff' : color;
            ctx.lineWidth = tool === 'erase' ? 18 : 2;
        }
        function move(e) {
            if (!drawing) return;
            e.preventDefault();
            const p = pointerPos(e);
            ctx.lineTo(p.x, p.y);
            ctx.stroke();
        }
        function end() { drawing = false; }
        canvas.addEventListener('mousedown', start);
        canvas.addEventListener('mousemove', move);
        canvas.addEventListener('mouseup', end);
        canvas.addEventListener('mouseleave', end);
        canvas.addEventListener('touchstart', start, { passive: false });
        canvas.addEventListener('touchmove', move, { passive: false });
        canvas.addEventListener('touchend', end);
        wrap.querySelector('.ew-color').addEventListener('input', e => { color = e.target.value; });
        wrap.querySelectorAll('.ew-btn').forEach(b => b.addEventListener('click', () => {
            const t = b.dataset.tool;
            if (t === 'clear') { snapshot(); clearCanvas(); }
            else if (t === 'undo') {
                if (history.length === 0) return;
                const img = new Image();
                img.onload = () => { ctx.clearRect(0, 0, canvas.width, canvas.height); ctx.drawImage(img, 0, 0); };
                img.src = history.pop();
            } else if (t === 'grid') {
                showGrid = !showGrid; b.classList.toggle('active');
                clearCanvas();
            } else {
                tool = t;
                wrap.querySelectorAll('[data-tool="pen"], [data-tool="erase"]').forEach(x => x.classList.remove('active'));
                b.classList.add('active');
            }
        }));
        register(qNumber, 'draw',
            () => {
                // only return if user actually drew something — check for non-white pixel
                const data = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
                let drawn = false;
                for (let i = 0; i < data.length; i += 4) {
                    if (data[i] < 240 || data[i + 1] < 240 || data[i + 2] < 240) { drawn = true; break; }
                }
                return drawn ? canvas.toDataURL('image/png') : '';
            },
            (val) => {
                if (!val || typeof val !== 'string' || !val.startsWith('data:image')) return;
                const img = new Image();
                img.onload = () => { clearCanvas(); ctx.drawImage(img, 0, 0); };
                img.src = val;
            }
        );
    }

    // ====================================================================
    //  TABLE EDITOR
    // ====================================================================
    function renderTable(container, qNumber, opts) {
        injectStyles();
        opts = opts || {};
        const headers = (opts.headers && opts.headers.length) ? opts.headers : ['Column 1', 'Column 2', 'Column 3'];
        const initialRows = opts.rows || 3;
        const wrap = document.createElement('div');
        wrap.className = 'ew-wrap';
        wrap.innerHTML = `
            <div class="ew-toolbar">
                <span class="ew-label">📋 Table</span>
                <button type="button" class="ew-btn" data-act="addRow">+ Row</button>
                <button type="button" class="ew-btn" data-act="addCol">+ Column</button>
                <button type="button" class="ew-btn danger" data-act="delRow">− Row</button>
                <button type="button" class="ew-btn danger" data-act="delCol">− Column</button>
            </div>
            <table class="ew-table"><thead></thead><tbody></tbody></table>
        `;
        container.appendChild(wrap);
        const thead = wrap.querySelector('thead');
        const tbody = wrap.querySelector('tbody');
        let cols = headers.slice();
        const data = []; // 2D array of cell values
        for (let r = 0; r < initialRows; r++) data.push(new Array(cols.length).fill(''));
        function paint() {
            thead.innerHTML = '<tr>' + cols.map(h => `<th>${h}</th>`).join('') + '</tr>';
            tbody.innerHTML = data.map((row, ri) =>
                '<tr>' + row.map((cell, ci) => `<td><input type="text" data-r="${ri}" data-c="${ci}" value="${(cell || '').replace(/"/g, '&quot;')}"></td>`).join('') + '</tr>'
            ).join('');
            tbody.querySelectorAll('input').forEach(inp => {
                inp.addEventListener('input', () => {
                    data[+inp.dataset.r][+inp.dataset.c] = inp.value;
                });
            });
        }
        paint();
        wrap.querySelector('.ew-toolbar').addEventListener('click', e => {
            const btn = e.target.closest('.ew-btn'); if (!btn) return;
            const a = btn.dataset.act;
            if (a === 'addRow') data.push(new Array(cols.length).fill(''));
            else if (a === 'delRow') data.length > 1 && data.pop();
            else if (a === 'addCol') { cols.push('Column ' + (cols.length + 1)); data.forEach(r => r.push('')); }
            else if (a === 'delCol' && cols.length > 1) { cols.pop(); data.forEach(r => r.pop()); }
            paint();
        });
        register(qNumber, 'table',
            () => {
                if (data.every(row => row.every(c => !c || !String(c).trim()))) return '';
                const lines = [];
                lines.push('| ' + cols.join(' | ') + ' |');
                lines.push('|' + cols.map(() => '---').join('|') + '|');
                data.forEach(row => lines.push('| ' + row.map(c => c || '').join(' | ') + ' |'));
                return lines.join('\n');
            },
            (val) => {
                if (!val || typeof val !== 'string') return;
                const lines = val.split('\n').filter(l => l.trim().startsWith('|'));
                if (lines.length < 3) return;
                cols = lines[0].split('|').slice(1, -1).map(s => s.trim());
                data.length = 0;
                for (let i = 2; i < lines.length; i++) {
                    data.push(lines[i].split('|').slice(1, -1).map(s => s.trim()));
                }
                paint();
            }
        );
    }

    // ====================================================================
    //  GRAPH PLOTTER (snap-to-grid coordinate plane)
    // ====================================================================
    function renderGraph(container, qNumber, opts) {
        injectStyles();
        opts = opts || {};
        const w = 600, h = 400, gridSize = 30;
        const xMin = opts.xMin ?? -8, xMax = opts.xMax ?? 8, yMin = opts.yMin ?? -8, yMax = opts.yMax ?? 8;
        const wrap = document.createElement('div');
        wrap.className = 'ew-wrap';
        wrap.innerHTML = `
            <div class="ew-toolbar">
                <span class="ew-label">📈 Graph</span>
                <button type="button" class="ew-btn active" data-tool="point">Point</button>
                <button type="button" class="ew-btn" data-tool="line">Line</button>
                <button type="button" class="ew-btn" data-tool="curve">Curve (free)</button>
                <button type="button" class="ew-btn" data-tool="undo">Undo</button>
                <button type="button" class="ew-btn danger" data-tool="clear">Clear</button>
            </div>
            <div class="ew-graph-wrap"><canvas class="ew-graph-canvas" width="${w}" height="${h}"></canvas></div>
            <div class="ew-graph-info">Click to plot points; click two points to draw a line; "Curve" lets you free-draw a function.</div>
        `;
        container.appendChild(wrap);
        const canvas = wrap.querySelector('canvas');
        const ctx = canvas.getContext('2d');
        const items = []; // {type:'point'|'line'|'curve', ...}
        let tool = 'point';
        let lineStart = null;
        let drawingCurve = false, curvePts = [];

        function toCanvas(x, y) {
            const cx = ((x - xMin) / (xMax - xMin)) * w;
            const cy = h - ((y - yMin) / (yMax - yMin)) * h;
            return { cx, cy };
        }
        function toCoord(cx, cy) {
            const x = xMin + (cx / w) * (xMax - xMin);
            const y = yMin + ((h - cy) / h) * (yMax - yMin);
            return { x: Math.round(x * 2) / 2, y: Math.round(y * 2) / 2 };
        }
        function paint() {
            ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, w, h);
            // grid
            ctx.strokeStyle = '#e0e6ed'; ctx.lineWidth = 1;
            for (let x = xMin; x <= xMax; x++) {
                const { cx } = toCanvas(x, 0);
                ctx.beginPath(); ctx.moveTo(cx, 0); ctx.lineTo(cx, h); ctx.stroke();
            }
            for (let y = yMin; y <= yMax; y++) {
                const { cy } = toCanvas(0, y);
                ctx.beginPath(); ctx.moveTo(0, cy); ctx.lineTo(w, cy); ctx.stroke();
            }
            // axes
            ctx.strokeStyle = '#1a1a1a'; ctx.lineWidth = 1.5;
            const o = toCanvas(0, 0);
            ctx.beginPath(); ctx.moveTo(0, o.cy); ctx.lineTo(w, o.cy); ctx.stroke();
            ctx.beginPath(); ctx.moveTo(o.cx, 0); ctx.lineTo(o.cx, h); ctx.stroke();
            // tick labels
            ctx.fillStyle = '#444'; ctx.font = '10px sans-serif'; ctx.textAlign = 'center';
            for (let x = xMin; x <= xMax; x += 2) if (x !== 0) {
                const { cx } = toCanvas(x, 0);
                ctx.fillText(x, cx, o.cy + 12);
            }
            for (let y = yMin; y <= yMax; y += 2) if (y !== 0) {
                const { cy } = toCanvas(0, y);
                ctx.textAlign = 'right';
                ctx.fillText(y, o.cx - 4, cy + 3);
            }
            // items
            ctx.strokeStyle = '#4f8cff'; ctx.fillStyle = '#4f8cff'; ctx.lineWidth = 2;
            items.forEach(it => {
                if (it.type === 'point') {
                    const p = toCanvas(it.x, it.y);
                    ctx.beginPath(); ctx.arc(p.cx, p.cy, 5, 0, Math.PI * 2); ctx.fill();
                    ctx.fillStyle = '#1a1a1a'; ctx.font = '11px sans-serif'; ctx.textAlign = 'left';
                    ctx.fillText(`(${it.x}, ${it.y})`, p.cx + 8, p.cy - 6);
                    ctx.fillStyle = '#4f8cff';
                } else if (it.type === 'line') {
                    const a = toCanvas(it.x1, it.y1), b = toCanvas(it.x2, it.y2);
                    ctx.beginPath(); ctx.moveTo(a.cx, a.cy); ctx.lineTo(b.cx, b.cy); ctx.stroke();
                } else if (it.type === 'curve') {
                    if (it.points.length < 2) return;
                    ctx.beginPath();
                    const p0 = toCanvas(it.points[0].x, it.points[0].y);
                    ctx.moveTo(p0.cx, p0.cy);
                    for (let i = 1; i < it.points.length; i++) {
                        const p = toCanvas(it.points[i].x, it.points[i].y);
                        ctx.lineTo(p.cx, p.cy);
                    }
                    ctx.stroke();
                }
            });
        }
        function pos(e) {
            const r = canvas.getBoundingClientRect();
            return { cx: ((e.touches ? e.touches[0].clientX : e.clientX) - r.left) * (w / r.width),
                     cy: ((e.touches ? e.touches[0].clientY : e.clientY) - r.top) * (h / r.height) };
        }
        canvas.addEventListener('mousedown', e => {
            const p = pos(e); const c = toCoord(p.cx, p.cy);
            if (tool === 'point') { items.push({ type: 'point', x: c.x, y: c.y }); paint(); }
            else if (tool === 'line') {
                if (!lineStart) { lineStart = c; }
                else { items.push({ type: 'line', x1: lineStart.x, y1: lineStart.y, x2: c.x, y2: c.y }); lineStart = null; paint(); }
            } else if (tool === 'curve') {
                drawingCurve = true; curvePts = [{ x: c.x, y: c.y }];
            }
        });
        canvas.addEventListener('mousemove', e => {
            if (tool === 'curve' && drawingCurve) {
                const p = pos(e); const c = toCoord(p.cx, p.cy);
                curvePts.push({ x: c.x, y: c.y });
                if (curvePts.length > 2) {
                    paint();
                    ctx.strokeStyle = '#4f8cff'; ctx.lineWidth = 2;
                    ctx.beginPath();
                    const p0 = toCanvas(curvePts[0].x, curvePts[0].y);
                    ctx.moveTo(p0.cx, p0.cy);
                    for (let i = 1; i < curvePts.length; i++) {
                        const pp = toCanvas(curvePts[i].x, curvePts[i].y);
                        ctx.lineTo(pp.cx, pp.cy);
                    }
                    ctx.stroke();
                }
            }
        });
        canvas.addEventListener('mouseup', () => {
            if (tool === 'curve' && drawingCurve) {
                drawingCurve = false;
                if (curvePts.length > 1) items.push({ type: 'curve', points: curvePts });
                curvePts = []; paint();
            }
        });
        wrap.querySelectorAll('.ew-btn').forEach(b => b.addEventListener('click', () => {
            const t = b.dataset.tool;
            if (t === 'clear') { items.length = 0; lineStart = null; paint(); }
            else if (t === 'undo') { items.pop(); paint(); }
            else { tool = t; lineStart = null;
                wrap.querySelectorAll('[data-tool="point"], [data-tool="line"], [data-tool="curve"]').forEach(x => x.classList.remove('active'));
                b.classList.add('active');
            }
        }));
        paint();
        register(qNumber, 'graph',
            () => {
                if (items.length === 0) return '';
                // Serialise as readable text + JSON for AI
                const lines = ['Graph submission:'];
                items.forEach(it => {
                    if (it.type === 'point') lines.push(`- Point: (${it.x}, ${it.y})`);
                    else if (it.type === 'line') lines.push(`- Line: from (${it.x1}, ${it.y1}) to (${it.x2}, ${it.y2})`);
                    else if (it.type === 'curve') lines.push(`- Curve passing through ${it.points.length} points starting at (${it.points[0].x}, ${it.points[0].y}) and ending at (${it.points[it.points.length - 1].x}, ${it.points[it.points.length - 1].y})`);
                });
                lines.push('Image:');
                return lines.join('\n') + '\n' + canvas.toDataURL('image/png');
            },
            (val) => { /* graph restore: skip — students redraw on resume */ }
        );
    }

    // ====================================================================
    //  CODE EDITOR (lightweight monospace textarea, optionally Python/SQL/JS)
    // ====================================================================
    function renderCode(container, qNumber, opts) {
        injectStyles();
        opts = opts || {};
        const lang = opts.language || 'python';
        const placeholder = opts.placeholder || `# Write your ${lang} code here…`;
        const starter = opts.starter || '';
        const wrap = document.createElement('div');
        wrap.className = 'ew-wrap';
        wrap.innerHTML = `
            <div class="ew-toolbar">
                <span class="ew-label">💻 ${lang.toUpperCase()}</span>
                <span style="color:#71767b; font-size:11px;">Tab indents · Use proper syntax</span>
            </div>
            <div class="ew-code-wrap">
                <textarea class="ew-code-textarea" spellcheck="false" placeholder="${placeholder.replace(/"/g, '&quot;')}">${starter.replace(/</g, '&lt;')}</textarea>
            </div>`;
        container.appendChild(wrap);
        const ta = wrap.querySelector('textarea');
        ta.addEventListener('keydown', e => {
            if (e.key === 'Tab') {
                e.preventDefault();
                const s = ta.selectionStart, en = ta.selectionEnd;
                ta.value = ta.value.substring(0, s) + '    ' + ta.value.substring(en);
                ta.selectionStart = ta.selectionEnd = s + 4;
            }
        });
        register(qNumber, 'code',
            () => ta.value.trim() ? `\`\`\`${lang}\n${ta.value}\n\`\`\`` : '',
            (val) => {
                if (!val) return;
                // strip fence wrapper if present
                const m = val.match(/^```\w*\n([\s\S]*?)\n```$/);
                ta.value = m ? m[1] : val;
            }
        );
    }

    // ====================================================================
    //  SQL EDITOR (with schema panel)
    // ====================================================================
    function renderSQL(container, qNumber, opts) {
        injectStyles();
        opts = opts || {};
        const schema = opts.schema || []; // [{name, columns:[{name,type}]}]
        const wrap = document.createElement('div');
        wrap.className = 'ew-wrap';
        let schemaHtml = '';
        if (schema.length) {
            schemaHtml = `<div class="ew-sql-schema"><h4>Database schema</h4>` +
                schema.map(t => {
                    const cols = (t.columns || []).map(c => `${c.name}${c.type ? ' ' + c.type : ''}`).join(', ');
                    return `<div class="ew-sql-table"><strong>${t.name}</strong>(${cols})</div>`;
                }).join('') + '</div>';
        }
        wrap.innerHTML = `
            ${schemaHtml}
            <div class="ew-toolbar"><span class="ew-label">🗄️ SQL Query</span></div>
            <div class="ew-code-wrap">
                <textarea class="ew-code-textarea" spellcheck="false" placeholder="SELECT … FROM …">${(opts.starter || '').replace(/</g, '&lt;')}</textarea>
            </div>`;
        container.appendChild(wrap);
        const ta = wrap.querySelector('textarea');
        ta.addEventListener('keydown', e => {
            if (e.key === 'Tab') {
                e.preventDefault();
                const s = ta.selectionStart;
                ta.value = ta.value.substring(0, s) + '    ' + ta.value.substring(ta.selectionEnd);
                ta.selectionStart = ta.selectionEnd = s + 4;
            }
        });
        register(qNumber, 'sql',
            () => ta.value.trim() ? '```sql\n' + ta.value + '\n```' : '',
            (val) => {
                if (!val) return;
                const m = val.match(/^```\w*\n([\s\S]*?)\n```$/);
                ta.value = m ? m[1] : val;
            }
        );
    }

    // ====================================================================
    //  SPREADSHEET (formula grid — students write formulas; AI marks)
    // ====================================================================
    function renderSpreadsheet(container, qNumber, opts) {
        injectStyles();
        opts = opts || {};
        const cols = opts.cols || 5, rows = opts.rows || 8;
        const initial = opts.cells || {}; // { 'A1': 'value', ... }
        const wrap = document.createElement('div');
        wrap.className = 'ew-wrap';
        const colLetter = i => String.fromCharCode(65 + i);
        let head = '<tr><th></th>' + Array.from({ length: cols }, (_, i) => `<th>${colLetter(i)}</th>`).join('') + '</tr>';
        let body = '';
        for (let r = 1; r <= rows; r++) {
            body += `<tr><th>${r}</th>` + Array.from({ length: cols }, (_, i) => {
                const ref = colLetter(i) + r;
                const v = initial[ref] != null ? String(initial[ref]).replace(/"/g, '&quot;') : '';
                return `<td><input type="text" data-ref="${ref}" value="${v}"></td>`;
            }).join('') + '</tr>';
        }
        wrap.innerHTML = `
            <div class="ew-toolbar">
                <span class="ew-label">📈 Spreadsheet</span>
                <span style="color:#71767b; font-size:11px;">Use formulas like <code>=SUM(A1:A5)</code>, <code>=IF(A1&gt;10, "Yes", "No")</code></span>
            </div>
            <table class="ew-sheet"><thead>${head}</thead><tbody>${body}</tbody></table>`;
        container.appendChild(wrap);
        const cells = {};
        wrap.querySelectorAll('input').forEach(inp => {
            cells[inp.dataset.ref] = inp.value;
            inp.addEventListener('input', () => { cells[inp.dataset.ref] = inp.value; });
        });
        register(qNumber, 'spreadsheet',
            () => {
                const filled = Object.entries(cells).filter(([k, v]) => v && String(v).trim());
                if (filled.length === 0) return '';
                const lines = ['Spreadsheet submission:'];
                filled.forEach(([k, v]) => lines.push(`${k}: ${v}`));
                return lines.join('\n');
            },
            (val) => {
                if (!val) return;
                const lines = String(val).split('\n');
                lines.forEach(l => {
                    const m = l.match(/^([A-Z]+\d+):\s*(.+)$/);
                    if (m) {
                        const inp = wrap.querySelector(`input[data-ref="${m[1]}"]`);
                        if (inp) { inp.value = m[2]; cells[m[1]] = m[2]; }
                    }
                });
            }
        );
    }

    // ====================================================================
    //  DIAGRAM BUILDER (DFD / class-diagram / flowchart)
    // ====================================================================
    function renderDiagram(container, qNumber, opts) {
        injectStyles();
        opts = opts || {};
        const variant = opts.variant || 'dfd'; // dfd | flowchart | class
        const palettes = {
            dfd: [
                { type: 'process',  shape: 'circle',  label: 'Process' },
                { type: 'store',    shape: 'store',   label: 'Data Store' },
                { type: 'entity',   shape: 'rect',    label: 'External Entity' }
            ],
            flowchart: [
                { type: 'start',    shape: 'circle',  label: 'Start/End' },
                { type: 'process',  shape: 'rect',    label: 'Process' },
                { type: 'decision', shape: 'diamond', label: 'Decision' },
                { type: 'io',       shape: 'rect',    label: 'Input/Output' }
            ],
            class: [
                { type: 'class',    shape: 'class',   label: 'Class' }
            ]
        };
        const palette = palettes[variant] || palettes.dfd;
        const wrap = document.createElement('div');
        wrap.className = 'ew-wrap';
        const paletteHtml = palette.map(p => `<button type="button" class="ew-btn" data-add="${p.type}" data-shape="${p.shape}">+ ${p.label}</button>`).join('');
        wrap.innerHTML = `
            <div class="ew-toolbar">
                <span class="ew-label">🧩 ${variant === 'class' ? 'Class Diagram' : variant === 'flowchart' ? 'Flowchart' : 'Data Flow Diagram'}</span>
                ${paletteHtml}
                <button type="button" class="ew-btn" data-act="connect">Connect</button>
                <button type="button" class="ew-btn danger" data-act="del">Delete selected</button>
                <button type="button" class="ew-btn danger" data-act="clear">Clear</button>
            </div>
            <div class="ew-diagram-wrap">
                <div class="ew-diagram-canvas">
                    <svg class="ew-diagram-svg"><defs><marker id="ew-arrow-${qNumber}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><polygon points="0,0 10,5 0,10"/></marker></defs></svg>
                </div>
                <div class="ew-diagram-hint">Drag nodes · Click "Connect" then click two nodes to link them · Double-click a node to rename</div>
            </div>`;
        container.appendChild(wrap);
        const canvasDiv = wrap.querySelector('.ew-diagram-canvas');
        const svg = wrap.querySelector('svg');
        const nodes = []; // {id, type, shape, label, x, y, body?}
        const edges = []; // {from, to, label?}
        let connectMode = false, connectFrom = null, selectedId = null;
        let nodeId = 0;

        function paintEdges() {
            // remove existing lines (keep defs)
            [...svg.querySelectorAll('line, text.edge-label')].forEach(n => n.remove());
            edges.forEach(e => {
                const a = nodes.find(n => n.id === e.from), b = nodes.find(n => n.id === e.to);
                if (!a || !b) return;
                const ln = document.createElementNS('http://www.w3.org/2000/svg', 'line');
                ln.setAttribute('x1', a.x + 50); ln.setAttribute('y1', a.y + 25);
                ln.setAttribute('x2', b.x + 50); ln.setAttribute('y2', b.y + 25);
                ln.setAttribute('marker-end', `url(#ew-arrow-${qNumber})`);
                svg.appendChild(ln);
            });
        }
        function paint() {
            // remove existing node divs
            [...canvasDiv.querySelectorAll('.ew-diagram-node')].forEach(n => n.remove());
            nodes.forEach(n => {
                const div = document.createElement('div');
                div.className = `ew-diagram-node shape-${n.shape}` + (n.id === selectedId ? ' selected' : '');
                div.style.left = n.x + 'px'; div.style.top = n.y + 'px';
                if (n.shape === 'class') {
                    div.innerHTML = `<div class="cls-name">${n.label}</div><div class="cls-body" contenteditable="true">${(n.body || 'attr1\nattr2()')}</div>`;
                } else if (n.shape === 'diamond') {
                    div.innerHTML = `<span>${n.label}</span>`;
                } else {
                    div.textContent = n.label;
                }
                div.dataset.id = n.id;
                makeDraggable(div, n);
                div.addEventListener('click', e => {
                    e.stopPropagation();
                    if (connectMode) {
                        if (!connectFrom) { connectFrom = n.id; selectedId = n.id; }
                        else if (connectFrom !== n.id) { edges.push({ from: connectFrom, to: n.id }); connectFrom = null; selectedId = null; connectMode = false; }
                    } else {
                        selectedId = n.id;
                    }
                    paint(); paintEdges();
                });
                div.addEventListener('dblclick', e => {
                    e.stopPropagation();
                    const newLabel = prompt('Label:', n.label);
                    if (newLabel != null) { n.label = newLabel; paint(); paintEdges(); }
                });
                if (n.shape === 'class') {
                    const body = div.querySelector('.cls-body');
                    if (body) body.addEventListener('input', () => { n.body = body.innerText; });
                }
                canvasDiv.appendChild(div);
            });
            paintEdges();
        }
        function makeDraggable(el, n) {
            let dx, dy, dragging = false;
            el.addEventListener('mousedown', e => {
                if (e.target.closest('.cls-body')) return;
                dragging = true;
                const r = canvasDiv.getBoundingClientRect();
                dx = e.clientX - r.left - n.x; dy = e.clientY - r.top - n.y;
                e.preventDefault();
            });
            document.addEventListener('mousemove', e => {
                if (!dragging) return;
                const r = canvasDiv.getBoundingClientRect();
                n.x = Math.max(0, Math.min(r.width - 100, e.clientX - r.left - dx));
                n.y = Math.max(0, Math.min(r.height - 50, e.clientY - r.top - dy));
                el.style.left = n.x + 'px'; el.style.top = n.y + 'px';
                paintEdges();
            });
            document.addEventListener('mouseup', () => { dragging = false; });
        }
        wrap.querySelectorAll('.ew-toolbar .ew-btn').forEach(b => b.addEventListener('click', () => {
            if (b.dataset.add) {
                const p = palette.find(x => x.type === b.dataset.add);
                const label = prompt(`${p.label} name:`, p.label);
                if (label == null) return;
                nodes.push({ id: ++nodeId, type: p.type, shape: p.shape, label: label || p.label, x: 30 + Math.random() * 200, y: 30 + Math.random() * 100, body: p.shape === 'class' ? 'attr: type\nmethod()' : '' });
                paint();
            } else if (b.dataset.act === 'connect') {
                connectMode = !connectMode; connectFrom = null; b.classList.toggle('active');
            } else if (b.dataset.act === 'del') {
                if (selectedId == null) return;
                const idx = nodes.findIndex(x => x.id === selectedId);
                if (idx >= 0) {
                    nodes.splice(idx, 1);
                    for (let i = edges.length - 1; i >= 0; i--) {
                        if (edges[i].from === selectedId || edges[i].to === selectedId) edges.splice(i, 1);
                    }
                }
                selectedId = null; paint();
            } else if (b.dataset.act === 'clear') {
                nodes.length = 0; edges.length = 0; selectedId = null; paint();
            }
        }));
        canvasDiv.addEventListener('click', () => { selectedId = null; paint(); });
        register(qNumber, 'diagram',
            () => {
                if (nodes.length === 0) return '';
                const lines = [`${variant.toUpperCase()} submission:`];
                lines.push('Nodes:');
                nodes.forEach(n => lines.push(`- ${n.id}: [${n.type}] ${n.label}${n.body ? ' { ' + n.body.replace(/\n/g, '; ') + ' }' : ''}`));
                if (edges.length) {
                    lines.push('Connections:');
                    edges.forEach(e => {
                        const a = nodes.find(n => n.id === e.from), b = nodes.find(n => n.id === e.to);
                        if (a && b) lines.push(`- ${a.label} → ${b.label}`);
                    });
                } else { lines.push('Connections: (none)'); }
                return lines.join('\n');
            },
            (val) => { /* skip restore for diagrams — students rebuild on resume */ }
        );
    }

    // ====================================================================
    //  Dispatch
    // ====================================================================
    function render(inputType, container, qNumber, options) {
        if (!container) return;
        switch (inputType) {
            case 'draw':        renderDrawing(container, qNumber, options); break;
            case 'graph':       renderGraph(container, qNumber, options); break;
            case 'table':       renderTable(container, qNumber, options); break;
            case 'spreadsheet': renderSpreadsheet(container, qNumber, options); break;
            case 'code':        renderCode(container, qNumber, options); break;
            case 'sql':         renderSQL(container, qNumber, options); break;
            case 'diagram':
            case 'dfd':
            case 'flowchart':
            case 'class-diagram': {
                const variant = inputType === 'dfd' ? 'dfd' : inputType === 'flowchart' ? 'flowchart' : inputType === 'class-diagram' ? 'class' : (options && options.variant) || 'dfd';
                renderDiagram(container, qNumber, Object.assign({}, options, { variant }));
                break;
            }
            default: break;
        }
    }

    window.ExamWidgets = { render, getValue, setValue, mountCalculator, SUPPORTED };
})();
