#!/usr/bin/env node
/* generate-seo.js — one-time / resumable pre-generation of the AI "plain English"
 * decode for every syllabus subject + module. Writes syllabuses/decoded/{id}/{slug}.json,
 * which the /learn/* SEO pages serve. Skips files that already exist (resumable).
 *
 * Requires: OPENAI_API_KEY and the production syllabuses/ tree.
 * Usage:
 *   node generate-seo.js                 # generate everything missing
 *   node generate-seo.js --force         # regenerate even if cached
 *   node generate-seo.js --subject=biology
 *   node generate-seo.js --limit=50      # cap the number generated this run
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = __dirname;
const SYLLABUSES_PATH = path.join(ROOT, 'syllabuses');
const DECODED_PATH = path.join(SYLLABUSES_PATH, 'decoded');
const API_KEY = process.env.OPENAI_API_KEY || process.env.OPENAI_KEY;

const args = process.argv.slice(2);
const FORCE = args.includes('--force');
const ONLY_SUBJECT = (args.find(a => a.startsWith('--subject=')) || '').split('=')[1] || null;
const LIMIT = parseInt((args.find(a => a.startsWith('--limit=')) || '').split('=')[1], 10) || Infinity;

function seoSlug(s) {
    return String(s || '').toLowerCase().trim()
        .replace(/&/g, ' and ').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80);
}

function buildCatalog() {
    const code = fs.readFileSync(path.join(ROOT, 'subject-data.js'), 'utf8');
    const sandbox = { window: {} };
    vm.runInNewContext(code, sandbox, { timeout: 2000 });
    const SD = sandbox.window.SD_SUBJECTS;
    const topics = SD.topics || {};
    const out = [];
    const add = (list, level) => (list || []).forEach(s => out.push({
        id: s.id, name: s.name, level, modules: (topics[s.id] || []).map(m => ({ name: m, slug: seoSlug(m) }))
    }));
    add(SD.senior, 'senior'); add(SD.junior, 'junior');
    return out;
}

let modulesIndex = {};
try { modulesIndex = JSON.parse(fs.readFileSync(path.join(SYLLABUSES_PATH, 'modules', 'modules-index.json'), 'utf8')); } catch (e) { /* none */ }

// Best-effort module text lookup (mirrors server getSyllabusContent fuzzy match).
function moduleText(subjectId, moduleName) {
    const subjMods = modulesIndex[subjectId];
    if (!subjMods) return '';
    let file = subjMods[moduleName];
    if (!file) {
        const ml = moduleName.toLowerCase();
        for (const [n, f] of Object.entries(subjMods)) {
            if (n.toLowerCase().includes(ml) || ml.includes(n.toLowerCase())) { file = f; break; }
        }
    }
    if (!file) return '';
    try { return fs.readFileSync(path.join(SYLLABUSES_PATH, 'modules', subjectId, file), 'utf8'); } catch (e) { return ''; }
}

async function decode(subjectName, levelWord, moduleName, syllabus) {
    const sys = `You are an expert NSW ${levelWord} teacher. Decode a syllabus module into plain, student-friendly English. Return ONLY valid JSON:
{ "summary": "<=120 words, what this module is really about and why it matters, no jargon>", "points": ["6-10 short bullet strings of what the module covers"], "examTips": "<=60 words on how it's typically assessed" }`;
    const usr = `Subject: ${subjectName} (${levelWord})\nModule: ${moduleName}\n\nOfficial syllabus content:\n${(syllabus || '(not provided — infer from the module name and standard NSW NESA scope)').slice(0, 12000)}`;
    const r = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${API_KEY}` },
        body: JSON.stringify({ model: 'gpt-4o-mini', response_format: { type: 'json_object' }, max_tokens: 900, temperature: 0.5,
            messages: [{ role: 'system', content: sys }, { role: 'user', content: usr }] })
    });
    if (!r.ok) throw new Error('OpenAI HTTP ' + r.status);
    const data = await r.json();
    const parsed = JSON.parse(data.choices?.[0]?.message?.content || '{}');
    return {
        summary: String(parsed.summary || '').slice(0, 1200),
        points: Array.isArray(parsed.points) ? parsed.points.map(p => String(p).slice(0, 240)).slice(0, 12) : [],
        examTips: String(parsed.examTips || '').slice(0, 600),
        generatedAt: new Date().toISOString()
    };
}

(async function main() {
    if (!API_KEY) { console.error('❌ OPENAI_API_KEY not set'); process.exit(1); }
    const catalog = buildCatalog();
    let made = 0, skipped = 0, failed = 0;
    for (const s of catalog) {
        if (ONLY_SUBJECT && s.id !== ONLY_SUBJECT) continue;
        if (made >= LIMIT) break;
        const levelWord = s.level === 'junior' ? 'Years 7-10' : 'HSC';
        const dir = path.join(DECODED_PATH, s.id);
        fs.mkdirSync(dir, { recursive: true });
        for (const m of s.modules) {
            if (made >= LIMIT) break;
            const out = path.join(dir, m.slug + '.json');
            if (!FORCE && fs.existsSync(out)) { skipped++; continue; }
            try {
                const content = await decode(s.name, levelWord, m.name, moduleText(s.id, m.name));
                fs.writeFileSync(out, JSON.stringify(content, null, 2));
                made++;
                console.log(`✅ ${s.id}/${m.slug}`);
                await new Promise(r => setTimeout(r, 350)); // gentle rate limit
            } catch (e) {
                failed++;
                console.error(`⚠️  ${s.id}/${m.slug}: ${e.message}`);
            }
        }
    }
    console.log(`\nDone. Generated ${made}, skipped ${skipped} (already cached), failed ${failed}.`);
})();
