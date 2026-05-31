#!/usr/bin/env node
/**
 * embed-syllabus.js — Build the RAG corpus for StudyDecoder.
 *
 * Walks the syllabuses/ tree, chunks each subject + module file into
 * dot-point-sized chunks, embeds each chunk with OpenAI's
 * text-embedding-3-small ($0.02 / 1M tokens — embedding the entire
 * senior + junior corpus costs roughly $0.05 one-time), and writes
 * the result to data/syllabus-embeddings.json.
 *
 * The server loads that file at startup into memory (a Float32Array
 * per chunk + metadata array) and uses cosine similarity to retrieve
 * the top-k chunks for a given query. At ~5,000 dot-points across 45
 * subjects, brute-force cosine over a flat array runs in <10ms — no
 * vector DB needed.
 *
 * Usage:
 *   node scripts/embed-syllabus.js              # embed everything
 *   node scripts/embed-syllabus.js --subject=biology
 *   node scripts/embed-syllabus.js --dry-run    # parse + chunk, skip API
 *
 * Re-runs are idempotent — already-embedded chunks (matched on a stable
 * content hash) are skipped. Re-running after a syllabus update only
 * embeds the changed chunks.
 *
 * NOTE: requires OPENAI_API_KEY in the environment (loads .env via dotenv
 * if available).
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
try { require('dotenv').config(); } catch (_) {}

const ROOT = path.resolve(__dirname, '..');
const SYLLABUSES_PATH = path.join(ROOT, 'syllabuses');
const DATA_PATH = process.env.NODE_ENV === 'production' ? '/var/data' : path.join(ROOT, 'data');
const OUTPUT_PATH = path.join(DATA_PATH, 'syllabus-embeddings.json');

const args = process.argv.slice(2);
const flags = Object.fromEntries(
    args.filter(a => a.startsWith('--')).map(a => {
        const [k, v] = a.replace(/^--/, '').split('=');
        return [k, v == null ? true : v];
    })
);
const SUBJECT_FILTER = flags.subject || null;
const DRY_RUN = !!flags['dry-run'];
const BATCH_SIZE = 100;   // OpenAI embeddings accept up to 2048/req
const EMBED_MODEL = 'text-embedding-3-small';
const EMBED_DIMS = 1536;

const apiKey = process.env.OPENAI_API_KEY;
if (!apiKey && !DRY_RUN) {
    console.error('❌ OPENAI_API_KEY not set. Run with --dry-run to test chunking without API calls.');
    process.exit(1);
}

// Load existing embeddings so re-runs only embed changed chunks
let existing = { _meta: {}, chunks: [] };
if (fs.existsSync(OUTPUT_PATH)) {
    try {
        existing = JSON.parse(fs.readFileSync(OUTPUT_PATH, 'utf8'));
        console.log(`📂 Loaded existing corpus: ${existing.chunks.length} chunks`);
    } catch (e) {
        console.warn('Could not parse existing embeddings file; starting fresh.', e.message);
    }
}
const existingByHash = new Map(existing.chunks.map(c => [c.hash, c]));

// Load subject configs
function loadJson(p) {
    try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
    catch (_) { return null; }
}
const seniorConfig = loadJson(path.join(SYLLABUSES_PATH, 'subjects.json')) || { subjects: [] };
const juniorConfig = loadJson(path.join(SYLLABUSES_PATH, 'junior-subjects.json')) || { subjects: [] };
const modulesIndex = loadJson(path.join(SYLLABUSES_PATH, 'modules', 'modules-index.json')) || {};

// === CHUNKING ===
// Split a syllabus text into roughly-paragraph-sized chunks at natural
// boundaries: numbered or bulleted dot-points, blank lines, or headings.
// Target ~300-600 tokens (~1200-2400 chars) per chunk so the retrieved
// context window stays useful but each chunk represents one idea.
function chunkSyllabus(text, { subjectId, isJunior, module, sourceFile }) {
    if (!text || text.length < 100) return [];
    const lines = text.split(/\r?\n/);
    const chunks = [];
    let buf = [];
    let currentHeading = null;
    let bufLen = 0;
    const MAX = 2200;   // ~550 tokens
    const MIN = 400;

    function flush(label) {
        if (!buf.length) return;
        const t = buf.join('\n').trim();
        if (t.length < 80) { buf = []; bufLen = 0; return; }
        const hash = crypto.createHash('sha1').update(`${subjectId}|${module || ''}|${t}`).digest('hex').slice(0, 16);
        chunks.push({
            id: `${subjectId}::${module || 'all'}::${chunks.length}`,
            hash,
            subjectId,
            isJunior,
            module: module || null,
            heading: label || currentHeading || null,
            sourceFile: sourceFile || null,
            text: t.slice(0, 4000)   // hard cap on stored text
        });
        buf = [];
        bufLen = 0;
    }

    for (const raw of lines) {
        const line = raw.replace(/\s+$/, '');
        // Treat headings (ALL CAPS, "Module X:", or markdown #) as flush points
        const isHeading = /^(#+\s|MODULE\s+\d|Module\s+\d|[A-Z][A-Z0-9 :,.\-/&'()]{8,}$)/.test(line.trim());
        if (isHeading && bufLen >= MIN) flush();
        if (isHeading) currentHeading = line.trim();

        // Treat numbered/bulleted dot points as natural splits when over MIN
        const isDotPoint = /^[\s]*[-•·*•]|^\s*\d+[.)]\s|^\s*\([a-z]\)\s/.test(line);
        if (isDotPoint && bufLen >= MIN) flush();

        buf.push(line);
        bufLen += line.length + 1;

        if (bufLen >= MAX) flush();
    }
    flush();
    return chunks;
}

// === COLLECT ALL CHUNKS ===
function collect() {
    const all = [];
    const configs = [
        { cfg: seniorConfig, isJunior: false },
        { cfg: juniorConfig, isJunior: true }
    ];
    for (const { cfg, isJunior } of configs) {
        for (const subj of cfg.subjects || []) {
            if (SUBJECT_FILTER && subj.id !== SUBJECT_FILTER) continue;

            // Per-module files (senior only) — best chunking source because each
            // file is already topic-scoped.
            if (!isJunior && modulesIndex[subj.id]) {
                for (const [modName, modFile] of Object.entries(modulesIndex[subj.id])) {
                    const p = path.join(SYLLABUSES_PATH, 'modules', subj.id, modFile);
                    if (!fs.existsSync(p)) continue;
                    const txt = fs.readFileSync(p, 'utf8');
                    const ch = chunkSyllabus(txt, { subjectId: subj.id, isJunior, module: modName, sourceFile: `modules/${subj.id}/${modFile}` });
                    all.push(...ch);
                }
            }
            // Always also chunk the full subject syllabus file(s) so non-module
            // questions still hit the corpus.
            for (const f of subj.files || []) {
                const p = path.join(SYLLABUSES_PATH, f);
                if (!fs.existsSync(p)) continue;
                const txt = fs.readFileSync(p, 'utf8');
                const ch = chunkSyllabus(txt, { subjectId: subj.id, isJunior, module: null, sourceFile: f });
                all.push(...ch);
            }
        }
    }
    return all;
}

// === EMBED ===
async function embedBatch(texts) {
    const res = await fetch('https://api.openai.com/v1/embeddings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
        body: JSON.stringify({ model: EMBED_MODEL, input: texts })
    });
    if (!res.ok) {
        const err = await res.text();
        throw new Error(`OpenAI embeddings HTTP ${res.status}: ${err.slice(0, 200)}`);
    }
    const data = await res.json();
    return data.data.map(d => d.embedding);   // array of float[1536]
}

async function main() {
    if (!fs.existsSync(SYLLABUSES_PATH)) {
        console.error(`❌ syllabuses/ directory not found at ${SYLLABUSES_PATH}`);
        console.error('   Run this script in your local repo where the syllabus files live.');
        process.exit(1);
    }
    console.log('🔍 Chunking syllabus corpus...');
    const chunks = collect();
    console.log(`📚 Collected ${chunks.length} chunks across ${new Set(chunks.map(c => c.subjectId)).size} subjects`);
    if (!chunks.length) {
        console.error('No chunks produced — check the syllabuses/ tree.');
        process.exit(1);
    }
    if (DRY_RUN) {
        console.log('— Dry run, skipping embeddings.');
        const sample = chunks.slice(0, 3);
        sample.forEach(c => console.log(`\n[${c.subjectId} / ${c.module || 'all'}] (${c.text.length} chars)\n${c.text.slice(0, 200)}…`));
        return;
    }

    // Skip chunks we've already embedded
    const toEmbed = [];
    for (const c of chunks) {
        const prev = existingByHash.get(c.hash);
        if (prev && prev.vector && prev.vector.length === EMBED_DIMS) {
            c.vector = prev.vector;
        } else {
            toEmbed.push(c);
        }
    }
    console.log(`🔁 ${chunks.length - toEmbed.length} chunks already embedded (skipped); ${toEmbed.length} new/changed to embed.`);

    // Batch embed
    let done = 0;
    for (let i = 0; i < toEmbed.length; i += BATCH_SIZE) {
        const slice = toEmbed.slice(i, i + BATCH_SIZE);
        const inputs = slice.map(c => `${c.subjectId} / ${c.module || 'general'}\n${c.heading || ''}\n${c.text}`.slice(0, 8000));
        try {
            const vectors = await embedBatch(inputs);
            slice.forEach((c, j) => { c.vector = vectors[j]; });
            done += slice.length;
            process.stdout.write(`\r⚙️  Embedded ${done}/${toEmbed.length}…`);
        } catch (e) {
            console.error('\nBatch failed:', e.message, '— retrying after 5s...');
            await new Promise(r => setTimeout(r, 5000));
            try {
                const vectors = await embedBatch(inputs);
                slice.forEach((c, j) => { c.vector = vectors[j]; });
                done += slice.length;
                process.stdout.write(`\r⚙️  Embedded ${done}/${toEmbed.length} (retry ok)`);
            } catch (e2) {
                console.error('Batch failed again, skipping:', e2.message);
            }
        }
    }
    process.stdout.write('\n');

    // Persist
    const output = {
        _meta: {
            embeddedAt: new Date().toISOString(),
            model: EMBED_MODEL,
            dims: EMBED_DIMS,
            chunkCount: chunks.length,
            subjects: [...new Set(chunks.map(c => c.subjectId))].length,
            note: 'Generated by scripts/embed-syllabus.js. Re-run after syllabus updates — only changed chunks re-embed.'
        },
        chunks: chunks.filter(c => Array.isArray(c.vector) && c.vector.length === EMBED_DIMS)
    };
    if (!fs.existsSync(DATA_PATH)) fs.mkdirSync(DATA_PATH, { recursive: true });
    fs.writeFileSync(OUTPUT_PATH, JSON.stringify(output));
    const sizeMb = (fs.statSync(OUTPUT_PATH).size / 1024 / 1024).toFixed(1);
    console.log(`✅ Wrote ${output.chunks.length} embedded chunks to ${OUTPUT_PATH} (${sizeMb}MB)`);
    console.log(`   Server will pick these up on next restart.`);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
