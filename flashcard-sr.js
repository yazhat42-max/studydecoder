/**
 * flashcard-sr.js — Spaced-repetition engine for Study Decoder flashcards
 * =======================================================================
 * Pure functions, no I/O. Easy to unit-test (see flashcard-sr.test.js).
 *
 * Implements an SM-2-style scheduler plus the rolling "mastery" EMA that
 * feeds the student mastery map and the teacher progress dashboard.
 *
 * Used server-side (required by server.js).
 */

'use strict';

const DAY_MS = 24 * 60 * 60 * 1000;

const MIN_EASE = 1.3;
const DEFAULT_EASE = 2.5;

// EMA smoothing factor — tuned so the score behaves like an average over the
// last ~5 grades:  alpha = 2 / (N + 1)  with N = 5.
const MASTERY_ALPHA = 2 / (5 + 1);

/**
 * Map an AI grade (+ whether a hint was used) to an SM-2 quality score 0–5.
 *   correct, no hint        -> 5
 *   correct, with hint      -> 4
 *   partial                 -> 3
 *   incorrect but recovered -> 2
 *   incorrect               -> 1
 *   off-track               -> 0
 */
function gradeToQuality(grade, usedHint) {
    switch (grade) {
        case 'correct':   return usedHint ? 4 : 5;
        case 'partial':   return 3;
        case 'incorrect': return usedHint ? 2 : 1;
        case 'off-track': return 0;
        default:          return 1;
    }
}

/**
 * Core SM-2 transition.
 *
 * @param {{ease?:number, interval?:number, reps?:number, lapses?:number}} prior
 * @param {number} quality   integer 0–5
 * @param {number} [now]     epoch ms (defaults to Date.now())
 * @returns {{ease:number, interval:number, reps:number, lapses:number, dueAt:string, lastGrade:number, lastReviewedAt:string}}
 */
function schedule(prior, quality, now) {
    now = typeof now === 'number' ? now : Date.now();
    const q = Math.max(0, Math.min(5, Math.round(Number(quality) || 0)));

    let ease = Number(prior && prior.ease);
    if (!Number.isFinite(ease) || ease < MIN_EASE) ease = DEFAULT_EASE;
    let reps = Number(prior && prior.reps);
    if (!Number.isFinite(reps) || reps < 0) reps = 0;
    let interval = Number(prior && prior.interval);
    if (!Number.isFinite(interval) || interval < 0) interval = 0;
    let lapses = Number(prior && prior.lapses);
    if (!Number.isFinite(lapses) || lapses < 0) lapses = 0;

    // Update ease factor (standard SM-2 formula), clamped at MIN_EASE.
    ease = ease + (0.1 - (5 - q) * (0.08 + (5 - q) * 0.02));
    if (ease < MIN_EASE) ease = MIN_EASE;

    if (q < 3) {
        // Lapse — reset the rep count, re-show soon (1 day).
        reps = 0;
        interval = 1;
        lapses += 1;
    } else {
        if (reps === 0) {
            interval = 1;
        } else if (reps === 1) {
            interval = 6;
        } else {
            interval = Math.round(interval * ease);
        }
        if (interval < 1) interval = 1;
        reps += 1;
    }

    return {
        ease: Math.round(ease * 1000) / 1000,
        interval,
        reps,
        lapses,
        lastGrade: q,
        lastReviewedAt: new Date(now).toISOString(),
        dueAt: new Date(now + interval * DAY_MS).toISOString()
    };
}

/**
 * Rolling mastery score (EMA) for a dot point, bounded 0–1.
 *
 * @param {number|null|undefined} prevScore  previous score (0–1) or null for first review
 * @param {number} quality                  SM-2 quality 0–5 of the latest grade
 * @returns {number} new score, 0–1, rounded to 3 dp
 */
function updateMastery(prevScore, quality) {
    const q = Math.max(0, Math.min(5, Math.round(Number(quality) || 0)));
    const sample = q / 5; // normalise to 0–1
    let prev = prevScore == null ? NaN : Number(prevScore);
    if (!Number.isFinite(prev)) prev = sample; // seed EMA with first sample
    let next = MASTERY_ALPHA * sample + (1 - MASTERY_ALPHA) * prev;
    if (next < 0) next = 0;
    if (next > 1) next = 1;
    return Math.round(next * 1000) / 1000;
}

/**
 * Convenience: given an existing mastery record and a fresh quality, return the
 * updated record. Tracks consecutive strong (q>=4) / weak (q<=2) streaks.
 */
function applyMastery(prevRecord, quality, now) {
    now = typeof now === 'number' ? now : Date.now();
    const q = Math.max(0, Math.min(5, Math.round(Number(quality) || 0)));
    const prev = prevRecord && typeof prevRecord === 'object' ? prevRecord : {};
    const score = updateMastery(prev.score, q);
    let strongStreak = Number(prev.strongStreak) || 0;
    let weakStreak = Number(prev.weakStreak) || 0;
    if (q >= 4) { strongStreak += 1; weakStreak = 0; }
    else if (q <= 2) { weakStreak += 1; strongStreak = 0; }
    else { strongStreak = 0; weakStreak = 0; }
    return {
        score,
        strongStreak,
        weakStreak,
        lastUpdate: new Date(now).toISOString()
    };
}

/** Heatmap band for a 0–1 mastery score. */
function masteryBand(score) {
    if (score == null) return 'none';
    const s = Number(score);
    if (!Number.isFinite(s)) return 'none';
    if (s >= 0.75) return 'strong';   // green
    if (s >= 0.45) return 'medium';   // yellow
    return 'weak';                    // red
}

module.exports = {
    DAY_MS,
    MIN_EASE,
    DEFAULT_EASE,
    gradeToQuality,
    schedule,
    updateMastery,
    applyMastery,
    masteryBand
};
