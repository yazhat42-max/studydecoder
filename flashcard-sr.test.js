/**
 * Unit tests for flashcard-sr.js
 * Run with:  node --test   (Node 18+ built-in test runner)
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const sr = require('./flashcard-sr');

const FIXED_NOW = Date.parse('2026-01-01T00:00:00.000Z');

test('gradeToQuality maps AI grades to SM-2 quality', () => {
    assert.strictEqual(sr.gradeToQuality('correct', false), 5);
    assert.strictEqual(sr.gradeToQuality('correct', true), 4);
    assert.strictEqual(sr.gradeToQuality('partial', false), 3);
    assert.strictEqual(sr.gradeToQuality('incorrect', true), 2);
    assert.strictEqual(sr.gradeToQuality('incorrect', false), 1);
    assert.strictEqual(sr.gradeToQuality('off-track', false), 0);
});

test('SM-2 transitions for quality 0-5 from a fresh card', () => {
    for (let q = 0; q <= 5; q++) {
        const next = sr.schedule({}, q, FIXED_NOW);
        assert.ok(Number.isFinite(next.ease), `ease finite for q=${q}`);
        assert.ok(next.ease >= sr.MIN_EASE, `ease >= ${sr.MIN_EASE} for q=${q}`);
        assert.ok(next.interval >= 1, `interval >= 1 for q=${q}`);
        assert.ok(Number.isInteger(next.interval), `interval integer for q=${q}`);
        assert.strictEqual(next.lastGrade, q);
        if (q < 3) {
            assert.strictEqual(next.reps, 0, `lapse resets reps for q=${q}`);
            assert.strictEqual(next.interval, 1, `lapse interval is 1 for q=${q}`);
            assert.strictEqual(next.lapses, 1, `lapse counted for q=${q}`);
        } else {
            assert.strictEqual(next.reps, 1, `pass increments reps for q=${q}`);
            assert.strictEqual(next.lapses, 0, `no lapse for q=${q}`);
        }
    }
});

test('ease never drops below the floor even on repeated failures', () => {
    let state = {};
    for (let i = 0; i < 20; i++) state = sr.schedule(state, 0, FIXED_NOW);
    assert.ok(state.ease >= sr.MIN_EASE);
    assert.strictEqual(state.ease, sr.MIN_EASE);
});

test('dueAt is monotonically increasing for repeated correct answers', () => {
    let state = sr.schedule({}, 5, FIXED_NOW);
    let prevDue = Date.parse(state.dueAt);
    let prevInterval = state.interval;
    // Each subsequent review happens once the card is due.
    for (let i = 0; i < 6; i++) {
        const reviewAt = Date.parse(state.dueAt);
        state = sr.schedule(state, 5, reviewAt);
        const due = Date.parse(state.dueAt);
        assert.ok(due > prevDue, `dueAt increases on rep ${i}`);
        assert.ok(state.interval >= prevInterval, `interval grows on rep ${i}`);
        prevDue = due;
        prevInterval = state.interval;
    }
});

test('classic SM-2 interval ladder: 1 -> 6 -> interval*ease', () => {
    let state = sr.schedule({}, 4, FIXED_NOW);
    assert.strictEqual(state.interval, 1);
    state = sr.schedule(state, 4, FIXED_NOW);
    assert.strictEqual(state.interval, 6);
    state = sr.schedule(state, 4, FIXED_NOW);
    assert.ok(state.interval > 6, 'third correct rep extends past 6 days');
});

test('updateMastery stays within 0-1 bounds', () => {
    let score = sr.updateMastery(null, 5);
    assert.ok(score >= 0 && score <= 1);
    // Hammer with perfect scores — should approach but never exceed 1.
    for (let i = 0; i < 50; i++) score = sr.updateMastery(score, 5);
    assert.ok(score <= 1);
    assert.ok(score > 0.9);
    // Hammer with zeros — should approach but never go below 0.
    for (let i = 0; i < 50; i++) score = sr.updateMastery(score, 0);
    assert.ok(score >= 0);
    assert.ok(score < 0.1);
});

test('updateMastery first sample seeds the EMA directly', () => {
    assert.strictEqual(sr.updateMastery(null, 5), 1);
    assert.strictEqual(sr.updateMastery(undefined, 0), 0);
    assert.strictEqual(sr.updateMastery(NaN, 3), 0.6);
});

test('applyMastery tracks strong/weak streaks', () => {
    let rec = sr.applyMastery(null, 5, FIXED_NOW);
    assert.strictEqual(rec.strongStreak, 1);
    assert.strictEqual(rec.weakStreak, 0);
    rec = sr.applyMastery(rec, 4, FIXED_NOW);
    assert.strictEqual(rec.strongStreak, 2);
    rec = sr.applyMastery(rec, 1, FIXED_NOW);
    assert.strictEqual(rec.strongStreak, 0);
    assert.strictEqual(rec.weakStreak, 1);
    rec = sr.applyMastery(rec, 0, FIXED_NOW);
    assert.strictEqual(rec.weakStreak, 2);
    rec = sr.applyMastery(rec, 3, FIXED_NOW);
    assert.strictEqual(rec.strongStreak, 0);
    assert.strictEqual(rec.weakStreak, 0);
});

test('masteryBand classifies scores into heatmap colours', () => {
    assert.strictEqual(sr.masteryBand(0.9), 'strong');
    assert.strictEqual(sr.masteryBand(0.6), 'medium');
    assert.strictEqual(sr.masteryBand(0.2), 'weak');
    assert.strictEqual(sr.masteryBand(null), 'none');
});
