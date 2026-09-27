const { test } = require('node:test');
const assert = require('node:assert/strict');
const s = require('../src/scheduler.cjs');

const config = (quick = {}, full = {}) => [
  { id: 'quick', enabled: true, frequency: 'daily', time: '12:00', day: 0, ...quick },
  { id: 'full', enabled: true, frequency: 'weekly', time: '18:00', day: 0, ...full }
];
const at = (d, h = 0, m = 0) => new Date(2026, 8, d, h, m); // September 2026, local time
const minutes = (a, b) => (new Date(b) - new Date(a)) / 60000;

// Drives the scheduler like the app does: advance, pick a job, start it, and record an outcome.
function run(cfg, runtime, now, status, error) {
  s.advance(cfg, runtime, now);
  const job = s.nextJob(cfg, runtime, now);
  if (!job) return null;
  job.started = now.toISOString();
  s.recordStart(runtime, job, now);
  s.recordOutcome(runtime, job, status, now, error);
  return job;
}

test('an occurrence becomes pending and the following one is planned', () => {
  const cfg = config();
  const rt = s.reconcile(cfg, {}, at(27, 11));
  assert.equal(new Date(rt.quick.next).getTime(), at(27, 12).getTime());
  assert.equal(s.nextJob(cfg, rt, at(27, 11, 59)), null);
  s.advance(cfg, rt, at(27, 12));
  assert.equal(rt.quick.pending.occurrence, at(27, 12).toISOString());
  assert.equal(new Date(rt.quick.next).getTime(), at(28, 12).getTime());
});

test('a scan that fails to start keeps its occurrence and retries with bounded backoff', () => {
  const cfg = config({ enabled: false });
  const rt = s.reconcile(cfg, {}, at(26, 12)); // full due Sunday 27 at 18:00
  const job = run(cfg, rt, at(27, 18), 'failed-to-start', 'clamscan.exe missing');
  assert.equal(job.scheduleId, 'full');
  assert.equal(rt.full.pending.attempts, 1);
  assert.equal(minutes(at(27, 18), rt.full.pending.retryAfter), 15);
  assert.equal(rt.full.pending.lastError, 'clamscan.exe missing');
  assert.equal(s.nextJob(cfg, rt, at(27, 18, 14)), null);
  const delays = [];
  let now = new Date(rt.full.pending.retryAfter);
  for (let i = 0; i < 8; i++) {
    run(cfg, rt, now, 'error');
    delays.push(minutes(now, rt.full.pending.retryAfter));
    now = new Date(rt.full.pending.retryAfter);
  }
  assert.deepEqual(delays, [30, 60, 120, 240, 360, 360, 360, 360]);
  // The weekly occurrence is still owed; it did not silently wait a week.
  assert.equal(rt.full.pending.occurrence, at(27, 18).toISOString());
});

test('an error exit after a successful start is retried, and success clears it', () => {
  const cfg = config({ enabled: false });
  const rt = s.reconcile(cfg, {}, at(26));
  run(cfg, rt, at(27, 18), 'error', 'exit 2');
  const retryAt = new Date(rt.full.pending.retryAfter);
  run(cfg, rt, retryAt, 'completed');
  assert.equal(rt.full.pending, null);
  assert.equal(rt.full.lastSuccess, retryAt.toISOString());
  assert.equal(rt.full.lastOutcome, 'completed');
});

test('partial results count as a successful run', () => {
  const cfg = config({}, { enabled: false });
  const rt = s.reconcile(cfg, {}, at(27, 11));
  run(cfg, rt, at(27, 12), 'partial');
  assert.equal(rt.quick.pending, null);
});

test('user cancellation does not cause an immediate rescan', () => {
  const cfg = config({}, { enabled: false });
  const rt = s.reconcile(cfg, {}, at(27, 11));
  run(cfg, rt, at(27, 12), 'cancelled');
  assert.equal(rt.quick.pending, null);
  assert.equal(s.nextJob(cfg, rt, at(27, 12, 1)), null);
  assert.equal(new Date(rt.quick.next).getTime(), at(28, 12).getTime());
});

test('an interrupted scan is retried soon without counting as a failure', () => {
  const cfg = config({}, { enabled: false });
  const rt = s.reconcile(cfg, {}, at(27, 11));
  run(cfg, rt, at(27, 12), 'interrupted');
  assert.equal(rt.quick.pending.attempts, 0);
  assert.equal(minutes(at(27, 12), rt.quick.pending.retryAfter), 2);
});

test('both overdue: the full scan runs first and satisfies the quick occurrence', () => {
  const cfg = config();
  const rt = s.reconcile(cfg, {}, at(20, 13)); // quick next 21 12:00, full next 27 18:00
  const now = at(28, 9); // the PC was off for a week
  const job = run(cfg, rt, now, 'completed');
  assert.equal(job.scheduleId, 'full');
  assert.equal(rt.full.pending, null);
  assert.equal(rt.quick.pending, null);
  assert.equal(rt.quick.lastOutcome, 'covered');
  assert.equal(s.nextJob(cfg, rt, now), null);
});

test('a failed full scan does not cover the quick occurrence', () => {
  const cfg = config();
  const rt = s.reconcile(cfg, {}, at(20, 13));
  run(cfg, rt, at(28, 9), 'error');
  const next = s.nextJob(cfg, rt, at(28, 9));
  assert.equal(next.scheduleId, 'quick');
});

test('many missed occurrences collapse into a single pending run', () => {
  const cfg = config({}, { enabled: false });
  const rt = s.reconcile(cfg, {}, at(1, 13));
  s.advance(cfg, rt, at(20, 9));
  assert.ok(rt.quick.pending);
  assert.equal(new Date(rt.quick.next).getTime(), at(20, 12).getTime());
  assert.equal(run(cfg, rt, at(20, 9), 'completed').scheduleId, 'quick');
  assert.equal(s.nextJob(cfg, rt, at(20, 9)), null);
});

test('repeated ticks and resume events do not duplicate a job', () => {
  const cfg = config({}, { enabled: false });
  const rt = s.reconcile(cfg, {}, at(27, 11));
  s.advance(cfg, rt, at(27, 12));
  s.advance(cfg, rt, at(27, 12, 0));
  s.advance(cfg, rt, at(27, 12, 1));
  const job = s.nextJob(cfg, rt, at(27, 12, 1));
  assert.equal(job.occurrence, at(27, 12).toISOString());
  job.started = at(27, 12, 1).toISOString();
  s.recordOutcome(rt, job, 'completed', at(27, 13));
  assert.equal(s.nextJob(cfg, rt, at(27, 13)), null);
});

test('an occurrence arriving during a long scan is kept for the next run', () => {
  const cfg = config({}, { enabled: false });
  const rt = s.reconcile(cfg, {}, at(27, 11));
  s.advance(cfg, rt, at(27, 12));
  const job = s.nextJob(cfg, rt, at(27, 12));
  job.started = at(27, 12).toISOString();
  s.advance(cfg, rt, at(28, 12, 5)); // the scan is still running a day later
  s.recordOutcome(rt, job, 'completed', at(28, 13));
  assert.equal(rt.quick.pending.occurrence, at(28, 12).toISOString());
});

test('editing a schedule during a scan re-plans it; the finishing job does not resurrect old work', () => {
  const cfg = config({}, { enabled: false });
  let rt = s.reconcile(cfg, {}, at(27, 11));
  s.advance(cfg, rt, at(27, 12));
  const job = s.nextJob(cfg, rt, at(27, 12));
  job.started = at(27, 12).toISOString();
  rt = s.reconcile(config({ time: '20:00' }, { enabled: false }), rt, at(27, 12, 30));
  assert.equal(rt.quick.pending, null);
  assert.equal(new Date(rt.quick.next).getTime(), at(27, 20).getTime());
  s.recordOutcome(rt, job, 'error', at(27, 12, 45));
  assert.equal(rt.quick.pending, null);
  assert.equal(rt.quick.lastOutcome, 'error');
});

test('disabling a schedule clears pending work; unchanged settings keep an overdue occurrence', () => {
  const cfg = config({}, { enabled: false });
  const rt = s.reconcile(cfg, {}, at(27, 11));
  s.advance(cfg, rt, at(27, 12));
  assert.ok(s.reconcile(cfg, rt, at(27, 13)).quick.pending);
  const off = s.reconcile(config({ enabled: false }, { enabled: false }), rt, at(27, 13));
  assert.equal(off.quick.pending, null);
  assert.equal(off.quick.next, null);
  assert.equal(s.nextJob(config({ enabled: false }, { enabled: false }), off, at(27, 13)), null);
});

test('a planned run migrated from version 1.0 is kept even when overdue', () => {
  const cfg = config();
  const rt = s.reconcile(cfg, { quick: { next: '2020-01-01T12:00:00.000Z' } }, at(27, 9));
  assert.equal(rt.quick.next, '2020-01-01T12:00:00.000Z');
  s.advance(cfg, rt, at(27, 9));
  assert.ok(rt.quick.pending);
});

test('upcoming lists a pending retry before the next regular run', () => {
  const cfg = config();
  const rt = s.reconcile(cfg, {}, at(27, 11));
  run(cfg, rt, at(27, 12), 'error');
  const [first] = s.upcoming(cfg, rt, at(27, 12, 1));
  assert.equal(first.id, 'quick');
  assert.equal(first.retry, true);
  assert.equal(first.at, rt.quick.pending.retryAfter);
});
