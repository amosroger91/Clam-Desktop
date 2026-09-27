const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const { createJournal, JournalError } = require('../src/journal.cjs');
const { startScan } = require('../src/scanner.cjs');
const { applyScan } = require('../src/state.cjs');
const scheduler = require('../src/scheduler.cjs');
const { defaults } = require('../src/core.cjs');

let dir;
beforeEach(() => (dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-journal-'))));
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

const now = new Date('2026-09-27T12:00:00.000Z');
const header = (id, extra = {}) => ({ reportId: id, kind: 'custom', started: '2026-09-27T11:00:00.000Z', ...extra });
const emptyState = () => ({
  settings: defaults(),
  reports: [],
  detections: [],
  quarantine: [],
  scheduleRuntime: scheduler.reconcile(defaults().schedules, {}, new Date('2026-09-27T10:00:00.000Z')),
  jobs: { current: null, lastSuccessfulScan: null }
});
function fakeProcess() {
  const proc = new EventEmitter();
  proc.stdout = new PassThrough();
  proc.stderr = new PassThrough();
  proc.kill = () => true;
  return proc;
}
const flush = () => new Promise(resolve => setImmediate(resolve));

test('R06: a detection after the diagnostic log cap is still durably recorded', async () => {
  const journal = createJournal(dir);
  const id = crypto.randomUUID();
  const writer = journal.begin(id, header(id));
  const proc = fakeProcess();
  const scan = startScan({
    exe: 'clamscan.exe',
    args: [],
    logPath: path.join(dir, 'scan.log'),
    spawn: () => proc,
    maxLogBytes: 200,
    onThreat: t => writer.append('detection', { eventId: crypto.randomUUID(), ...t, at: now.toISOString() })
  });
  for (let i = 0; i < 50; i++) proc.stdout.write(`C:\\file${i}.txt: OK\n`);
  proc.stdout.write('C:\\late.exe: Win.Test.Late FOUND\n');
  await flush();
  proc.emit('close', 1);
  const result = await scan.done;
  assert.equal(result.logTruncated, true);
  assert.doesNotMatch(fs.readFileSync(path.join(dir, 'scan.log'), 'utf8'), /late\.exe/);
  // Crash here: nothing was committed, but the journal has the detection.
  const replay = journal.read(id);
  assert.equal(replay.detections.length, 1);
  assert.equal(replay.detections[0].path, 'C:\\late.exe');
});

test('R06: a failed log writer does not affect the evidence journal', async () => {
  const journal = createJournal(dir);
  const id = crypto.randomUUID();
  const writer = journal.begin(id, header(id));
  const proc = fakeProcess();
  const brokenLogFs = {
    ...fs,
    createWriteStream: () => {
      const { Writable } = require('node:stream');
      const w = new Writable({ write: (c, e, cb) => cb(Object.assign(Error('EIO'), { code: 'EIO' })) });
      return w;
    }
  };
  const scan = startScan({
    exe: 'clamscan.exe',
    args: [],
    logPath: path.join(dir, 'scan.log'),
    spawn: () => proc,
    fs: brokenLogFs,
    onThreat: t => writer.append('detection', { eventId: crypto.randomUUID(), ...t, at: now.toISOString() })
  });
  proc.stdout.write('C:\\a.exe: Win.Test FOUND\n');
  await flush();
  proc.emit('close', 1);
  const result = await scan.done;
  assert.ok(result.logError);
  assert.equal(journal.read(id).detections.length, 1);
});

test('R06: crash right after a detection, then replay twice, yields one interrupted report and one sighting', () => {
  const journal = createJournal(dir);
  const id = crypto.randomUUID();
  const writer = journal.begin(
    id,
    header(id, { scheduleId: 'quick', occurrence: '2026-09-27T10:30:00.000Z', exclusions: ['D:\\VMs'] })
  );
  writer.append('targets', { targets: ['C:\\Users\\A\\Downloads'] });
  writer.append('progress', { files: 1200 });
  writer.append('detection', { eventId: 'e1', path: 'C:\\a.exe', signature: 'Win.Test', at: now.toISOString() });
  // Process dies here. On restart the journal is applied twice (the second time simulates a crash
  // after the stores were saved but before the journal was deleted).
  const state = emptyState();
  state.scheduleRuntime.quick.pending = { occurrence: '2026-09-27T10:30:00.000Z', attempts: 0, retryAfter: null };
  const first = applyScan(state, journal.read(id), now);
  const snapshot = structuredClone(state);
  applyScan(state, journal.read(id), now);
  assert.deepEqual(state, snapshot, 'replay is idempotent');
  assert.equal(first.status, 'interrupted');
  assert.equal(first.files, 1200);
  assert.deepEqual(first.exclusions, ['D:\\VMs'], 'the report keeps the scope it ran with');
  assert.equal(state.detections.length, 1);
  assert.equal(state.detections[0].sightings, 1);
  assert.equal(state.reports.length, 1);
  assert.ok(state.scheduleRuntime.quick.pending.retryAfter, 'the scheduled occurrence will be retried');
});

test('R09: a committed journal replayed after partial persistence converges on the uninterrupted result', () => {
  const journal = createJournal(dir);
  const id = crypto.randomUUID();
  const writer = journal.begin(id, header(id, { scheduleId: 'full', occurrence: '2026-09-27T10:00:00.000Z' }));
  writer.append('detection', { eventId: 'e1', path: 'C:\\a.exe', signature: 'Win.Test', at: now.toISOString() });
  writer.append('commit', {
    outcome: {
      status: 'error',
      finished: now.toISOString(),
      exitCode: 2,
      files: 10,
      warnings: [],
      warningCount: 0,
      error: 'exit 2'
    }
  });
  const make = () => {
    const state = emptyState();
    state.scheduleRuntime.full.pending = { occurrence: '2026-09-27T10:00:00.000Z', attempts: 0, retryAfter: null };
    return state;
  };
  const once = make();
  applyScan(once, journal.read(id), now);
  const twice = make();
  applyScan(twice, journal.read(id), now);
  applyScan(twice, journal.read(id), now);
  assert.deepEqual(twice, once);
  assert.equal(once.scheduleRuntime.full.pending.attempts, 1, 'a failure is counted once');
});

test('R09: a stray journal for a report that already finished does not downgrade it', () => {
  const journal = createJournal(dir);
  const id = crypto.randomUUID();
  journal.begin(id, header(id));
  const state = emptyState();
  state.reports.push({ id, kind: 'custom', status: 'completed', started: header(id).started, threats: [] });
  const report = applyScan(state, journal.read(id), now);
  assert.equal(report.status, 'completed');
});

test('journal records are checksummed; a torn final line is ignored', () => {
  const journal = createJournal(dir);
  const id = crypto.randomUUID();
  const writer = journal.begin(id, header(id));
  writer.append('detection', { eventId: 'e1', path: 'C:\\a.exe', signature: 'S', at: now.toISOString() });
  writer.close();
  fs.appendFileSync(path.join(dir, id + '.ndjson'), '{"c":"0000","r":{"seq":3,"type":"detection","path":"C:\\\\b');
  const replay = journal.read(id);
  assert.equal(replay.torn, true);
  assert.equal(replay.detections.length, 1);
});

test('R06: journal write failures are reported, and a scan cannot start without a journal', () => {
  const failing = createJournal(dir, {
    fs: {
      ...fs,
      writeSync: () => {
        throw Object.assign(Error('no space'), { code: 'ENOSPC' });
      }
    }
  });
  assert.throws(() => failing.begin(crypto.randomUUID(), header('x')), JournalError);
  assert.deepEqual(fs.readdirSync(dir), [], 'no half-created journal is left behind');
  assert.throws(() => createJournal(dir).begin('../escape', header('x')), /Invalid scan id/);
});
