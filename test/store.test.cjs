const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createStore, StorageError } = require('../src/store.cjs');
const schemas = require('../src/schemas.cjs');
const detections = require('../src/detections.cjs');

let dir, store;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-store-'));
  store = createStore(dir);
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

const write = (name, value) => fs.writeFileSync(path.join(dir, name + '.json'), value);
const files = () => fs.readdirSync(dir).sort();

// Version 1.0.x files, as written by the released app.
const legacySettings = {
  engineDir: 'C:\\engine',
  launchAtLogin: true,
  notifications: false,
  closeToTray: true,
  autoUpdate: true,
  scanArchives: true,
  detectPUA: false,
  exclusions: ['C:\\Users\\A\\AppData\\Roaming\\sentinel-av'],
  schedules: [
    { id: 'quick', enabled: true, frequency: 'daily', time: '09:30', day: 0, next: '2026-09-27T13:30:00.000Z' },
    { id: 'full', enabled: false, frequency: 'weekly', time: '18:00', day: 3, next: '2026-09-30T22:00:00.000Z' }
  ]
};
const legacyHistory = [
  {
    id: 'r2',
    kind: 'quick',
    scheduled: true,
    started: '2026-09-26T12:00:00.000Z',
    finished: '2026-09-26T12:10:00.000Z',
    status: 'completed',
    files: 10,
    targets: ['C:\\Users\\A\\Downloads'],
    warnings: [],
    threats: [
      { id: 't3', path: 'C:\\Users\\A\\Downloads\\bad.exe', signature: 'Win.Test', status: 'detected' },
      { id: 't4', path: 'C:\\Users\\A\\Downloads\\gone.exe', signature: 'Win.Other', status: 'quarantined' }
    ]
  },
  {
    id: 'r1',
    kind: 'full',
    scheduled: false,
    started: '2026-09-20T12:00:00.000Z',
    finished: '2026-09-20T15:00:00.000Z',
    status: 'partial',
    files: 99,
    targets: ['C:\\'],
    warnings: ['C:\\pagefile.sys: Access denied. ERROR'],
    threats: [{ id: 't1', path: 'c:\\users\\a\\downloads\\BAD.exe', signature: 'Win.Test', status: 'detected' }]
  }
];

test('saves an envelope atomically and keeps the previous version as a backup', () => {
  store.save('settings', { a: 1 }, 1);
  store.save('settings', { a: 2 }, 1);
  const saved = JSON.parse(fs.readFileSync(path.join(dir, 'settings.json'), 'utf8'));
  assert.equal(saved.schema, 1);
  assert.deepEqual(saved.data, { a: 2 });
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(dir, 'settings.json.bak'), 'utf8')).data, { a: 1 });
  assert.deepEqual(files(), ['settings.json', 'settings.json.bak']);
});

test('migrates version 1.0 settings and keeps legacy schedule runs available', () => {
  write('settings', JSON.stringify(legacySettings));
  const { value, issue, legacy, migrated } = store.load('settings', schemas.settings);
  assert.equal(issue, null);
  assert.equal(migrated, true);
  assert.equal(value.engineDir, 'C:\\engine');
  assert.equal(value.notifications, false);
  assert.equal(value.staleAfterDays, 3);
  assert.deepEqual(value.schedules[0], { id: 'quick', enabled: true, frequency: 'daily', time: '09:30', day: 0 });
  assert.equal(value.schedules[1].enabled, false);
  assert.equal(legacy.schedules[0].next, '2026-09-27T13:30:00.000Z');
});

test('an invalid field is replaced individually and the original file is preserved', () => {
  write('settings', JSON.stringify({ schema: 1, data: { ...legacySettings, notifications: 'yes', schedules: [] } }));
  const { value, issue } = store.load('settings', schemas.settings);
  assert.equal(value.engineDir, 'C:\\engine');
  assert.equal(value.notifications, true);
  assert.equal(value.schedules.length, 2);
  assert.match(issue.message, /notifications/);
  assert.ok(fs.existsSync(issue.preservedAs));
});

test('a truncated file falls back to the backup and is preserved for diagnosis', () => {
  store.save('history', [{ ok: 1 }], 1);
  store.save('history', [{ ok: 2 }], 1);
  fs.writeFileSync(path.join(dir, 'history.json'), '{"schema":1,"data":[{"ok"');
  const { value, issue } = store.load('history', { ...schemas.reports, validate: v => ({ value: v, problems: [] }) });
  assert.deepEqual(value, [{ ok: 1 }]);
  assert.match(issue.message, /previous saved copy/);
  assert.match(fs.readFileSync(issue.preservedAs, 'utf8'), /"ok"$/);
});

test('an unreadable file without a backup resets with a visible issue', () => {
  write('settings', 'not json');
  const { value, issue } = store.load('settings', schemas.settings);
  assert.equal(value.autoUpdate, true);
  assert.match(issue.message, /reset to defaults/);
  assert.ok(files().some(f => f.startsWith('settings.json.corrupt-')));
});

test('a file from a newer version is left in place, not overwritten blindly', () => {
  write('settings', JSON.stringify({ schema: 99, data: {} }));
  const { issue, readOnly } = store.load('settings', schemas.settings);
  assert.match(issue.message, /newer version/);
  assert.equal(readOnly, true);
});

test('an abandoned temporary write is discarded in favour of the committed file', () => {
  store.save('updates', { lastCheck: null }, 1);
  write('updates.json', 'partial');
  fs.renameSync(path.join(dir, 'updates.json.json'), path.join(dir, 'updates.json.tmp'));
  const { issue } = store.load('updates', schemas.updates);
  assert.equal(issue, null);
  assert.ok(!fs.existsSync(path.join(dir, 'updates.json.tmp')));
});

test('storage failures raise an actionable error and leave no temporary file', () => {
  const full = createStore(dir, {
    fs: {
      ...fs,
      writeSync: () => {
        throw Object.assign(Error('no space'), { code: 'ENOSPC' });
      }
    }
  });
  assert.throws(
    () => full.save('history', [], 1),
    err => err instanceof StorageError && /disk is full/.test(err.message) && err.code === 'ENOSPC'
  );
  assert.ok(!fs.existsSync(path.join(dir, 'history.json.tmp')));
});

test('invalid report entries are set aside without losing valid ones', () => {
  write('history', JSON.stringify([...legacyHistory, { id: 5, kind: 'nope' }]));
  const { value, issue } = store.load('history', schemas.reports);
  assert.equal(value.length, 2);
  assert.match(issue.message, /report 3/);
  assert.equal(value[0].threats[0].detectionId, 't3');
  assert.equal(value[0].threats[0].status, undefined);
});

test('quarantine records from version 1.0 migrate, keeping pending moves for recovery', () => {
  write(
    'quarantine',
    JSON.stringify([
      {
        id: 't4',
        original: 'C:\\x.exe',
        stored: 'C:\\q\\t4.quarantine',
        signature: 'S',
        date: '2026-09-26T12:00:00.000Z',
        status: 'pending'
      }
    ])
  );
  const { value, issue } = store.load('quarantine', schemas.quarantine);
  assert.equal(issue, null);
  assert.equal(value[0].status, 'prepared');
  assert.equal(value[0].detectionId, 't4');
  assert.equal(value[0].sha256, null);
});

test('version 1.0 update state keeps its last successful update', () => {
  write('updates', JSON.stringify({ lastUpdate: '2026-09-27T01:33:00.000Z' }));
  const { value } = store.load('updates', schemas.updates);
  assert.equal(value.lastSuccess, '2026-09-27T01:33:00.000Z');
  assert.equal(value.failures, 0);
});

test('legacy detections migrate with status, deduplication, and quarantine association', () => {
  const { detections: list, idMap } = detections.migrateLegacy(legacyHistory, '2026-09-27T00:00:00.000Z');
  const open = list.filter(detections.isUnresolved);
  // t1 (older) and t3 are the same file (case-insensitive) and signature.
  assert.equal(open.length, 1);
  assert.equal(open[0].id, 't1');
  assert.equal(open[0].sightings, 2);
  assert.equal(idMap.t3, 't1');
  const quarantined = list.find(d => d.id === 't4');
  assert.equal(quarantined.status, 'quarantined');
  assert.equal(quarantined.quarantineId, 't4');
});

test('an old unresolved detection survives more than 200 later scan reports', () => {
  const list = [];
  const old = detections.observe(list, {
    path: 'C:\\old.exe',
    signature: 'Win.Old',
    reportId: 'r0',
    at: '2026-01-01T00:00:00.000Z'
  });
  let reports = [{ id: 'r0', threats: [{ id: 'x', detectionId: old.id }] }];
  for (let i = 1; i <= 250; i++) {
    const d = detections.observe(list, {
      path: `C:\\f${i}.exe`,
      signature: 'Win.New',
      reportId: 'r' + i,
      at: new Date(2026, 1, 1, 0, i).toISOString()
    });
    detections.transition(d, 'quarantined', d.firstSeen, 'quarantined');
    reports = [{ id: 'r' + i, threats: [] }, ...reports].slice(0, 200);
  }
  assert.ok(!reports.some(r => r.id === 'r0'));
  const pruned = detections.prune(list, 100);
  assert.ok(pruned.some(d => d.id === old.id && d.status === 'detected'));
  assert.equal(pruned.filter(d => !detections.isUnresolved(d)).length, 100);
});

test('a missing detection returns to detected when seen again', () => {
  const list = [];
  const d = detections.observe(list, {
    path: 'C:\\a.exe',
    signature: 'S',
    reportId: 'r1',
    at: '2026-09-01T00:00:00.000Z'
  });
  detections.transition(d, 'missing', '2026-09-02T00:00:00.000Z', 'missing');
  const again = detections.observe(list, {
    path: 'C:\\A.EXE',
    signature: 'S',
    reportId: 'r2',
    at: '2026-09-03T00:00:00.000Z'
  });
  assert.equal(again, d);
  assert.equal(d.status, 'detected');
  assert.deepEqual(d.reports, ['r2', 'r1']);
  assert.deepEqual(
    d.audit.map(a => a.action),
    ['detected', 'missing', 'seen-again']
  );
});

test('a resolved detection is not reused for a new sighting', () => {
  const list = [];
  const d = detections.observe(list, {
    path: 'C:\\a.exe',
    signature: 'S',
    reportId: 'r1',
    at: '2026-09-01T00:00:00.000Z'
  });
  detections.transition(d, 'restored', '2026-09-02T00:00:00.000Z', 'restored');
  const again = detections.observe(list, {
    path: 'C:\\a.exe',
    signature: 'S',
    reportId: 'r2',
    at: '2026-09-03T00:00:00.000Z'
  });
  assert.notEqual(again, d);
  assert.equal(list.length, 2);
});

// ---- R07: saving recovered state must never destroy the only valid generation ----

const plainSpec = { version: 1, fallback: () => null, migrations: {}, validate: v => ({ value: v, problems: [] }) };
// Persistently fails the given operation on the given file, like a disk or lock failure at that step.
function failingFs(op, match) {
  const wrap =
    name =>
    (...args) => {
      if (op === name && String(args[op === 'renameSync' ? 1 : 0]).endsWith(match))
        throw Object.assign(Error(name + ' failed'), { code: 'EPERM' });
      return fs[name](...args);
    };
  return { ...fs, openSync: wrap('openSync'), copyFileSync: wrap('copyFileSync'), renameSync: wrap('renameSync') };
}
function corruptPrimaryWithGoodBackup() {
  store.save('history', ['good'], 1);
  store.save('history', ['good'], 1); // backup now holds ['good'] too
  fs.writeFileSync(path.join(dir, 'history.json'), 'broken');
}

test('R07: recover from backup, then a failed save at any step leaves a valid generation', () => {
  for (const [op, match] of [
    ['openSync', 'history.json.tmp'],
    ['copyFileSync', 'history.json'],
    ['renameSync', 'history.json']
  ]) {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.mkdirSync(dir);
    store = createStore(dir);
    corruptPrimaryWithGoodBackup();
    const recovered = store.load('history', plainSpec);
    assert.deepEqual(recovered.value, ['good']);
    const flaky = createStore(dir, { fs: failingFs(op, match) });
    try {
      flaky.save('history', ['good', 'new'], 1);
    } catch (err) {
      assert.ok(err instanceof StorageError);
    }
    // The known-good backup is never replaced by the corrupt primary.
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(dir, 'history.json.bak'), 'utf8')).data, ['good']);
    // Restarting (twice) always finds a validated generation: the new save if it completed, else the old one.
    for (let i = 0; i < 2; i++) {
      const { value } = createStore(dir).load('history', plainSpec);
      assert.ok(
        JSON.stringify(value) === '["good","new"]' || JSON.stringify(value) === '["good"]',
        `${op}: ${JSON.stringify(value)}`
      );
    }
  }
});

test('R07: a complete new generation whose promotion failed is kept and preferred on restart', () => {
  store.save('history', ['old'], 1);
  const flaky = createStore(dir, { fs: failingFs('renameSync', 'history.json') });
  assert.throws(() => flaky.save('history', ['new'], 1), StorageError);
  assert.ok(fs.existsSync(path.join(dir, 'history.json.tmp')));
  const { value, issue } = createStore(dir).load('history', plainSpec);
  assert.deepEqual(value, ['new']);
  assert.match(issue.message, /latest save/);
});

test('R07: a partially written temporary file is discarded', () => {
  store.save('history', ['old'], 1);
  fs.writeFileSync(path.join(dir, 'history.json.tmp'), '{"schema":1,"savedAt":"2099');
  const { value, issue } = createStore(dir).load('history', plainSpec);
  assert.deepEqual(value, ['old']);
  assert.equal(issue, null);
  assert.ok(!fs.existsSync(path.join(dir, 'history.json.tmp')));
});

test('R07: a file from a newer version is read-only and never overwritten', () => {
  const newer = JSON.stringify({ schema: 99, savedAt: '2027-01-01T00:00:00.000Z', data: { future: true } });
  fs.writeFileSync(path.join(dir, 'settings.json'), newer);
  const s = createStore(dir);
  const { issue, readOnly } = s.load('settings', schemas.settings);
  assert.equal(readOnly, true);
  assert.match(issue.message, /newer version/);
  assert.throws(
    () => s.save('settings', {}, 1),
    err => err instanceof StorageError && err.code === 'EREADONLY'
  );
  assert.equal(fs.readFileSync(path.join(dir, 'settings.json'), 'utf8'), newer);
});
