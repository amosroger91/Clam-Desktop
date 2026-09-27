const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createStore } = require('../src/store.cjs');
const { loadState, verifyLinks, storeValue, SPECS, SAVE_ORDER } = require('../src/state.cjs');

const now = new Date('2026-09-27T12:00:00.000Z');
// Version 1.0.x files, as written by the released app.
const legacy = {
  settings: {
    engineDir: 'C:\\engine',
    launchAtLogin: true,
    notifications: true,
    closeToTray: true,
    autoUpdate: true,
    scanArchives: true,
    detectPUA: false,
    exclusions: [],
    schedules: [
      { id: 'quick', enabled: true, frequency: 'daily', time: '12:00', day: 0, next: '2026-09-27T17:00:00.000Z' },
      { id: 'full', enabled: true, frequency: 'weekly', time: '18:00', day: 0, next: '2026-09-27T23:00:00.000Z' }
    ]
  },
  history: [
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
      threats: [{ id: 't3', path: 'C:\\Users\\A\\Downloads\\bad.exe', signature: 'Win.Test', status: 'detected' }]
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
      warnings: [],
      threats: [{ id: 't1', path: 'C:\\Users\\A\\Downloads\\bad.exe', signature: 'Win.Test', status: 'detected' }]
    }
  ],
  updates: { lastUpdate: '2026-09-27T01:33:00.000Z' }
};

function legacyDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-migrate-'));
  for (const [name, value] of Object.entries(legacy))
    fs.writeFileSync(path.join(dir, name + '.json'), JSON.stringify(value));
  return dir;
}
// Data only: envelopes carry savedAt timestamps that legitimately differ between runs.
const snapshot = dir =>
  Object.fromEntries(
    Object.keys(SPECS).map(name => [name, JSON.parse(fs.readFileSync(path.join(dir, name + '.json'), 'utf8')).data])
  );
function migrate(dir, stopAfter = SAVE_ORDER.length) {
  const store = createStore(dir, { now: () => now });
  const { state } = loadState(store, { now, dataRoot: 'C:\\data' });
  for (const name of SAVE_ORDER.slice(0, stopAfter)) store.save(name, storeValue(state, name), SPECS[name].version);
}

test('R09.4: a restart after any individual migration save converges on the uninterrupted result', () => {
  const baselineDir = legacyDir();
  migrate(baselineDir);
  const expected = snapshot(baselineDir);
  assert.equal(expected.detections.length, 1);
  assert.equal(expected.history[0].threats[0].detectionId, 't1');
  for (let stop = 0; stop < SAVE_ORDER.length; stop++) {
    const dir = legacyDir();
    migrate(dir, stop); // crash after `stop` files were saved
    migrate(dir); // restart
    migrate(dir); // and again
    assert.deepEqual(snapshot(dir), expected, `interrupted after ${SAVE_ORDER.slice(0, stop).join(', ') || 'nothing'}`);
    fs.rmSync(dir, { recursive: true, force: true });
  }
  fs.rmSync(baselineDir, { recursive: true, force: true });
});

test('R09.5: a report threat whose detection is missing is reopened for review; other breaks are reported', () => {
  const state = {
    reports: [
      {
        id: 'r1',
        started: '2026-09-27T10:00:00.000Z',
        finished: '2026-09-27T10:05:00.000Z',
        threats: [{ id: 't1', path: 'C:\\a.exe', signature: 'S', detectionId: 'lost' }]
      }
    ],
    detections: [
      {
        id: 'd2',
        path: 'C:\\b.exe',
        signature: 'S',
        status: 'quarantined',
        quarantineId: 'gone',
        reports: [],
        audit: [],
        sightings: 1
      }
    ],
    quarantine: [{ id: 'q9', detectionId: 'nobody', signature: 'S' }]
  };
  const { repaired, ambiguous } = verifyLinks(state);
  assert.equal(repaired, 1);
  const reopened = state.detections.find(d => d.id === state.reports[0].threats[0].detectionId);
  assert.equal(reopened.status, 'detected');
  assert.equal(ambiguous.length, 2);
  assert.equal(verifyLinks(state).repaired, 0, 'repair is idempotent');
});
