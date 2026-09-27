const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { assess, classifyUpdateFailure } = require('../src/health.cjs');
const { parseHeader, inspect, verify } = require('../src/database.cjs');

const now = new Date('2026-09-27T12:00:00Z');
function healthy(overrides = {}) {
  return {
    now,
    busy: { scanning: false, updating: false, installing: false },
    engine: { installed: true, runnable: true, version: 'ClamAV 1.5.4' },
    database: {
      present: true,
      missing: [],
      version: 28136,
      buildTime: '2026-09-27T06:26:00.000Z',
      verified: true,
      failures: []
    },
    settings: { autoUpdate: true, staleAfterDays: 3 },
    updates: { lastCheck: '2026-09-27T11:00:00.000Z', failures: 0 },
    upcoming: [{ id: 'quick', at: '2026-09-27T16:00:00.000Z', retry: false }],
    pendingRetries: [],
    lastSuccessfulScan: { id: 'r1', status: 'completed' },
    lastScan: { id: 'r1', status: 'completed' },
    unresolved: 0,
    quarantineReview: 0,
    storageIssues: 0,
    ...overrides
  };
}
const check = (h, id) => h.checks.find(c => c.id === id);

test('reassuring language only when everything is actually in place', () => {
  const h = assess(healthy());
  assert.equal(h.state, 'ok');
  assert.match(h.headline, /Scheduled scanning is on/);
  assert.equal(h.nextScan.id, 'quick');
});

test('disabled schedules are reported as paused, not covered', () => {
  const h = assess(healthy({ upcoming: [] }));
  assert.equal(h.state, 'attention');
  assert.equal(check(h, 'schedule').status, 'off');
  assert.match(h.headline, /paused/);
  assert.doesNotMatch(h.headline, /covered|on and/);
});

test('disabled updates are called out', () => {
  const h = assess(healthy({ settings: { autoUpdate: false, staleAfterDays: 3 } }));
  assert.equal(check(h, 'updates').status, 'off');
  assert.equal(h.state, 'attention');
});

test('a database that fails verification or loading is a problem', () => {
  const corrupt = assess(healthy({ database: { ...healthy().database, verified: false, failures: ['daily.cvd'] } }));
  assert.equal(corrupt.state, 'problem');
  assert.match(check(corrupt, 'database').detail, /daily.cvd/);
  const unloadable = assess(healthy({ database: { ...healthy().database, loadFailed: true } }));
  assert.equal(check(unloadable, 'database').status, 'error');
});

test('an old database is outdated, based on its build time rather than the last update check', () => {
  const h = assess(
    healthy({
      database: { ...healthy().database, buildTime: '2026-09-20T06:00:00.000Z' },
      updates: { lastCheck: '2026-09-27T11:59:00.000Z', failures: 0 }
    })
  );
  assert.equal(check(h, 'database').status, 'warn');
  assert.match(check(h, 'database').label, /7 days old/);
});

test('the staleness threshold is configurable', () => {
  const database = { ...healthy().database, buildTime: '2026-09-22T12:00:00.000Z' };
  assert.equal(check(assess(healthy({ database })), 'database').status, 'warn');
  assert.equal(
    check(assess(healthy({ database, settings: { autoUpdate: true, staleAfterDays: 7 } })), 'database').status,
    'ok'
  );
});

test('partial initial setup is reported as setup, not as protected', () => {
  const noEngine = assess(healthy({ engine: { installed: false, runnable: false } }));
  assert.equal(noEngine.state, 'setup');
  const noDatabase = assess(healthy({ database: { present: false, missing: ['main', 'daily'], failures: [] } }));
  assert.equal(noDatabase.state, 'setup');
  assert.match(check(noDatabase, 'database').detail, /main, daily/);
  assert.match(check(noDatabase, 'schedule').label, /waiting for setup/);
});

test('repeated update failures show the reason and next attempt', () => {
  const h = assess(
    healthy({
      updates: {
        lastCheck: '2026-09-27T11:00:00.000Z',
        failures: 3,
        failure: { kind: 'dns', message: 'The ClamAV update server could not be found.' },
        nextAttempt: '2026-09-27T13:00:00.000Z'
      }
    })
  );
  assert.equal(check(h, 'updates').status, 'warn');
  assert.match(check(h, 'updates').detail, /could not be found.*2026-09-27T13:00/);
});

test('a failed scheduled scan and unresolved detections are surfaced', () => {
  const h = assess(
    healthy({
      pendingRetries: [{ id: 'full', attempts: 2, retryAfter: '2026-09-27T13:00:00.000Z', lastError: 'Exit 2' }],
      unresolved: 1
    })
  );
  assert.equal(h.state, 'problem');
  assert.equal(h.headline, '1 detection needs review.');
  assert.match(check(h, 'schedule').label, /full scan failed/);
});

test('no successful scan yet is not described as protected', () => {
  const h = assess(healthy({ lastSuccessfulScan: null, lastScan: null }));
  assert.equal(h.state, 'attention');
  assert.equal(check(h, 'scans').status, 'warn');
});

test('the tray tooltip prefers the current operation', () => {
  const h = assess(healthy({ busy: { scanning: true, updating: false, installing: false } }));
  assert.equal(h.tooltip, 'Sentinel AV • Scanning');
});

test('update failures are classified into readable reasons', () => {
  assert.equal(classifyUpdateFailure("ERROR: Can't resolve hostname database.clamav.net").kind, 'dns');
  assert.equal(
    classifyUpdateFailure('WARNING: FreshClam received error code 429 from the ClamAV Content Delivery Network').kind,
    'rate-limit'
  );
  assert.equal(classifyUpdateFailure('', Object.assign(Error('spawn freshclam.exe ENOENT'))).kind, 'missing');
  assert.equal(classifyUpdateFailure('something unexpected').kind, 'other');
});

test('database headers are parsed for version and build time', () => {
  const header = parseHeader('ClamAV-VDB:27 Sep 2026 06-26 +0000:28136:355678:90:X:X:svc:1');
  assert.deepEqual(header, { buildTime: '2026-09-27T06:26:00.000Z', version: 28136, signatures: 355678 });
  assert.equal(parseHeader('garbage'), null);
});

test('inspection reports missing and unreadable databases, and verification uses sigtool output', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-db-'));
  try {
    fs.writeFileSync(path.join(dir, 'daily.cvd'), 'ClamAV-VDB:27 Sep 2026 06-26 +0000:28136:355678:90:x'.padEnd(512));
    let info = inspect(dir);
    assert.equal(info.present, false);
    assert.deepEqual(info.missing, ['main']);
    assert.equal(info.version, 28136);
    fs.writeFileSync(path.join(dir, 'main.cvd'), 'not a database');
    info = inspect(dir);
    assert.equal(info.present, true);
    assert.deepEqual(info.unreadable, ['main.cvd']);
    const result = await verify(info.files, 'sigtool.exe', async (exe, args) =>
      args[0].endsWith('daily.cvd')
        ? 'Verification OK.'
        : "ERROR: cvdinfo: Verification: Can't verify database integrity"
    );
    assert.deepEqual(result, { verified: false, failures: ['main.cvd'] });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---- R01: one capability snapshot drives execution policy and every reassuring statement ----
const { capability } = require('../src/health.cjs');

test('R01: an unverified database never produces an ok state or a "verified" label', () => {
  const pending = assess(healthy({ database: { ...healthy().database, verified: null } }));
  assert.notEqual(pending.state, 'ok');
  assert.doesNotMatch(check(pending, 'database').detail, /\(verified\)/);
});

test('R01: capability and health agree across every engine/database combination', () => {
  const bools = [true, false];
  let combos = 0;
  for (const installed of bools)
    for (const runnable of bools)
      for (const present of bools)
        for (const age of ['fresh', 'stale', 'unknown'])
          for (const verified of [true, false, null])
            for (const unavailable of bools)
              for (const loadFailed of bools) {
                if (runnable && !installed) continue;
                if (verified !== null && unavailable) continue;
                combos++;
                const engine = { installed, runnable, version: 'ClamAV 1.5.4' };
                const database = {
                  present,
                  missing: present ? [] : ['main'],
                  version: 1,
                  buildTime: { fresh: '2026-09-27T06:00:00.000Z', stale: '2026-09-01T06:00:00.000Z', unknown: null }[
                    age
                  ],
                  verified,
                  verifyUnavailable: unavailable,
                  failures: verified === false ? ['daily.cvd'] : [],
                  loadFailed
                };
                const cap = capability({ engine, database, now, settings: { staleAfterDays: 3 } });
                const h = assess(healthy({ engine, database }));
                const label = `${JSON.stringify({ installed, runnable, present, age, verified, unavailable, loadFailed })}`;
                // Execution policy: blocked by anything that makes a scan meaningless or known to fail.
                assert.equal(cap.canScan, runnable && present && verified !== false && !loadFailed, label);
                assert.equal(cap.canScan, cap.blocking.length === 0, label);
                assert.equal(
                  cap.verification,
                  verified === true
                    ? 'verified'
                    : verified === false
                      ? 'failed'
                      : unavailable
                        ? 'unavailable'
                        : 'pending',
                  label
                );
                // Every green statement is justified by the same snapshot.
                if (h.state === 'ok') {
                  assert.ok(cap.canScan && cap.verification === 'verified' && age === 'fresh', label);
                  assert.equal(cap.advisory.length, 0, label);
                }
                if (/\(verified\)/.test(check(h, 'database').detail)) assert.equal(cap.verification, 'verified', label);
                if (!cap.canScan) assert.notEqual(h.state, 'ok', label);
                if (loadFailed && present) assert.equal(check(h, 'database').action, 'recheck', label);
              }
  assert.ok(combos > 100);
});

test('R01: verification pending or unavailable is advisory, stated plainly', () => {
  const base = healthy().database;
  const pending = capability({
    engine: healthy().engine,
    database: { ...base, verified: null },
    now,
    settings: { staleAfterDays: 3 }
  });
  assert.equal(pending.canScan, true);
  assert.deepEqual(pending.advisory, ['verification-pending']);
  const missingTool = assess(healthy({ database: { ...base, verified: null, verifyUnavailable: true } }));
  assert.match(check(missingTool, 'database').label, /cannot be verified/);
});
