const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createCoordinator, CONFLICTS, OperationConflict } = require('../src/operations.cjs');

const TYPES = Object.keys(CONFLICTS);

test('R08: the conflict matrix is symmetric and every pair is enforced', () => {
  for (const a of TYPES)
    for (const b of TYPES) {
      assert.equal(CONFLICTS[a].includes(b), CONFLICTS[b].includes(a), `${a}/${b} must be symmetric`);
      const c = createCoordinator();
      const first = c.begin(a);
      if (CONFLICTS[a].includes(b)) assert.throws(() => c.begin(b), OperationConflict, `${a} blocks ${b}`);
      else assert.doesNotThrow(() => c.begin(b).end(), `${a} allows ${b}`);
      first.end();
    }
});

test('R08: the required policies hold', () => {
  const required = [
    ['scan', 'file'],
    ['scan', 'update'],
    ['update', 'verify'],
    ['install', 'scan'],
    ['file', 'file'],
    ['file', 'identify']
  ];
  for (const [a, b] of required) assert.ok(CONFLICTS[a].includes(b), `${a} must conflict with ${b}`);
  assert.ok(!CONFLICTS.identify.includes('scan'), 'hashing detections may run beside a scan');
});

test('R08: a scan that became due while a confirmation was open blocks the file operation afterwards', () => {
  const c = createCoordinator();
  // The quarantine dialog is open: nothing is held while waiting for the user.
  const scan = c.begin('scan', 'Scheduled quick scan');
  // The user confirms; permission is acquired only now, and is refused with an explanation.
  assert.throws(() => c.begin('file', 'Quarantine file'), /Scheduled quick scan/);
  scan.end();
  assert.doesNotThrow(() => c.begin('file', 'Quarantine file').end());
});

test('R08: once shutdown starts, new work is refused and running work is drained', async () => {
  const c = createCoordinator();
  let release;
  const copying = c.run('file', 'Quarantine file', () => new Promise(resolve => (release = resolve)));
  c.close();
  assert.throws(() => c.begin('scan'), /closing/);
  let drained = false;
  const draining = c.drain(5000).then(remaining => {
    drained = true;
    return remaining;
  });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(drained, false, 'shutdown waits for the file operation');
  release();
  await copying;
  assert.deepEqual(await draining, []);
});

test('R08: drain is bounded and reports what is still running', async () => {
  const c = createCoordinator();
  c.begin('identify', 'Hashing detections');
  const remaining = await c.drain(20);
  assert.deepEqual(
    remaining.map(o => o.type),
    ['identify']
  );
});

test('R08: run() always ends its operation, and tryBegin reports conflicts without throwing', async () => {
  const c = createCoordinator();
  await assert.rejects(
    c.run('update', 'Update', async () => {
      throw Error('boom');
    }),
    /boom/
  );
  assert.deepEqual(c.active(), []);
  const scan = c.begin('scan');
  assert.equal(c.tryBegin('file'), null);
  assert.ok(c.conflictsWith('file'));
  scan.end();
  scan.end(); // idempotent
  assert.equal(c.conflictsWith('file'), null);
});
