const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const detections = require('../src/detections.cjs');
const { identify } = require('../src/files.cjs');
const { createQuarantine } = require('../src/quarantine.cjs');

const sighting = (reportId, at, file = 'C:\\x\\a.exe') => ({ path: file, signature: 'Test.Sig', reportId, at });

test('R02: a new sighting invalidates stale identity and keeps the old revision as history', () => {
  const list = [];
  const d = detections.observe(list, sighting('r1', '2026-09-01T00:00:00.000Z'));
  detections.recordIdentity(d, { sha256: 'a'.repeat(64), size: 10 }, '2026-09-01T00:01:00.000Z');
  d.identifyError = 'EBUSY';
  detections.observe(list, sighting('r2', '2026-09-02T00:00:00.000Z'));
  assert.equal(d.sha256, null, 'identity must be re-established for the new sighting');
  assert.equal(d.identifyError, undefined, 'a transient identity failure is retried on a new sighting');
  assert.deepEqual(d.revisions[0], {
    sha256: 'a'.repeat(64),
    size: 10,
    identifiedAt: '2026-09-01T00:01:00.000Z',
    reportId: 'r1'
  });
});

test('R02: replaying the same scan does not add a sighting or discard identity', () => {
  const list = [];
  const d = detections.observe(list, sighting('r1', '2026-09-01T00:00:00.000Z'));
  detections.recordIdentity(d, { sha256: 'a'.repeat(64), size: 10 }, '2026-09-01T00:01:00.000Z');
  detections.observe(list, sighting('r1', '2026-09-01T00:00:00.000Z'));
  assert.equal(d.sightings, 1);
  assert.equal(d.sha256, 'a'.repeat(64));
});

test('R02: a changed revision is recorded in the audit trail', () => {
  const list = [];
  const d = detections.observe(list, sighting('r1', '2026-09-01T00:00:00.000Z'));
  detections.recordIdentity(d, { sha256: 'a'.repeat(64), size: 10 }, '2026-09-01T00:01:00.000Z');
  detections.observe(list, sighting('r2', '2026-09-02T00:00:00.000Z'));
  detections.recordIdentity(d, { sha256: 'b'.repeat(64), size: 12 }, '2026-09-02T00:01:00.000Z');
  assert.equal(d.audit.at(-1).action, 'content-changed');
  const changes = () => d.audit.filter(a => a.action === 'content-changed').length;
  detections.observe(list, sighting('r3', '2026-09-03T00:00:00.000Z'));
  detections.recordIdentity(d, { sha256: 'b'.repeat(64), size: 12 }, '2026-09-03T00:01:00.000Z');
  assert.equal(changes(), 1, 'unchanged content is not reported as a change');
});

test('R02: detect A, replace with B, rescan, then quarantine B', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-r02-'));
  try {
    const file = path.join(dir, 'sample.exe');
    fs.writeFileSync(file, 'content A');
    const list = [];
    const d = detections.observe(list, sighting('r1', '2026-09-01T00:00:00.000Z', file));
    detections.recordIdentity(d, await identify(file), '2026-09-01T00:01:00.000Z');
    fs.writeFileSync(file, 'content B, still matching the same synthetic signature');
    const records = [];
    const q = createQuarantine({ vault: dir, records, persist: () => {} });
    await assert.rejects(q.quarantine(d), /changed since it was detected/);
    // "Scan it again": the new sighting refreshes identity, and quarantine now acts on B.
    detections.observe(list, sighting('r2', '2026-09-02T00:00:00.000Z', file));
    detections.recordIdentity(d, await identify(file), '2026-09-02T00:01:00.000Z');
    const record = await q.quarantine(d);
    assert.equal(record.status, 'quarantined');
    assert.equal(fs.readFileSync(record.stored, 'utf8'), 'content B, still matching the same synthetic signature');
    assert.equal(d.revisions.length, 1, 'the history of content A is preserved');
    assert.deepEqual(d.reports, ['r2', 'r1']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
