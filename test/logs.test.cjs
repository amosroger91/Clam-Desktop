const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { migrateLayout, pruneScanLogs, appendAppError } = require('../src/logs.cjs');

let root;
beforeEach(() => (root = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-logs-'))));
afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

test('R14: report cleanup removes only owned scan logs, never crash diagnostics or journals', () => {
  const kept = crypto.randomUUID(),
    stale = crypto.randomUUID();
  // The 1.x flat layout.
  fs.writeFileSync(path.join(root, kept + '.log'), 'kept');
  fs.writeFileSync(path.join(root, stale + '.log'), 'stale');
  fs.writeFileSync(path.join(root, 'app-errors.log'), 'previous crash');
  fs.writeFileSync(path.join(root, 'notes.log'), 'not ours');
  const dirs = migrateLayout(root);
  migrateLayout(root); // idempotent
  const journal = path.join(root, '..', path.basename(root) + '-journal');
  fs.mkdirSync(journal, { recursive: true });
  fs.writeFileSync(path.join(journal, stale + '.ndjson'), 'evidence');
  appendAppError(dirs.app, 'new crash');

  assert.equal(pruneScanLogs(dirs.scans, [kept]), 1);
  assert.deepEqual(fs.readdirSync(dirs.scans), [kept + '.log']);
  assert.match(fs.readFileSync(path.join(dirs.app, 'errors.log'), 'utf8'), /previous crash[\s\S]*new crash/);
  assert.ok(fs.existsSync(path.join(root, 'notes.log')), 'unrecognized files are left alone');
  assert.ok(fs.existsSync(path.join(journal, stale + '.ndjson')), 'journals are outside log retention');
  fs.rmSync(journal, { recursive: true, force: true });
});

test('R14: the application error log is size-rotated rather than growing or being deleted', () => {
  const app = path.join(root, 'app');
  fs.mkdirSync(app);
  fs.writeFileSync(path.join(app, 'errors.log'), 'x'.repeat(1024 * 1024 + 1));
  appendAppError(app, 'after rotation');
  assert.ok(fs.existsSync(path.join(app, 'errors.1.log')));
  assert.match(fs.readFileSync(path.join(app, 'errors.log'), 'utf8'), /after rotation/);
  assert.equal(appendAppError(path.join(root, 'app', 'errors.log', 'not-a-dir'), 'x'), null, 'never throws');
});
