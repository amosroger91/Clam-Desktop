const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { AnalysisPipeline, peFindings } = require('../src/analysis-tools.cjs');
const { highRisk, MonitorQueue } = require('../src/monitor-queue.cjs');
const { defaults, validate } = require('../src/monitor-settings.cjs');
const { findings } = require('../src/behavior.cjs');
const { createRuleFeed } = require('../src/rule-feed.cjs');

test('high-risk filter handles case, installers and scripts without scanning arbitrary text', () => {
  for (const file of ['setup.EXE', 'installer.msi', 'archive.zip', 'run.bat', 'run.ps1', 'script.js'])
    assert.ok(highRisk(file));
  for (const file of ['document.txt', 'payload.exe.download', 'picture.png']) assert.equal(highRisk(file), false);
  assert.throws(() => validate({ ...defaults(), autoQuarantine: 'yes' }));
});
test('community rules cannot authorize automatic quarantine and retain author attribution', async () => {
  const p = new AnalysisPipeline({
    prefs: { yaraEnabled: true },
    clam: { scan: async () => ({ clean: true, sha256: 'a'.repeat(64) }) },
    rules: { active: () => ({ path: 'rules.yarc', version: 'abc' }) },
    run: async () =>
      JSON.stringify({
        matches: [{ rule: 'Suspicious', meta: { author: 'Rule Author', action: 'quarantine', confidence: 100 } }]
      })
  });
  const r = await p.scan('file.exe');
  assert.equal(r.action, 'review');
  assert.match(r.signature, /Rule Author/);
  assert.equal(r.clean, false);
});
test('YARA errors and missing rules never become clean verdicts', async () => {
  const p = new AnalysisPipeline({
    prefs: { yaraEnabled: true },
    clam: { scan: async () => ({ clean: true }) },
    rules: { active: () => null }
  });
  await assert.rejects(p.scan('file.exe'), /no validated rules/);
  p.rules.active = () => ({ path: 'rules' });
  p.run = async () => '{}';
  await assert.rejects(p.scan('file.exe'), /Invalid YARA/);
});
test('ClamAV malware is quarantine eligible; PUA and heuristic verdicts require review', async () => {
  for (const [signature, action] of [
    ['Win.Test', 'quarantine'],
    ['PUA.Tool', 'review'],
    ['Heuristics.Test', 'review']
  ]) {
    const p = new AnalysisPipeline({ prefs: {}, clam: { scan: async () => ({ clean: false, signature }) } });
    assert.equal((await p.scan('file.exe')).action, action);
  }
});
test('PE anomalies require combinations and never call them malware', () => {
  assert.deepEqual(peFindings({ sections: [{ name: '.text', perm: '-r-x' }] }), []);
  assert.equal(peFindings({ imports: [{ name: 'WriteProcessMemory' }] }).length, 0);
  assert.equal(
    peFindings({
      sections: [{ name: 'UPX0', perm: '-rwx' }],
      imports: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'].map(name => ({ name }))
    }).length,
    3
  );
});
test('behavior correlates parent/child and does not label ordinary shells as attacks', () => {
  const rows = [
    { pid: '1', name: 'winword.exe' },
    { pid: '2', parent: '1', name: 'powershell.exe' },
    { pid: '3', parent: '9', name: 'cmd.exe' }
  ];
  assert.deepEqual(
    findings(rows).map(r => r.pid),
    ['2']
  );
});
test('automatic quarantine observes a durable outbox and a hash of the scanned bytes', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-layer-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const file = path.join(root, 'test.exe');
  fs.writeFileSync(file, 'harmless');
  let saved,
    callback = false;
  const queue = new MonitorQueue({
    prefs: { ...defaults(), settleMs: 0 },
    folders: [root],
    exclusions: [],
    scan: async () => ({ clean: false, signature: 'Test', sha256: 'a'.repeat(64), action: 'quarantine' }),
    save: s => {
      saved = structuredClone(s);
    },
    onThreat: async e => {
      assert.equal(saved.outbox[0].id, e.id);
      assert.equal(e.sha256, 'a'.repeat(64));
      callback = true;
    }
  });
  queue.paused = false;
  queue.enqueue(file);
  await queue.pump();
  await Promise.all([...queue.running.values()].map(r => r.task));
  assert.ok(callback);
  assert.equal(saved.outbox.length, 1);
});
test('tampered compiled feed is not accepted at startup', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-feed-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const version = 'a'.repeat(40);
  fs.mkdirSync(path.join(root, version));
  fs.writeFileSync(path.join(root, version, 'rules.yarc'), 'tampered');
  require('../src/store.cjs')
    .createStore(root)
    .save('active', { version, digest: 'b'.repeat(64) }, 1);
  const feed = createRuleFeed(root, null);
  assert.equal(feed.active(), null);
  assert.match(feed.status().error, /integrity/);
});
