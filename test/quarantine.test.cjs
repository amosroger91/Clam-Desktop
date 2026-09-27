const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { createQuarantine } = require('../src/quarantine.cjs');

let dir, vault, docs;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-q-'));
  vault = path.join(dir, 'vault');
  docs = path.join(dir, 'docs');
  fs.mkdirSync(vault);
  fs.mkdirSync(docs);
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

const sha = text => crypto.createHash('sha256').update(text).digest('hex');
const read = p => fs.readFileSync(p, 'utf8');

// A harness whose "disk" is the last persisted snapshot, so a simulated crash can be recovered by a fresh
// instance exactly as the app would after restarting.
function harness({ crashAt, fsImpl = fs, failPersist = 0 } = {}) {
  const h = { records: [], disk: [], detections: {}, persistCalls: 0 };
  h.make = (options = {}) =>
    createQuarantine({
      vault,
      records: h.records,
      fs: options.fs || fsImpl,
      persist: () => {
        if (++h.persistCalls <= failPersist) throw Object.assign(Error('disk full'), { code: 'ENOSPC' });
        h.disk = structuredClone(h.records);
      },
      onDetection: (id, status) => (h.detections[id] = status),
      fault: step => {
        if (step === (options.crashAt ?? crashAt)) throw Object.assign(Error('crash at ' + step), { reason: 'fault' });
      }
    });
  h.restart = () => {
    h.records = structuredClone(h.disk);
    return h.make({ crashAt: null });
  };
  return h;
}

function detected(name, content = 'suspicious ' + name) {
  const file = path.join(docs, name);
  fs.writeFileSync(file, content);
  return { id: 'det-' + name, path: file, signature: 'Test.Sig', sha256: sha(content) };
}

// Simulates a different volume: moving into the vault fails with EXDEV, so the copy path is used.
const crossVolumeFs = {
  ...fs,
  promises: {
    ...fs.promises,
    rename: async (from, to) => {
      if (to.endsWith('.quarantine') && !from.endsWith('.partial'))
        throw Object.assign(Error('cross-device'), { code: 'EXDEV' });
      return fs.promises.rename(from, to);
    }
  }
};

test('quarantine moves the file and records its hash', async () => {
  const h = harness();
  const d = detected('a.exe');
  const r = await h.make().quarantine(d);
  assert.equal(r.status, 'quarantined');
  assert.equal(r.sha256, d.sha256);
  assert.equal(r.size, 'suspicious a.exe'.length);
  assert.ok(!Number.isNaN(Date.parse(r.modified)));
  assert.ok(!fs.existsSync(d.path));
  assert.equal(read(r.stored), 'suspicious a.exe');
  assert.equal(h.detections[d.id], 'quarantined');
  assert.equal(h.disk[0].status, 'quarantined');
});

test('a file that changed since detection is not quarantined', async () => {
  const h = harness();
  const d = detected('b.exe');
  fs.writeFileSync(d.path, 'now different');
  await assert.rejects(h.make().quarantine(d), /changed since it was detected/);
  assert.ok(fs.existsSync(d.path));
  assert.equal(h.records.length, 0);
});

test('a metadata write failure before the move leaves the file untouched', async () => {
  const h = harness({ failPersist: 1 });
  const d = detected('c.exe');
  await assert.rejects(h.make().quarantine(d), /disk full/);
  assert.equal(read(d.path), 'suspicious c.exe');
  assert.equal(h.records.length, 0);
  assert.deepEqual(fs.readdirSync(vault), []);
});

test('crash before the move: recovery reports the file was left in place', async () => {
  const h = harness({ crashAt: 'prepared' });
  const d = detected('d.exe');
  await assert.rejects(h.make().quarantine(d), /crash/);
  const [r] = await h.restart().recover();
  assert.equal(r.status, 'failed');
  assert.equal(read(d.path), 'suspicious d.exe');
  assert.equal(h.detections[d.id], 'detected');
});

test('move completed before metadata commit: recovery completes the record', async () => {
  const h = harness({ crashAt: 'moved' });
  const d = detected('e.exe');
  await assert.rejects(h.make().quarantine(d), /crash/);
  assert.equal(h.disk[0].status, 'prepared');
  const [r] = await h.restart().recover();
  assert.equal(r.status, 'quarantined');
  assert.equal(h.detections[d.id], 'quarantined');
});

test('replacement file at the original path: nothing is deleted', async () => {
  const h = harness({ crashAt: 'moved' });
  const d = detected('f.exe');
  await assert.rejects(h.make().quarantine(d), /crash/);
  fs.writeFileSync(d.path, 'a different, legitimate file');
  const [r] = await h.restart().recover();
  assert.equal(r.status, 'quarantined');
  assert.match(r.issue, /different file now exists/);
  assert.equal(read(r.stored), 'suspicious f.exe');
  assert.equal(read(d.path), 'a different, legitimate file');
});

test('missing original parent folder after the move is handled', async () => {
  const h = harness({ crashAt: 'moved' });
  const d = detected('g.exe');
  await assert.rejects(h.make().quarantine(d), /crash/);
  fs.rmSync(docs, { recursive: true });
  const q = h.restart();
  const [r] = await q.recover();
  assert.equal(r.status, 'quarantined');
  // Restore recreates the missing folder.
  const restored = await q.restore(r.id);
  assert.equal(restored.status, 'restored');
  assert.equal(read(d.path), 'suspicious g.exe');
});

test('cross-volume copy verifies content before removing the original', async () => {
  const h = harness({ fsImpl: crossVolumeFs });
  const d = detected('h.exe');
  const r = await h.make().quarantine(d);
  assert.equal(r.status, 'quarantined');
  assert.ok(!fs.existsSync(d.path));
  assert.equal(read(r.stored), 'suspicious h.exe');
  assert.ok(!fs.existsSync(r.stored + '.partial'));
});

test('partial copy with the original intact: the incomplete copy is removed', async () => {
  const h = harness({ fsImpl: crossVolumeFs, crashAt: 'copied-partial' });
  const d = detected('i.exe');
  await assert.rejects(h.make().quarantine(d), /crash/);
  const partial = h.disk[0].stored + '.partial';
  fs.writeFileSync(partial, 'suspic'); // truncated copy
  const [r] = await h.restart().recover();
  assert.equal(r.status, 'failed');
  assert.ok(!fs.existsSync(partial));
  assert.equal(read(d.path), 'suspicious i.exe');
});

test('partial copy with the original gone: the partial copy is kept for review', async () => {
  const h = harness({ fsImpl: crossVolumeFs, crashAt: 'copied-partial' });
  const d = detected('j.exe');
  await assert.rejects(h.make().quarantine(d), /crash/);
  fs.unlinkSync(d.path);
  const [r] = await h.restart().recover();
  assert.equal(r.status, 'recovery-needed');
  assert.ok(fs.existsSync(h.disk[0].stored + '.partial'));
  assert.deepEqual(r.options, ['dismiss']);
});

test('copy finished but original not removed: user can finish or undo, both verified', async () => {
  for (const action of ['finish', 'undo']) {
    const h = harness({ fsImpl: crossVolumeFs, crashAt: 'copied' });
    const d = detected('k-' + action + '.exe');
    await assert.rejects(h.make().quarantine(d), /crash/);
    const q = h.restart();
    const [r] = await q.recover();
    assert.equal(r.status, 'recovery-needed');
    assert.deepEqual(r.options, ['finish', 'undo']);
    assert.ok(fs.existsSync(r.stored) && fs.existsSync(d.path));
    const done = await q.resolve(r.id, action);
    if (action === 'finish') {
      assert.equal(done.status, 'quarantined');
      assert.ok(!fs.existsSync(d.path) && fs.existsSync(r.stored));
    } else {
      assert.equal(done.status, 'failed');
      assert.ok(fs.existsSync(d.path) && !fs.existsSync(r.stored));
    }
  }
});

test('finish is refused if the files changed after review', async () => {
  const h = harness({ fsImpl: crossVolumeFs, crashAt: 'copied' });
  const d = detected('l.exe');
  await assert.rejects(h.make().quarantine(d), /crash/);
  const q = h.restart();
  const [r] = await q.recover();
  fs.writeFileSync(d.path, 'edited by the user');
  await assert.rejects(q.resolve(r.id, 'finish'), /changed/);
  assert.equal(read(d.path), 'edited by the user');
});

test('legacy records without a hash keep both copies when both exist', async () => {
  const h = harness();
  const d = detected('m.exe');
  const stored = path.join(vault, 'legacy.quarantine');
  fs.copyFileSync(d.path, stored);
  h.disk = [
    {
      id: 'legacy',
      detectionId: d.id,
      original: d.path,
      stored,
      signature: 'Test.Sig',
      sha256: null,
      created: new Date().toISOString(),
      status: 'prepared',
      options: [],
      audit: []
    }
  ];
  const [r] = await h.restart().recover();
  assert.equal(r.status, 'recovery-needed');
  assert.ok(fs.existsSync(stored) && fs.existsSync(d.path));
});

test('recovery is idempotent across repeated restarts', async () => {
  const h = harness({ crashAt: 'moved' });
  const d = detected('n.exe');
  await assert.rejects(h.make().quarantine(d), /crash/);
  await h.restart().recover();
  const snapshot = structuredClone(h.disk);
  const second = await h.restart().recover();
  assert.equal(second.length, 0);
  assert.deepEqual(h.disk, snapshot);
});

test('restore never overwrites an existing file and supports another location', async () => {
  const h = harness();
  const d = detected('o.exe');
  const q = h.make();
  const r = await q.quarantine(d);
  fs.writeFileSync(d.path, 'new file with the same name');
  await assert.rejects(q.restore(r.id), /already exists/);
  assert.equal(read(d.path), 'new file with the same name');
  const elsewhere = path.join(dir, 'restored', 'o.exe');
  const restored = await q.restore(r.id, elsewhere);
  assert.equal(restored.status, 'restored');
  assert.equal(read(elsewhere), 'suspicious o.exe');
  assert.ok(!fs.existsSync(r.stored));
  assert.equal(h.detections[d.id], 'restored');
});

test('interrupted restore recovers to quarantined or restored without losing a copy', async () => {
  for (const [step, expected] of [
    ['restore-copied', 'quarantined'],
    ['restore-linked', 'restored']
  ]) {
    const h = harness();
    const d = detected('p-' + step + '.exe');
    const r = await h.make().quarantine(d);
    await assert.rejects(h.make({ crashAt: step }).restore(r.id), /crash/);
    const [after] = await h.restart().recover();
    assert.equal(after.status, expected);
    const leftovers = fs.readdirSync(docs).filter(n => n.endsWith('.sentinel-restore'));
    assert.deepEqual(leftovers, []);
    if (expected === 'restored') assert.ok(fs.existsSync(d.path) && !fs.existsSync(r.stored));
    else assert.ok(!fs.existsSync(d.path) && fs.existsSync(r.stored));
  }
});

test('a metadata write failure after the move is reported and recovered on restart', async () => {
  const h = harness();
  const d = detected('q.exe');
  // Allow the 'prepared' write, then fail the write that commits the move.
  let calls = 0;
  const failing = createQuarantine({
    vault,
    records: h.records,
    persist: () => {
      if (++calls === 2) throw Object.assign(Error('disk full'), { code: 'ENOSPC' });
      h.disk = structuredClone(h.records);
    }
  });
  const r = await failing.quarantine(d);
  assert.equal(r.status, 'quarantined');
  assert.match(r.saveError, /disk full/);
  assert.equal(h.disk[0].status, 'prepared');
  const [recovered] = await h.restart().recover();
  assert.equal(recovered.status, 'quarantined');
});
