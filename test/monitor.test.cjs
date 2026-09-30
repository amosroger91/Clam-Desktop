const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { once } = require('node:events');
const { defaults, validate, resourceReason } = require('../src/monitor-settings.cjs');
const { MonitorQueue } = require('../src/monitor-queue.cjs');
const { command, configText } = require('../src/clamd.cjs');
const rpc = require('../src/monitor-rpc.cjs');
const detections = require('../src/detections.cjs');
const { startDaemonScan } = require('../src/daemon-scan.cjs');
const { queueSpec } = require('../src/monitor-state.cjs');

function fixture(t, options = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-monitor-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  let time = Date.now() + 100000,
    saved;
  const queue = new MonitorQueue({
    prefs: { ...defaults(), enabled: true, highRiskOnly: false, settleMs: 500 },
    folders: [dir],
    exclusions: [],
    scan: async () => ({ clean: true }),
    now: () => time,
    save: state => {
      saved = structuredClone(state);
    },
    ...options
  });
  queue.paused = false;
  const file = (name, body = 'harmless') => {
    const target = path.join(dir, name);
    fs.writeFileSync(target, body);
    return target;
  };
  const drain = async () => {
    time += 1000;
    await queue.pump();
    await Promise.all([...queue.running.values()].map(r => r.task));
  };
  return {
    queue,
    file,
    drain,
    dir,
    advance: ms => {
      time += ms;
    },
    saved: () => saved
  };
}

test('monitor settings reject unbounded resource budgets and non-local roots', () => {
  const prefs = { ...defaults(), folders: ['C:\\Downloads', 'c:\\Downloads'] };
  assert.equal(validate(prefs).folders.length, 1);
  for (const patch of [
    { concurrency: 5 },
    { maxQueue: 100000 },
    { maxFileMB: 0 },
    { folders: ['\\\\server\\share'] },
    { folders: ['C:\\safe\nInjected yes'] },
    { idleOnly: 'yes' }
  ])
    assert.throws(() => validate({ ...prefs, ...patch }));
});

test('queue state validation preserves valid events and flags corrupted evidence', () => {
  const result = queueSpec.validate({ pending: [{ path: 'relative' }], outbox: [{ id: 'bad', path: 'C:\\a' }] });
  assert.equal(result.problems.length, 2);
  assert.equal(result.value.outbox.length, 0);
});

test('directory adapter awaits durable detections, excludes folders, and records incomplete scans', async t => {
  const f = fixture(t),
    found = [];
  f.file('clean.txt');
  f.file('detected.txt');
  f.file('unreadable.txt');
  const excluded = path.join(f.dir, 'excluded');
  fs.mkdirSync(excluded);
  fs.writeFileSync(path.join(excluded, 'ignore'), 'ignore');
  const client = {
    call: async (_action, { file }) => {
      if (file.endsWith('unreadable.txt')) throw Error('File is locked');
      return file.endsWith('detected.txt') ? { clean: false, signature: 'Test' } : { clean: true };
    }
  };
  const logDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-daemon-log-'));
  t.after(() => fs.rmSync(logDir, { recursive: true, force: true }));
  const scan = startDaemonScan({
    targets: [f.dir],
    exclusions: [excluded],
    client,
    logPath: path.join(logDir, 'scan.log'),
    onProgress: () => {},
    onThreat: async event => {
      await new Promise(r => setTimeout(r, 10));
      found.push(event);
    }
  });
  const result = await scan.done;
  assert.equal(result.files, 2);
  assert.equal(result.warningCount, 1);
  assert.equal(found.length, 1);
  assert.match(fs.readFileSync(path.join(logDir, 'scan.log'), 'utf8'), /Test FOUND/);
});

test('directory adapter stops on resource unavailability instead of skipping an entire tree', async t => {
  const f = fixture(t);
  f.file('one');
  f.file('two');
  let requests = 0;
  const scan = startDaemonScan({
    targets: [f.dir],
    exclusions: [],
    logPath: path.join(f.dir, 'scan.log'),
    onProgress: () => {},
    onThreat: () => {},
    client: {
      call: async () => {
        requests++;
        throw Object.assign(Error('Paused on battery'), { code: 'SCANNER_UNAVAILABLE' });
      }
    }
  });
  const result = await scan.done;
  assert.equal(requests, 1);
  assert.equal(result.exitCode, 2);
  assert.match(result.error, /battery/);
});

test('resource policy pauses for memory, battery, idle, unknown sessions, and timed pauses', () => {
  const prefs = { ...defaults(), enabled: true };
  const resources = { freeMB: 2048, battery: false, idleSeconds: 300 };
  assert.equal(resourceReason(prefs, resources), null);
  assert.match(resourceReason(prefs, { ...resources, freeMB: 100 }), /memory/);
  assert.match(resourceReason(prefs, { ...resources, cpuPercent: 95 }), /CPU/);
  assert.match(resourceReason(prefs, { ...resources, battery: true }), /battery/);
  assert.match(resourceReason(prefs, { ...resources, battery: null }), /power/);
  assert.match(resourceReason({ ...prefs, idleOnly: true }, { ...resources, sessionKnown: false }), /idle/);
  assert.match(
    resourceReason({ ...prefs, pauseUntil: new Date(Date.now() + 60000).toISOString() }, resources),
    /Paused/
  );
  assert.equal(resourceReason({ ...prefs, pauseUntil: '2000-01-01T00:00:00Z' }, resources), null);
});

test('duplicate notifications coalesce and changed files precede reconciliation work', async t => {
  const seen = [];
  const f = fixture(t, {
    scan: async file => {
      seen.push(path.basename(file));
      return { clean: true };
    }
  });
  const old = f.file('old.txt'),
    fresh = f.file('new.txt');
  f.queue.enqueue(old);
  f.queue.enqueue(fresh, 1);
  f.queue.enqueue(fresh, 1);
  assert.equal(f.queue.pending.size, 2);
  await f.drain();
  await f.drain();
  assert.deepEqual(seen, ['new.txt', 'old.txt']);
  await f.queue.consider(fresh);
  assert.equal(f.queue.pending.size, 0, 'unchanged files are cached');
  f.queue.databaseVersion = 'new definitions';
  await f.queue.consider(fresh);
  assert.equal(f.queue.pending.size, 1, 'new definitions invalidate clean cache');
});

test('notifications arriving during a scan remain queued', async t => {
  let unblock, entered;
  const started = new Promise(resolve => {
    entered = resolve;
  });
  const f = fixture(t, {
    scan: async () => {
      entered();
      await new Promise(resolve => {
        unblock = resolve;
      });
      return { clean: true };
    }
  });
  const file = f.file('changing.txt');
  f.queue.enqueue(file);
  f.advance(1000);
  await f.queue.pump();
  await started;
  f.queue.enqueue(file, 1);
  unblock();
  await Promise.all([...f.queue.running.values()].map(r => r.task));
  assert.equal(f.queue.pending.size, 1);
});

test('mutated files never enter the clean cache', async t => {
  const f = fixture(t, {
    scan: async file => {
      fs.appendFileSync(file, 'changed');
      return { clean: true };
    }
  });
  f.queue.enqueue(f.file('changing.txt'));
  await f.drain();
  assert.equal(f.queue.pending.size, 1);
  assert.equal(f.queue.cache.size, 0);
  assert.match(f.queue.recent[0].message, /changed/);
});

test('detections survive restart until acknowledged', async t => {
  const f = fixture(t, { scan: async () => ({ clean: false, signature: 'Sentinel.Test' }) });
  f.queue.enqueue(f.file('fixture.txt'));
  await f.drain();
  const saved = f.saved();
  assert.equal(saved.pending.length, 0);
  assert.equal(saved.outbox.length, 1);
  const replay = new MonitorQueue({ prefs: defaults(), folders: [f.dir], exclusions: [], state: saved });
  assert.deepEqual(replay.outbox, saved.outbox);
  replay.acknowledge([saved.outbox[0].id]);
  assert.equal(replay.outbox.length, 0);
});

test('queue overflow is bounded and requests reconciliation', t => {
  const f = fixture(t);
  f.queue.prefs.maxQueue = 2;
  f.queue.enqueue(f.file('a'));
  f.queue.enqueue(f.file('b'));
  assert.equal(f.queue.enqueue(f.file('c')), false);
  assert.equal(f.queue.pending.size, 2);
  assert.equal(f.queue.reconcileNeeded, true);
  assert.equal(f.queue.metrics.overflows, 1);
});

test('scan errors retry, disappeared files leave the queue, and exclusions have path boundaries', async t => {
  const f = fixture(t, {
    scan: async () => {
      throw Error('sharing violation');
    }
  });
  const file = f.file('locked');
  f.queue.enqueue(file);
  await f.drain();
  assert.equal(f.queue.pending.size, 1);
  assert.equal(f.queue.metrics.errors, 1);
  fs.unlinkSync(file);
  f.advance(100000);
  await f.drain();
  assert.equal(f.queue.pending.size, 0);
  f.queue.exclusions = [path.join(f.dir, 'vault')];
  assert.equal(f.queue.allowed(path.join(f.dir, 'vault', 'sample')), false);
  assert.equal(f.queue.allowed(path.join(f.dir, 'vault-other', 'sample')), true);
  assert.equal(f.queue.allowed(path.join(f.dir, '..', 'elsewhere')), false);
});

test('file-size limits are visible skips, not clean verdicts', async t => {
  let scans = 0;
  const f = fixture(t, {
    scan: async () => {
      scans++;
      return { clean: true };
    }
  });
  f.queue.prefs.maxFileMB = 0;
  f.queue.enqueue(f.file('large'));
  await f.drain();
  assert.equal(scans, 0);
  assert.equal(f.queue.metrics.skipped, 1);
  assert.equal(f.queue.metrics.scanned, 0);
});

test('pausing cancels active work but preserves it for resume', async t => {
  let entered;
  const started = new Promise(resolve => {
    entered = resolve;
  });
  const f = fixture(t, {
    scan: (_file, { signal }) =>
      new Promise((_resolve, reject) => {
        entered();
        signal.addEventListener('abort', () => reject(Error('cancelled')), { once: true });
      })
  });
  f.queue.enqueue(f.file('a'));
  f.advance(1000);
  await f.queue.pump();
  await started;
  await f.queue.pause();
  assert.equal(f.queue.pending.size, 1);
  assert.equal(f.queue.running.size, 0);
});

test('live detection replay does not reopen an already quarantined detection', () => {
  const list = [],
    event = { id: 'event', path: 'C:\\a', signature: 'Test', reportId: 'report', at: new Date().toISOString() };
  const d = detections.observe(list, event);
  detections.transition(d, 'quarantined', event.at, 'quarantine');
  assert.equal(detections.observe(list, event), d);
  assert.equal(list.length, 1);
  assert.equal(d.status, 'quarantined');
});

test('daemon configuration constrains memory amplification and rejects directive injection', () => {
  const text = configText('C:\\definitions', 1234, defaults(), { scanArchives: true, detectPUA: false });
  assert.match(text, /TCPAddr 127\.0\.0\.1/);
  assert.match(text, /ConcurrentDatabaseReload no/);
  assert.match(text, /AlertExceedsMax yes/);
  assert.throws(() => configText('C:\\defs\nTCPAddr 0.0.0.0', 1234, defaults(), {}));
});

test('clamd protocol assembles split responses and fails closed on timeout or incomplete replies', async t => {
  let mode = 'split';
  const server = net.createServer(socket => {
    socket.on('error', () => {});
    socket.on('data', () => {
      if (mode === 'split') {
        socket.write('PO');
        setTimeout(() => socket.end('NG\0'), 10);
      }
      if (mode === 'short') socket.end('PO');
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => server.close());
  const port = server.address().port;
  assert.equal(await command(port, 'PING'), 'PONG');
  mode = 'short';
  await assert.rejects(command(port, 'PING'), /complete result/);
  mode = 'silent';
  await assert.rejects(command(port, 'PING', { timeout: 30 }), /timed out/);
});

test('monitor RPC authenticates, rejects unknown actions, and bounds requests', async t => {
  const f = fixture(t),
    secret = rpc.token(f.dir, true);
  const server = rpc.server(f.dir, secret, action => {
    if (action === 'status') return { alive: true };
    throw Error('Unknown action');
  });
  server.listen(rpc.address(f.dir));
  await once(server, 'listening');
  t.after(() => new Promise(resolve => server.close(resolve)));
  assert.deepEqual(await rpc.request(f.dir, secret, 'status'), { alive: true });
  await assert.rejects(rpc.request(f.dir, '0'.repeat(64), 'status'), /Unauthorized/);
  await assert.rejects(rpc.request(f.dir, secret, 'execute'), /Unknown action/);
});
