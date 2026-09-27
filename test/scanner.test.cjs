const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const { startScan, reportStatus } = require('../src/scanner.cjs');

let dir;
beforeEach(() => (dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-scan-'))));
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

function fakeProcess({ ignoreKill = false } = {}) {
  const proc = new EventEmitter();
  proc.pid = 4242;
  proc.stdout = new PassThrough();
  proc.stderr = new PassThrough();
  proc.killed = 0;
  proc.kill = () => {
    proc.killed++;
    if (!ignoreKill) setImmediate(() => proc.emit('close', null));
    return true;
  };
  return proc;
}
function start(proc, options = {}) {
  return startScan({
    exe: 'clamscan.exe',
    args: [],
    logPath: path.join(dir, 'scan.log'),
    spawn: () => proc,
    ...options
  });
}
const flush = () => new Promise(resolve => setImmediate(resolve));

test('reports files, detections, and warnings, and resolves after the log is written', async () => {
  const proc = fakeProcess();
  const scan = start(proc);
  proc.stdout.write('Scanning C:\\a.txt\r\nC:\\a.txt: OK\r\nC:\\b.exe: Win.Test FOUND\r\n');
  proc.stdout.write('C:\\locked.db: Access denied. ERROR\r\nScanned files: 3\r\n');
  await flush();
  proc.emit('close', 1);
  const result = await scan.done;
  assert.equal(result.files, 3);
  assert.deepEqual(result.threats, [{ path: 'C:\\b.exe', signature: 'Win.Test' }]);
  assert.equal(result.warningCount, 1);
  assert.equal(reportStatus(result), 'partial');
  assert.match(fs.readFileSync(path.join(dir, 'scan.log'), 'utf8'), /Win.Test FOUND/);
});

test('multi-byte characters split across chunks are preserved', async () => {
  const proc = fakeProcess();
  const scan = start(proc);
  const line = Buffer.from('C:\\Users\\Zoë\\日本語.exe: Win.Test FOUND\n');
  const cut = line.indexOf(Buffer.from('本')) + 1; // split inside a 3-byte character
  proc.stdout.write(line.subarray(0, cut));
  await flush();
  proc.stdout.write(line.subarray(cut));
  await flush();
  proc.emit('close', 1);
  const result = await scan.done;
  assert.equal(result.threats[0].path, 'C:\\Users\\Zoë\\日本語.exe');
});

test('a final line without a newline is still processed', async () => {
  const proc = fakeProcess();
  const scan = start(proc);
  proc.stdout.write('C:\\x.exe: Win.Tail FOUND');
  await flush();
  proc.emit('close', 1);
  assert.equal((await scan.done).threats[0].signature, 'Win.Tail');
});

test('stderr is framed into lines and informational output is not a warning', async () => {
  const proc = fakeProcess();
  const scan = start(proc);
  proc.stderr.write('LibClamAV Warning: cli_scanxz: ');
  proc.stderr.write('decompress failed\nLoading: 3.2M sigs\n');
  await flush();
  proc.emit('close', 0);
  const result = await scan.done;
  assert.deepEqual(result.warnings, ['LibClamAV Warning: cli_scanxz: decompress failed']);
});

test('database load failures are identified', async () => {
  const proc = fakeProcess();
  const scan = start(proc);
  proc.stderr.write('LibClamAV Error: cli_loaddbdir: No supported database files found\n');
  await flush();
  proc.emit('close', 2);
  const result = await scan.done;
  assert.equal(result.databaseError, true);
  assert.equal(reportStatus(result), 'error');
});

test('very long lines are truncated instead of growing without bound', async () => {
  const proc = fakeProcess();
  const scan = start(proc);
  proc.stdout.write('x'.repeat(200000));
  proc.stdout.write(': OK\n');
  await flush();
  proc.emit('close', 0);
  const result = await scan.done;
  assert.equal(result.files, 0); // the truncated line no longer ends in ": OK"
  assert.equal(reportStatus(result), 'completed');
});

test('a failure to spawn completes once with an error', async () => {
  const scan = startScan({
    exe: 'missing.exe',
    args: [],
    logPath: path.join(dir, 'scan.log'),
    spawn: () => {
      throw Object.assign(Error('spawn missing.exe ENOENT'), { code: 'ENOENT' });
    }
  });
  const result = await scan.done;
  assert.match(result.error, /ENOENT/);
  assert.equal(reportStatus(result), 'error');
});

test('error and close together complete exactly once', async () => {
  const proc = fakeProcess();
  let progress = 0;
  const scan = start(proc, { onProgress: () => progress++ });
  proc.emit('error', Error('EPIPE'));
  proc.emit('close', 1);
  proc.emit('close', 0);
  const result = await scan.done;
  assert.equal(result.error, 'EPIPE');
  assert.equal(result.exitCode, null);
  assert.equal(reportStatus(result), 'error');
  assert.equal(result.warnings.filter(w => w === 'EPIPE').length, 1);
});

test('cancellation reports cancelled, and shutdown reports interrupted', async () => {
  for (const [reason, expected] of [
    ['user', 'cancelled'],
    ['shutdown', 'interrupted']
  ]) {
    const proc = fakeProcess();
    const scan = start(proc);
    scan.cancel(reason);
    scan.cancel(reason);
    const result = await scan.done;
    assert.equal(proc.killed, 1);
    assert.equal(reportStatus(result), expected);
  }
});

test('a process that ignores kill is force-terminated by PID', async () => {
  const proc = fakeProcess({ ignoreKill: true });
  const forced = [];
  const scan = start(proc, {
    killTimeoutMs: 20,
    forceKill: pid => {
      forced.push(pid);
      proc.emit('close', null);
    }
  });
  scan.cancel('user');
  const result = await scan.done;
  assert.deepEqual(forced, [4242]);
  assert.equal(reportStatus(result), 'cancelled');
});

test('the log is capped and marked as truncated', async () => {
  const proc = fakeProcess();
  const scan = start(proc, { maxLogBytes: 1000 });
  for (let i = 0; i < 100; i++) proc.stdout.write(`C:\\file${i}.txt: OK\n`);
  await flush();
  proc.emit('close', 0);
  const result = await scan.done;
  assert.equal(result.files, 100);
  assert.equal(result.logTruncated, true);
  const log = fs.readFileSync(path.join(dir, 'scan.log'), 'utf8');
  assert.ok(log.length < 1200);
  assert.match(log, /log truncated/);
});

// A log sink that applies backpressure and can then fail, like a disk that fills up mid-scan.
function stalledLog() {
  const { Writable } = require('node:stream');
  const sink = new Writable({ highWaterMark: 1, write: (chunk, enc, cb) => (sink.pendingCallback = cb) });
  return sink;
}

test('R05: a log failure under backpressure does not leave output paused', async () => {
  for (const code of ['ENOSPC', 'EIO']) {
    const proc = fakeProcess();
    const sink = stalledLog();
    const scan = start(proc, { fs: { ...fs, createWriteStream: () => sink } });
    proc.stdout.write('C:\a.txt: OK\n');
    await flush();
    assert.equal(proc.stdout.isPaused(), true, 'backpressure pauses stdout');
    sink.destroy(Object.assign(Error('write failed'), { code }));
    await flush();
    assert.equal(proc.stdout.isPaused(), false, 'stdout resumes when the log fails');
    proc.stdout.write('C:\b.exe: Win.Test FOUND\n');
    await flush();
    proc.emit('close', 1);
    const result = await scan.done;
    assert.equal(result.threats.length, 1, 'parsing continues without the log');
    assert.match(result.logError, /write failed/);
  }
});

test('R05: stderr pressure pauses stderr, and cancellation resumes paused streams', async () => {
  const proc = fakeProcess();
  const sink = stalledLog();
  const scan = start(proc, { fs: { ...fs, createWriteStream: () => sink } });
  proc.stderr.write('LibClamAV Warning: burst\n');
  await flush();
  assert.equal(proc.stderr.isPaused(), true);
  assert.equal(proc.stdout.isPaused(), false);
  scan.cancel('user');
  assert.equal(proc.stderr.isPaused(), false);
  await scan.done;
});

test('R05: the log closing before drain resumes output', async () => {
  const proc = fakeProcess();
  const sink = stalledLog();
  const scan = start(proc, { fs: { ...fs, createWriteStream: () => sink } });
  proc.stdout.write('C:\a.txt: OK\n');
  await flush();
  sink.destroy();
  await flush();
  assert.equal(proc.stdout.isPaused(), false);
  proc.emit('close', 0);
  await scan.done;
});
