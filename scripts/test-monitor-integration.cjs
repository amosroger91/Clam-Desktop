// Actual clamd + Windows filesystem notifications + IPC + process restart. Harmless custom signature.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const { Clamd } = require('../src/clamd.cjs');
const { defaults } = require('../src/monitor-settings.cjs');
const rpc = require('../src/monitor-rpc.cjs');

async function main() {
  const engineDir = fs.readFileSync('test-output/engine-path.txt', 'utf8').trim();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-live-integration-'));
  const watched = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-watched-'));
  const database = path.join(root, 'database');
  fs.mkdirSync(database);
  const sample = Buffer.from('Sentinel monitor synthetic test. This file is harmless.');
  fs.writeFileSync(
    path.join(database, 'test.hdb'),
    crypto.createHash('md5').update(sample).digest('hex') + ':' + sample.length + ':Sentinel.Monitor.Test\n'
  );
  const prefs = { ...defaults(), enabled: true, folders: [watched], pauseOnBattery: false, settleMs: 500 };
  const clamd = new Clamd({
    dir: path.join(root, 'daemon'),
    database,
    engineDir,
    prefs,
    options: { scanArchives: true, detectPUA: false }
  });
  let child,
    output = '';
  const secret = rpc.token(root, true);
  const call = (action, payload) => rpc.request(root, secret, action, payload, 30000);
  const wait = async (fn, label, timeout = 30000) => {
    const end = Date.now() + timeout;
    while (Date.now() < end) {
      try {
        const value = await fn();
        if (value) return value;
      } catch {}
      await new Promise(r => setTimeout(r, 200));
    }
    const state = await call('status').catch(e => ({ error: e.message }));
    throw Error('Timed out: ' + label + '\n' + JSON.stringify(state) + '\n' + output);
  };
  const launch = () => {
    const host = process.env.SENTINEL_TEST_HOST;
    child = spawn(
      host || process.execPath,
      host
        ? [process.execPath, path.resolve('test/fixtures/monitor-agent.cjs'), root, '--console']
        : ['test/fixtures/monitor-agent.cjs', root],
      { windowsHide: true }
    );
    child.stdout.on('data', c => {
      output += c;
    });
    child.stderr.on('data', c => {
      output += c;
    });
  };
  const stop = async () => {
    if (!child || child.exitCode !== null) return;
    const exited = once(child, 'exit');
    await call('stop');
    await exited;
  };
  try {
    const clean = path.join(watched, 'clean.txt');
    fs.writeFileSync(clean, 'Clean text');
    const detected = path.join(watched, 'sample.txt');
    fs.writeFileSync(detected, sample);
    assert.deepEqual(await clamd.scan(clean), { clean: true });
    assert.match((await clamd.scan(detected)).signature, /^Sentinel\.Monitor\.Test/);
    const pid = clamd.proc.pid;
    await clamd.scan(clean);
    assert.equal(clamd.proc.pid, pid, 'engine remains loaded between scans');
    await clamd.stop();
    fs.unlinkSync(detected);
    launch();
    await wait(() => call('status'), 'agent startup');
    await call('configure', {
      prefs,
      engineDir,
      database,
      exclusions: [],
      scanArchives: true,
      detectPUA: false,
      blocked: false
    });
    await wait(async () => (await call('status')).engineReady, 'engine readiness');
    const started = Date.now();
    fs.writeFileSync(detected, sample);
    const found = await wait(async () => {
      const s = await call('status');
      return s.events?.length ? s : null;
    }, 'watched detection');
    const latencyMs = Date.now() - started;
    assert.equal(found.events[0].path, detected);
    const id = found.events[0].id;
    await stop();
    launch();
    await wait(() => call('status'), 'agent restart');
    assert.equal((await call('status')).events[0].id, id, 'unacknowledged event survives restart');
    await call('ack', [id]);
    assert.equal((await call('status')).events.length, 0);
    await call('lease', { id: 'test-maintenance' });
    const paused = await call('status');
    assert.equal(paused.engineReady, false);
    const another = path.join(watched, 'during-pause.txt');
    fs.writeFileSync(another, sample);
    await new Promise(r => setTimeout(r, 700));
    assert.equal((await call('status')).events.length, 0, 'maintenance stops scanning');
    await call('release', 'test-maintenance');
    await wait(async () => (await call('status')).events.some(e => e.path === another), 'queued work after resume');
    await wait(async () => (await call('status')).active === 0, 'queue drain');
    assert.deepEqual(await call('scan', { file: clean, id: crypto.randomUUID() }), { clean: true });
    let hostCrashCleanup = false;
    if (process.env.SENTINEL_TEST_HOST) {
      const beforeCrash = await call('status');
      const expectedEvent = beforeCrash.events[0].id;
      const exited = once(child, 'exit');
      child.kill();
      await exited;
      for (const pid of [beforeCrash.pid, beforeCrash.enginePid])
        await wait(
          () => {
            try {
              process.kill(pid, 0);
              return false;
            } catch {
              return true;
            }
          },
          'job closes child ' + pid,
          10000
        );
      launch();
      await wait(() => call('status'), 'restart after host crash');
      assert.ok((await call('status')).events.some(e => e.id === expectedEvent));
      hostCrashCleanup = true;
    }
    const result = {
      realEngine: true,
      persistentEngine: true,
      watchedDetectionMs: latencyMs,
      restartRecovery: true,
      maintenancePause: true,
      backgroundFileScan: true,
      hostCrashCleanup
    };
    fs.writeFileSync('test-output/monitor-integration.json', JSON.stringify(result, null, 2));
    console.log(result);
  } finally {
    await clamd.stop();
    await stop().catch(() => {
      child?.kill();
    });
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(watched, { recursive: true, force: true });
  }
}
main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
