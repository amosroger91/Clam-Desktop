// Exercises the shipped RunAsNode runtime and service host against the official database fixtures.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const assert = require('node:assert/strict');
const { createClient } = require('../src/monitor-client.cjs');
const { defaults } = require('../src/monitor-settings.cjs');

async function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-packaged-profile-'));
  const watched = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-packaged-watch-'));
  const dist = path.resolve('release/win-unpacked');
  const client = createClient(root, {
    executable: path.join(dist, 'Sentinel AV.exe'),
    host: path.join(dist, 'resources/monitor/SentinelMonitor.exe'),
    agent: path.join(dist, 'resources/monitor/src/monitor-agent.cjs')
  });
  const deadline = async predicate => {
    for (let i = 0; i < 150; i++) {
      const state = await client.call('status', { idleSeconds: 300 });
      if (predicate(state)) return state;
      if (state.recent?.length) console.log(state.recent[0]);
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    throw Error('Packaged monitor did not reach the expected state');
  };
  let pid;
  try {
    await client.configure({
      engineDir: fs.readFileSync('test-output/engine-path.txt', 'utf8').trim(),
      database: path.resolve('test-output/database'),
      exclusions: [],
      scanArchives: true,
      detectPUA: false,
      blocked: false,
      autoUpdate: false,
      prefs: {
        ...defaults(),
        enabled: true,
        folders: [watched],
        pauseOnBattery: false,
        minFreeMemoryMB: 128,
        maxCpuPercent: 100
      }
    });
    const ready = await deadline(s => s.engineReady);
    pid = ready.pid;
    const clean = path.join(watched, 'clean.txt');
    fs.writeFileSync(clean, 'A harmless packaged-runtime integration test.');
    const checked = await deadline(s => s.metrics.scanned > 0);
    assert.equal(checked.events.length, 0);
    assert.equal(checked.pid, pid);
    assert.ok(checked.resources.freeMB > 0);
    await client.acquire();
    assert.equal((await client.call('status')).engineReady, false);
    await client.release();
    await deadline(s => s.engineReady);
    console.log('Packaged runtime, process job, resource probe, watcher, shared engine, and maintenance lease passed.');
  } finally {
    await client.call('stop').catch(() => {});
    for (let i = 0; pid && i < 50; i++) {
      try {
        process.kill(pid, 0);
      } catch {
        break;
      }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(watched, { recursive: true, force: true });
  }
}
main().catch(err => {
  console.error(err);
  process.exitCode = 1;
});
