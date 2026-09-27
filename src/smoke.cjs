// Development-only smoke test, run with `electron . --smoke-test`. Excluded from packaged builds.
const fs = require('node:fs');
const path = require('node:path');

const testRoot = path.join(__dirname, '../test-output');
const write = (name, data) => fs.writeFileSync(path.join(testRoot, name), data);

async function checkRenderer(win) {
  const result = await win.webContents.executeJavaScript(
    `({ title: document.title, bridge: typeof window.sentinel.call, cards: document.querySelectorAll('.card').length, text: document.body.innerText })`
  );
  if (result.bridge !== 'function' || result.cards < 6) throw Error('Dashboard failed to render.');
  write('smoke.json', JSON.stringify(result, null, 2));
  write('dashboard.png', (await win.webContents.capturePage()).toPNG());
  const screens = await win.webContents.executeJavaScript(`(async () => {
    const results = [];
    for (const page of ['scans', 'schedules', 'quarantine', 'activity', 'settings']) {
      document.querySelector('nav [data-value="' + page + '"]').click();
      results.push({ page, heading: document.querySelector('h1')?.textContent });
    }
    const prefs = (await window.sentinel.call('state')).data.settings;
    prefs.notifications = false;
    const saved = await window.sentinel.call('settings', prefs);
    const invalid = await window.sentinel.call('scan', 'injected-type');
    return { results, saved: saved.ok, rejectedInvalidScan: !invalid.ok };
  })()`);
  write('screens.json', JSON.stringify(screens, null, 2));
  if (!screens.saved || !screens.rejectedInvalidScan || screens.results.some(s => !s.heading)) {
    throw Error('Renderer navigation or IPC check failed.');
  }
  console.log('Electron smoke test passed: dashboard, five screens, preferences, and invalid IPC input.');
}

async function capture(win, page, name) {
  await win.webContents.executeJavaScript(`document.querySelector('nav [data-value="${page}"]').click()`);
  await new Promise(resolve => setTimeout(resolve, 300));
  write(name, (await win.webContents.capturePage()).toPNG());
}

async function prepareEngine(app) {
  const source = path.join(testRoot, 'database');
  if (!fs.existsSync(path.join(testRoot, 'engine-path.txt')) || !fs.existsSync(path.join(source, 'main.cvd'))) {
    console.log('Skipped real-engine checks: test-output/engine-path.txt and database/main.cvd are not present.');
    return false;
  }
  app.setEngineDir(fs.readFileSync(path.join(testRoot, 'engine-path.txt'), 'utf8').trim());
  for (const name of ['main.cvd', 'daily.cvd', 'bytecode.cvd'])
    fs.copyFileSync(path.join(source, name), path.join(app.db, name));
  fs.copyFileSync(path.join(testRoot, 'fixture-db/test.hdb'), path.join(app.db, 'test.hdb'));
  await app.detectEngine();
  return true;
}

// Runs real scans when a previously downloaded engine and database are available: a full scan lifecycle
// with a harmless synthetic detection, then a shutdown during a scan, which must be saved as interrupted.
async function checkEngine(app) {
  if (!(await prepareEngine(app))) return;
  await app.scan('custom', [path.join(testRoot, 'fixtures')]);
  const deadline = Date.now() + 180000;
  while (app.isScanning() && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 100));
  const report = app.latestReport();
  const state = app.state();
  const open = state.detections.filter(d => d.status === 'detected');
  if (app.isScanning() || report?.status !== 'completed' || report?.threats.length !== 1 || open.length !== 1)
    throw Error(
      'Actual engine lifecycle check failed: ' + JSON.stringify({ status: report?.status, open: open.length })
    );
  if (state.health.state !== 'problem' || !/detection needs review/.test(state.health.headline))
    throw Error('Health did not report the unresolved detection: ' + state.health.headline);
  console.log(
    'Real ClamAV lifecycle passed: spawn, progress, detection store, health, exit status, and persisted report.'
  );
  write('lifecycle.json', JSON.stringify(report, null, 2));
  await capture(app.win, 'overview', 'dashboard-detection.png');
  await capture(app.win, 'activity', 'activity.png');

  // Quit while a scan is running: the report must be finished as interrupted and written to disk.
  await app.scan('custom', [path.join(testRoot, 'fixtures')]);
  await app.shutdown();
  const interrupted = app.latestReport();
  const saved = JSON.parse(fs.readFileSync(path.join(path.dirname(app.db), 'history.json'), 'utf8')).data[0];
  const jobs = JSON.parse(fs.readFileSync(path.join(path.dirname(app.db), 'jobs.json'), 'utf8')).data;
  const journals = fs.readdirSync(path.join(path.dirname(app.db), 'journal'));
  if (interrupted.status !== 'interrupted' || saved.id !== interrupted.id || jobs.current !== null || journals.length)
    throw Error(
      'Shutdown during a scan was not recorded: ' +
        JSON.stringify({ status: interrupted.status, job: jobs.current, journals })
    );
  console.log('Shutdown during a scan passed: the scan was stopped and saved as interrupted.');
}

// First launch of the crash scenario: start a real scan; main exits abruptly once a detection is journaled.
async function crashStart(app) {
  if (!(await prepareEngine(app))) return;
  await app.scan('custom', [path.join(testRoot, 'fixtures')]);
  await new Promise(resolve => setTimeout(resolve, 180000));
  throw Error('The crash scenario did not reach a journaled detection.');
}

// Second launch: startup recovery must have turned the journal into an interrupted report with the detection.
async function crashRecover(app) {
  const state = app.state();
  const report = state.history[0];
  const journals = fs.readdirSync(path.join(path.dirname(app.db), 'journal'));
  const open = state.detections.filter(d => d.status === 'detected');
  if (report?.status !== 'interrupted' || report.threats.length !== 1 || open.length !== 1 || journals.length)
    throw Error(
      'Crash recovery failed: ' +
        JSON.stringify({ status: report?.status, threats: report?.threats.length, open: open.length, journals })
    );
  console.log('Crash recovery passed: a detection journaled before an abrupt exit was recovered on restart.');
}

module.exports = function runSmokeTest(win, app) {
  setTimeout(async () => {
    try {
      fs.mkdirSync(testRoot, { recursive: true });
      if (app.mode === 'fail') throw Error('Intentional smoke failure (verifies nonzero exit).');
      if (app.mode === 'crash-start') return await crashStart(app);
      if (app.mode === 'crash-recover') return await crashRecover(app);
      await checkRenderer(win);
      await checkEngine(app);
    } catch (err) {
      console.error(err);
      process.exitCode = 1;
    } finally {
      app.quit(process.exitCode || 0);
    }
  }, 1800);
};
