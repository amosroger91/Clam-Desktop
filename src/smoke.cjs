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

// Runs a real scan when a previously downloaded engine and database are available.
async function checkEngine(app) {
  if (
    !fs.existsSync(path.join(testRoot, 'engine-path.txt')) ||
    !fs.existsSync(path.join(testRoot, 'database/daily.cvd'))
  )
    return;
  app.setEngineDir(fs.readFileSync(path.join(testRoot, 'engine-path.txt'), 'utf8').trim());
  fs.copyFileSync(path.join(testRoot, 'database/daily.cvd'), path.join(app.db, 'daily.cvd'));
  fs.copyFileSync(path.join(testRoot, 'fixture-db/test.hdb'), path.join(app.db, 'test.hdb'));
  await app.detectEngine();
  await app.scan('custom', [path.join(testRoot, 'fixtures')]);
  const deadline = Date.now() + 60000;
  while (app.isScanning() && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 100));
  const report = app.latestReport();
  if (app.isScanning() || report?.status !== 'completed' || report?.threats.length !== 1) {
    throw Error('Actual engine lifecycle check failed.');
  }
  console.log('Real ClamAV lifecycle passed: spawn, progress, detection, exit status, and persisted report.');
  write('lifecycle.json', JSON.stringify(report, null, 2));
}

module.exports = function runSmokeTest(win, app) {
  setTimeout(async () => {
    try {
      fs.mkdirSync(testRoot, { recursive: true });
      await checkRenderer(win);
      await checkEngine(app);
    } catch (err) {
      console.error(err);
      process.exitCode = 1;
    } finally {
      app.quit();
    }
  }, 1800);
};
