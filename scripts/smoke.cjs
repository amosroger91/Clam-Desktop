// Runs every Electron smoke scenario and fails if any does. Scenarios:
//   standard       renderer, IPC validation, real scan lifecycle, shutdown during a scan
//   crash          a launch that dies abruptly after a detection is journaled, then a recovering launch
//   fail           an intentionally failing run, which must exit nonzero (proves failures propagate)
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const electron = require('electron');

const env = { ...process.env };
delete env.ELECTRON_RUN_AS_NODE;
function launch(mode, extraEnv = {}) {
  const arg = mode === 'standard' ? '--smoke-test' : '--smoke-test=' + mode;
  const result = spawnSync(electron, ['.', arg], {
    cwd: path.join(__dirname, '..'),
    env: { ...env, ...extraEnv },
    encoding: 'utf8',
    timeout: 600000
  });
  const lines = `${result.stdout}\n${result.stderr}`.split(/\r?\n/).filter(l => /passed|Skipped|Error|failed/.test(l));
  return { status: result.status, lines };
}

const failures = [];
const check = (name, ok, lines) => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  for (const line of lines) console.log('      ' + line.trim());
  if (!ok) failures.push(name);
};

const standard = launch('standard');
check('standard scenario', standard.status === 0, standard.lines);

const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-crash-'));
try {
  const start = launch('crash-start', { SENTINEL_SMOKE_PROFILE: profile });
  const skipped = start.lines.some(l => l.includes('Skipped'));
  if (skipped) check('crash scenario (skipped: no engine fixtures)', true, start.lines);
  else {
    const journals = fs.readdirSync(path.join(profile, 'journal'));
    check('crash: abrupt exit leaves a journal', start.status === 0 && journals.length === 1, start.lines);
    const recover = launch('crash-recover', { SENTINEL_SMOKE_PROFILE: profile });
    check('crash: next launch recovers the detection', recover.status === 0, recover.lines);
  }
} finally {
  fs.rmSync(profile, { recursive: true, force: true });
}

const fatalProfile = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-fatal-'));
try {
  const fatal = launch('fatal', { SENTINEL_SMOKE_PROFILE: fatalProfile });
  const errors = path.join(fatalProfile, 'logs', 'app', 'errors.log');
  const logged = fs.existsSync(errors) && fs.readFileSync(errors, 'utf8').includes('Intentional uncaught fault');
  const marked = fs.existsSync(path.join(fatalProfile, 'crash-state.json'));
  check('an uncaught fault exits nonzero with diagnostics and a crash marker', fatal.status === 1 && logged && marked, [
    `exit status ${fatal.status}, diagnostics ${logged ? 'kept' : 'missing'}, crash marker ${marked ? 'written' : 'missing'}`
  ]);
} finally {
  fs.rmSync(fatalProfile, { recursive: true, force: true });
}

const failing = launch('fail');
check('an intentionally failing scenario exits nonzero', failing.status !== 0, [`exit status ${failing.status}`]);

if (failures.length) {
  console.error(`\n${failures.length} smoke scenario(s) failed.`);
  process.exit(1);
}
console.log('\nAll smoke scenarios passed.');
