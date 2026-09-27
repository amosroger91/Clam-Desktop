const { test } = require('node:test');
const assert = require('node:assert/strict');
const { nextRun, defaults, validateSettings, scanArgs, parseLine } = require('../src/core.cjs');
const { selectAsset } = require('../src/installer.cjs');
test('daily schedule advances at the exact scheduled instant', () => {
  const now = new Date(2026, 8, 27, 12, 0);
  const next = new Date(nextRun({ frequency: 'daily', time: '12:00' }, now));
  assert.equal(next.getDate(), 28);
  assert.equal(next.getHours(), 12);
});
test('weekly schedule uses the next local weekday', () => {
  const next = new Date(nextRun({ frequency: 'weekly', time: '18:00', day: 0 }, new Date(2026, 8, 27, 19)));
  assert.equal(next.getDay(), 0);
  assert.equal(next.getMonth(), 9);
  assert.equal(next.getDate(), 4);
});
test('preferences preserve an overdue schedule until it runs', () => {
  const original = defaults();
  original.schedules[0].next = '2020-01-01T12:00:00Z';
  assert.equal(validateSettings(structuredClone(original), original).schedules[0].next, original.schedules[0].next);
});
test('invalid settings cannot smuggle arguments or malformed schedule values', () => {
  const original = defaults();
  const input = structuredClone(original);
  input.schedules[0].time = '--remove';
  assert.throws(() => validateSettings(input, original));
  input.schedules = [original.schedules[0], original.schedules[0]];
  assert.throws(() => validateSettings(input, original));
});
test('scan arguments use literal target paths and escape excluded folder regexes', () => {
  const s = defaults();
  s.exclusions = ['C:\\Users\\A (test)\\vault'];
  const args = scanArgs(s, 'C:\\database', ['C:\\My files & data']);
  assert.equal(args.at(-1), 'C:\\My files & data');
  const regex = new RegExp(args.find(a => a.startsWith('--exclude-dir=')).slice(14));
  assert.ok(regex.test('C:\\Users\\A (test)\\vault\\file.exe'));
  assert.ok(!regex.test('C:\\Users\\A (test)\\vault-other\\file.exe'));
  assert.ok(!args.some(a => a.startsWith('--remove')));
});
test('scan output handles Windows drive colons and detection names', () => {
  assert.deepEqual(parseLine('C:\\Users\\test.txt: Win.Test.Signature FOUND'), {
    type: 'threat',
    path: 'C:\\Users\\test.txt',
    signature: 'Win.Test.Signature'
  });
  assert.equal(parseLine('Scanned files: 321').count, 321);
  assert.equal(parseLine('WARNING: access denied').type, 'warning');
});
test('file names containing error or warning are not reported as warnings', () => {
  assert.deepEqual(parseLine('Scanning C:\\proj\\node_modules\\x\\errors.js'), {
    type: 'scanning',
    path: 'C:\\proj\\node_modules\\x\\errors.js'
  });
  assert.equal(parseLine('Scanning C:\\Docs\\WARNING letter.pdf').type, 'scanning');
  assert.equal(parseLine('C:\\Docs\\error-report.txt: OK').type, 'file');
  assert.equal(parseLine('C:\\Docs\\ERROR log.txt').type, 'info');
});
test('real clamscan error and warning formats are reported', () => {
  for (const line of [
    'C:\\pagefile.sys: Access denied. ERROR',
    "C:\\locked.db: Can't open file or directory ERROR",
    'LibClamAV Warning: cli_scanxz: decompress failed',
    "LibClamAV Error: cli_scandesc: Can't read file",
    "ERROR: Can't open file C:\\x"
  ])
    assert.equal(parseLine(line).type, 'warning', line);
});
test('installer requires an official architecture-matching asset with a checksum', () => {
  const asset = {
    name: 'clamav.win.x64.zip',
    browser_download_url: 'https://github.com/Cisco-Talos/clamav/releases/download/v1/clamav.zip',
    digest: 'sha256:' + 'a'.repeat(64)
  };
  assert.equal(selectAsset({ assets: [asset] }, 'x64'), asset);
  assert.throws(() => selectAsset({ assets: [{ ...asset, digest: null }] }, 'x64'));
  assert.throws(() =>
    selectAsset({ assets: [{ ...asset, browser_download_url: 'https://evil.example/engine.zip' }] }, 'x64')
  );
  assert.throws(() => selectAsset({ assets: [asset] }, 'arm64'));
});
