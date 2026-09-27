// Uses a previously downloaded real ClamAV engine; never uses real malware.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const assert = require('node:assert/strict');
const { defaults, scanArgs, parseLine } = require('../src/core.cjs');
const root = path.resolve('test-output');
const engine = fs.readFileSync(path.join(root, 'engine-path.txt'), 'utf8').trim();
const targets = path.join(root, 'fixtures');
const database = path.join(root, 'fixture-db');
fs.mkdirSync(targets, { recursive: true });
fs.mkdirSync(database, { recursive: true });
const sample = Buffer.from('Sentinel harmless synthetic integration fixture. This is not malware.');
fs.writeFileSync(path.join(targets, 'sample.txt'), sample);
fs.writeFileSync(path.join(targets, 'clean.txt'), 'An ordinary document for the clean scan check.');
fs.writeFileSync(
  path.join(database, 'test.hdb'),
  crypto.createHash('md5').update(sample).digest('hex') + ':' + sample.length + ':Sentinel.Test.Fixture\n'
);
const scan = paths =>
  spawnSync(path.join(engine, 'clamscan.exe'), scanArgs(defaults(), database, paths), {
    encoding: 'utf8',
    windowsHide: true
  });
const found = scan([targets]);
assert.equal(found.status, 1, found.stderr + found.stdout);
const detection = found.stdout
  .split(/\r?\n/)
  .map(parseLine)
  .find(l => l.type === 'threat');
assert.ok(detection.signature.startsWith('Sentinel.Test.Fixture'));
const clean = scan([path.join(targets, 'clean.txt')]);
assert.equal(clean.status, 0, clean.stderr + clean.stdout);
const missing = scan([path.join(targets, 'missing.txt')]);
assert.equal(missing.status, 2);
const result = {
  engine: engine.split(path.sep).at(-1),
  cleanExit: clean.status,
  detectionExit: found.status,
  missingExit: missing.status,
  detection: detection.signature
};
fs.writeFileSync(path.join(root, 'integration.json'), JSON.stringify(result, null, 2));
console.log(result);
