const { test } = require('node:test');
const assert = require('node:assert/strict');
const { assessCoverage, coversTargets, classifyWarning } = require('../src/coverage.cjs');

const quick = [
  'C:\\Users\\A\\Desktop',
  'C:\\Users\\A\\Downloads',
  'C:\\Users\\A\\Documents',
  'C:\\Users\\A\\AppData\\Local\\Temp'
];
const full = (extra = {}) => ({
  status: 'partial',
  targets: ['C:\\', 'D:\\'],
  warnings: ['C:\\pagefile.sys: Access denied. ERROR', 'C:\\Windows\\System32\\config\\SAM: Access denied. ERROR'],
  warningCount: 2,
  exclusions: ['C:\\Users\\A\\AppData\\Roaming\\sentinel-av'],
  ...extra
});

test('R03: warnings are classified, and file-level gaps are distinguished from target failures', () => {
  assert.deepEqual(classifyWarning('C:\\pagefile.sys: Access denied. ERROR'), {
    category: 'access',
    path: 'C:\\pagefile.sys'
  });
  assert.deepEqual(classifyWarning("WARNING: C:\\Users\\A\\Downloads: Can't access file"), {
    category: 'access',
    path: 'C:\\Users\\A\\Downloads'
  });
  assert.equal(classifyWarning('LibClamAV Warning: cli_scanxz: decompress failed').category, 'engine');
  assert.equal(classifyWarning('LibClamAV Warning: Heuristics.Limits.Exceeded: max-filesize').category, 'limit');
  const coverage = assessCoverage(
    full({ warnings: [...full().warnings, "WARNING: D:\\: Can't access file"], warningCount: 3 })
  );
  assert.equal(coverage.status, 'incomplete');
  assert.deepEqual(coverage.targetFailures, ['D:\\']);
  assert.equal(assessCoverage(full()).status, 'gaps');
  assert.equal(assessCoverage(full({ status: 'completed', warnings: [], warningCount: 0 })).status, 'complete');
});

test('R03: a partial full scan with gaps only in system files covers the quick folders', () => {
  assert.equal(coversTargets(full(), quick), true);
});

test('R03: a gap inside a quick folder means the quick scan is still owed', () => {
  const report = full({
    warnings: [...full().warnings, 'C:\\Users\\A\\Downloads\\locked.zip: Access denied. ERROR'],
    warningCount: 3
  });
  assert.equal(coversTargets(report, quick), false);
});

test('R03: redirected or network quick folders are not covered by a fixed-drive scan', () => {
  assert.equal(coversTargets(full(), [...quick, '\\\\server\\home\\A\\Documents']), false);
  assert.equal(coversTargets(full({ targets: ['D:\\'] }), quick), false);
});

test('R03: an excluded quick folder is not covered', () => {
  assert.equal(coversTargets(full({ exclusions: ['C:\\Users\\A\\Downloads'] }), quick), false);
  assert.equal(coversTargets(full({ exclusions: ['C:\\Users'] }), quick), false);
});

test('R03: coverage cannot be proven from a truncated warning list, a failed scan, or a failed target', () => {
  assert.equal(coversTargets(full({ warningCount: 5000 }), quick), false);
  assert.equal(coversTargets(full({ status: 'error' }), quick), false);
  assert.equal(coversTargets(full({ warnings: ["WARNING: C:\\: Can't access file"], warningCount: 1 }), quick), false);
});

test('R03: containment is by path segment and case-insensitive', () => {
  assert.equal(coversTargets(full({ targets: ['c:\\users\\a'], warnings: [], warningCount: 0 }), quick), true);
  assert.equal(coversTargets(full({ targets: ['C:\\Users\\Al'], warnings: [], warningCount: 0 }), quick), false);
});

test('R03: an exclusion the quick scan would also apply does not count against coverage', () => {
  const excluded = 'C:\\Users\\A\\Documents\\VM images';
  const report = full({ exclusions: [excluded] });
  assert.equal(coversTargets(report, quick), false, 'strict by default');
  assert.equal(coversTargets(report, quick, { sameExclusions: [excluded] }), true);
});
