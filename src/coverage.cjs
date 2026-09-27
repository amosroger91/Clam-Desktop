// Scan coverage evidence (R03, Q4). Separates "the scan process finished" from "these locations were
// inspected". ClamAV does not report per-file coverage, so conclusions are drawn only from the targets it
// was given, the exclusions in force, and the warnings it emitted, and never beyond what they support.
const path = require('node:path');

const norm = p =>
  path.win32
    .resolve(p)
    .toLowerCase()
    .replace(/[\\/]+$/, '');
// True when `child` is `parent` or inside it (by path segment, case-insensitively, as on Windows).
function within(child, parent) {
  const c = norm(child),
    p = norm(parent);
  return c === p || c.startsWith(p.endsWith('\\') ? p : p + '\\');
}

// Classifies one ClamAV warning line. `path` is set when the warning names a file or folder.
function classifyWarning(line) {
  const text = String(line).trim();
  if (/^LibClamAV (Error|Warning)/i.test(text)) {
    if (/Limits|exceeds? (the )?max|max-?(file)?size|max-?scansize|max-?recursion|max-?files/i.test(text))
      return { category: 'limit', path: null };
    return { category: 'engine', path: null };
  }
  const named = /^(?:WARNING: |ERROR: )?(.+?): (.+)$/.exec(text);
  if (named && /^([a-z]:[\\/]|[\\/]{2})/i.test(named[1])) {
    const category = /Access denied|Can't (open|access|read)|Permission denied|ERROR$/i.test(named[2])
      ? 'access'
      : 'other';
    return { category, path: named[1] };
  }
  return { category: 'other', path: null };
}

/**
 * report: { status, targets, warnings, warningCount }
 * Returns { status: 'complete' | 'gaps' | 'incomplete' | 'failed', targetFailures, categories, warningsTruncated }
 *   complete    the process finished and reported no warnings
 *   gaps        finished, but some files could not be read or hit limits (listed in the report)
 *   incomplete  at least one requested location could not be scanned at all
 *   failed      the scan did not finish
 */
function assessCoverage(report) {
  const categories = { access: 0, limit: 0, engine: 0, other: 0 };
  const targetFailures = [];
  for (const warning of report.warnings || []) {
    const { category, path: file } = classifyWarning(warning);
    categories[category]++;
    if (file && category === 'access')
      for (const target of report.targets || []) if (norm(file) === norm(target)) targetFailures.push(target);
  }
  const warningsTruncated = (report.warningCount ?? 0) > (report.warnings || []).length;
  let status;
  if (!['completed', 'partial'].includes(report.status)) status = 'failed';
  else if (targetFailures.length) status = 'incomplete';
  else if ((report.warningCount ?? 0) > 0) status = 'gaps';
  else status = 'complete';
  return { status, targetFailures: [...new Set(targetFailures)], categories, warningsTruncated };
}

// Whether a finished scan demonstrably covered every one of `required` locations: each lies inside a
// scanned target, no warning names anything inside it, the warning list is complete, and nothing was
// excluded that the scan being substituted for (`sameExclusions`) would itself have scanned.
function coversTargets(report, required, { sameExclusions = [] } = {}) {
  const coverage = assessCoverage(report);
  if (coverage.status === 'failed' || coverage.status === 'incomplete' || coverage.warningsTruncated) return false;
  const gapPaths = (report.warnings || []).map(w => classifyWarning(w).path).filter(Boolean);
  return required.every(
    location =>
      (report.targets || []).some(target => within(location, target)) &&
      !(report.exclusions || [])
        .filter(excluded => !sameExclusions.some(e => norm(e) === norm(excluded)))
        .some(excluded => within(location, excluded) || within(excluded, location)) &&
      !gapPaths.some(file => within(file, location))
  );
}

module.exports = { assessCoverage, coversTargets, classifyWarning, within };
