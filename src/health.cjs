// One health model for the dashboard, tray, and notifications. Every reassuring statement must be backed by
// verified state: an enabled schedule, verified and fresh definitions, and a successful scan.
// Times in check details are ISO strings; the renderer formats them in the user's locale.
const DAY = 86400000;

const LEVEL = { ok: 0, off: 1, warn: 1, error: 2 };

/**
 * The single engine capability snapshot. Execution (IPC, scheduler, tray) and every status surface
 * derive from this, so what the app says and what it will do cannot disagree.
 *
 * Policy: scans are blocked when the engine cannot run, the database is missing, ClamAV's signature
 * check failed, or ClamAV failed to load this database. Verification that is still pending, or
 * unavailable because the installation has no sigtool, does not block scanning (a successful scan is
 * itself evidence the database loads), but it is reported as an advisory and never described as verified.
 */
function capability({ engine, database, now, settings }) {
  const verification =
    database.verified === true
      ? 'verified'
      : database.verified === false
        ? 'failed'
        : database.verifyUnavailable
          ? 'unavailable'
          : 'pending';
  const blocking = [];
  if (!engine.installed) blocking.push('engine-missing');
  else if (!engine.runnable) blocking.push('engine-not-runnable');
  if (!database.present) blocking.push('database-missing');
  else {
    if (verification === 'failed') blocking.push('database-invalid');
    if (database.loadFailed) blocking.push('database-load-failed');
  }
  const advisory = [];
  if (database.present && verification === 'pending') advisory.push('verification-pending');
  if (database.present && verification === 'unavailable') advisory.push('verification-unavailable');
  const ageDays = database.buildTime ? (now - new Date(database.buildTime)) / DAY : null;
  if (database.present && ageDays === null) advisory.push('definitions-date-unknown');
  else if (database.present && ageDays > settings.staleAfterDays) advisory.push('definitions-outdated');
  return {
    canScan: blocking.length === 0,
    canUpdate: !!engine.installed,
    verification,
    blocking,
    advisory,
    ageDays
  };
}

/**
 * input: {
 *   now, busy: { scanning, updating, installing },
 *   engine: { installed, runnable, version, error },
 *   database: { present, missing, version, buildTime, verified (true|false|null), verifyUnavailable, failures, loadFailed },
 *   settings: { autoUpdate, staleAfterDays },
 *   updates: { lastCheck, lastSuccess, failure, failures, nextAttempt },
 *   upcoming: [{ id, at, retry }], pendingRetries: [{ id, attempts, retryAfter, lastError }],
 *   lastSuccessfulScan, lastScan, unresolved, quarantineReview, storageIssues
 * }
 */
function assess(input) {
  const { now, engine, database, settings, updates } = input;
  const cap = capability({ engine, database, now, settings });
  const checks = [];
  const add = (id, status, label, detail = '', action = null) => checks.push({ id, status, label, detail, action });

  // Engine
  if (!engine.installed) add('engine', 'error', 'ClamAV is not installed', '', 'settings');
  else if (!engine.runnable)
    add('engine', 'error', 'ClamAV could not start', engine.error || 'The scanner did not respond.', 'settings');
  else add('engine', 'ok', 'Scan engine ready', engine.version || '');

  // Definitions: blocking problems first, then advisories, and "current" only when verified.
  const built = database.buildTime ? `Version ${database.version}, built ${database.buildTime}.` : '';
  if (!database.present)
    add('database', 'error', 'Signature database is missing', 'Missing: ' + database.missing.join(', '), 'settings');
  else if (cap.blocking.includes('database-load-failed'))
    add(
      'database',
      'error',
      'ClamAV could not load the signature database',
      'The last scan failed while loading definitions. Scheduled scans are paused until the database is rechecked or updated.',
      'recheck'
    );
  else if (cap.verification === 'failed')
    add(
      'database',
      'error',
      'Signature database failed verification',
      'Could not verify: ' + database.failures.join(', ') + '. Update the definitions to replace them.',
      'update'
    );
  else if (cap.advisory.includes('definitions-date-unknown'))
    add('database', 'warn', 'Definition date unknown', 'The database header could not be read.', 'update');
  else if (cap.advisory.includes('definitions-outdated'))
    add(
      'database',
      'warn',
      `Definitions are ${Math.floor(cap.ageDays)} days old`,
      `Built ${database.buildTime}. Definitions older than ${settings.staleAfterDays} days are considered outdated.`,
      'update'
    );
  else if (cap.verification === 'unavailable')
    add(
      'database',
      'warn',
      'Definitions cannot be verified',
      built + ' This ClamAV installation has no sigtool.exe, so signatures cannot be checked.',
      'recheck'
    );
  else if (cap.verification === 'pending')
    add('database', 'warn', 'Definitions not yet verified', built + ' Verification is in progress.', 'recheck');
  else add('database', 'ok', 'Definitions are current', built.replace(/\.$/, '') + ' (verified)');

  // Updates
  if (!settings.autoUpdate) add('updates', 'off', 'Automatic definition updates are off', '', 'settings');
  else if (updates.failures > 0)
    add(
      'updates',
      'warn',
      'Definition updates are failing',
      (updates.failure?.message || 'The last update attempt failed.') +
        (updates.nextAttempt ? ` Next attempt ${updates.nextAttempt}.` : ''),
      'update'
    );
  else add('updates', 'ok', 'Automatic updates on', updates.lastCheck ? `Last checked ${updates.lastCheck}` : '');

  // Schedules
  const retries = input.pendingRetries.filter(p => p.attempts > 0);
  if (!input.upcoming.length)
    add('schedule', 'off', 'Scheduled scans are paused', 'No schedule is enabled.', 'schedules');
  else if (!cap.canScan)
    add(
      'schedule',
      'warn',
      engine.runnable && database.present
        ? 'Scheduled scans are paused by a database problem'
        : 'Scheduled scans are waiting for setup',
      'They will run once ClamAV and its definitions are ready.',
      engine.runnable && database.present ? 'recheck' : 'settings'
    );
  else if (retries.length)
    add(
      'schedule',
      'warn',
      `A scheduled ${retries[0].id} scan failed`,
      `${retries[0].lastError || 'It did not complete.'} Retrying ${retries[0].retryAfter}.`,
      'schedules'
    );
  else add('schedule', 'ok', 'Scheduled scanning on', `Next: ${input.upcoming[0].id} scan ${input.upcoming[0].at}`);

  // Results
  if (input.unresolved > 0)
    add(
      'detections',
      'error',
      `${input.unresolved} detection${input.unresolved === 1 ? '' : 's'} need${input.unresolved === 1 ? 's' : ''} review`,
      '',
      'activity'
    );
  if (!input.lastSuccessfulScan)
    add('scans', 'warn', 'No completed scan yet', 'Run a quick scan to establish a baseline.', 'scans');
  else if (
    input.lastScan &&
    !['completed', 'partial'].includes(input.lastScan.status) &&
    input.lastScan.status !== 'cancelled'
  )
    add(
      'scans',
      'warn',
      `The last scan ${input.lastScan.status === 'error' ? 'failed' : 'was interrupted'}`,
      '',
      'activity'
    );
  if (input.quarantineReview > 0) add('quarantine', 'warn', 'A quarantine operation needs review', '', 'quarantine');
  if (input.storageIssues > 0) add('storage', 'warn', 'Some saved data needed recovery', '', 'settings');

  const worst = checks.reduce((max, c) => Math.max(max, LEVEL[c.status]), 0);
  const first = status => checks.find(c => c.status === status);
  let state, headline;
  if (!engine.installed || !database.present) {
    state = 'setup';
    headline = 'Finish setting up ClamAV to start scanning.';
  } else if (worst === 2) {
    state = 'problem';
    headline = first('error').label + '.';
  } else if (worst === 1) {
    state = 'attention';
    headline = (first('warn') || first('off')).label + '.';
  } else {
    state = 'ok';
    headline = 'Scheduled scanning is on and definitions are current.';
  }
  const busy = input.busy.installing
    ? 'Installing ClamAV'
    : input.busy.updating
      ? 'Updating definitions'
      : input.busy.scanning
        ? 'Scanning'
        : null;
  return {
    state,
    headline,
    capability: cap,
    checks,
    nextScan: input.upcoming[0] || null,
    lastSuccessfulScan: input.lastSuccessfulScan || null,
    busy,
    tooltip: 'Sentinel AV • ' + (busy || headline.replace(/\.$/, ''))
  };
}

// Classifies a failed FreshClam run from its output, for readable messages and retry decisions.
function classifyUpdateFailure(output, error) {
  const text = `${output}\n${error?.message || ''}`;
  const kinds = [
    [
      'rate-limit',
      /cool-?down|429|rate limit|too many requests/i,
      'The ClamAV update service asked Sentinel to wait before retrying.'
    ],
    [
      'dns',
      /resolve|getaddrinfo|ENOTFOUND|EAI_AGAIN/i,
      'The ClamAV update server could not be found. Check your internet connection.'
    ],
    [
      'network',
      /Can't connect|connection|timed? ?out|ECONNRESET|ETIMEDOUT|ECONNREFUSED|download failed/i,
      'Could not connect to the ClamAV update service.'
    ],
    [
      'disk',
      /ENOSPC|No space|disk full|Can't (write|create)/i,
      'Definitions could not be saved. Check free disk space.'
    ],
    [
      'integrity',
      /verif|signature|corrupt|malformed|Database load/i,
      'Downloaded definitions failed verification and were not used.'
    ],
    ['missing', /ENOENT|missing/i, 'The FreshClam updater is missing from the ClamAV installation.']
  ];
  for (const [kind, pattern, message] of kinds) if (pattern.test(text)) return { kind, message };
  return { kind: 'other', message: 'The definition update failed. See the update log for details.' };
}

module.exports = { assess, capability, classifyUpdateFailure };
