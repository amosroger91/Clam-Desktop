// Schemas, validation, and migrations for every persisted file. Validation is per field or per entry:
// one bad value is replaced or set aside without discarding the rest of the file.
const { defaults } = require('./core.cjs');

const T = {
  str: v => typeof v === 'string',
  optStr: v => v == null || typeof v === 'string',
  bool: v => typeof v === 'boolean',
  date: v => typeof v === 'string' && !Number.isNaN(Date.parse(v)),
  optDate: v => v == null || (typeof v === 'string' && !Number.isNaN(Date.parse(v))),
  count: v => Number.isInteger(v) && v >= 0,
  optCount: v => v == null || (Number.isInteger(v) && v >= 0),
  strArray: v => Array.isArray(v) && v.every(x => typeof x === 'string'),
  array: v => Array.isArray(v),
  optArray: v => v == null || Array.isArray(v),
  oneOf:
    (...values) =>
    v =>
      values.includes(v),
  // A SHA-256 hex digest, or null when not yet known.
  sha: v => v == null || (typeof v === 'string' && /^[a-f0-9]{64}$/.test(v)),
  uuid: v => typeof v === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v),
  // Absolute drive or UNC paths; device namespaces (\\?\, \\.\) and control characters are rejected.
  winPath: v =>
    typeof v === 'string' &&
    v.length < 32768 &&
    /^([a-z]:[\\/]|[\\/]{2}[^\\/?.])/i.test(v) &&
    !/[\u0000-\u001f]/.test(v),
  audit: v =>
    Array.isArray(v) &&
    v.length <= 1000 &&
    v.every(
      e => e && typeof e === 'object' && typeof e.action === 'string' && (e.at == null || typeof e.at === 'string')
    )
};

function invalidField(obj, shape) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return 'entry';
  for (const [key, test] of Object.entries(shape)) if (!test(obj[key])) return key;
  return null;
}

function validList(list, shape, label, normalize = x => x) {
  if (!Array.isArray(list)) return { value: [], problems: [`the ${label} list was not a list`] };
  const value = [],
    problems = [];
  list.forEach((item, i) => {
    const bad = invalidField(item, shape);
    if (bad) problems.push(`${label} ${i + 1} had an invalid ${bad}`);
    else value.push(normalize(item));
  });
  return { value, problems };
}

// ---- Settings ----

const BOOLEAN_SETTINGS = ['launchAtLogin', 'notifications', 'closeToTray', 'autoUpdate', 'scanArchives', 'detectPUA'];
const SCHEDULE_SHAPE = {
  enabled: T.bool,
  frequency: T.oneOf('daily', 'weekly'),
  time: v => typeof v === 'string' && /^([01]\d|2[0-3]):[0-5]\d$/.test(v),
  day: v => Number.isInteger(v) && v >= 0 && v <= 6
};

const settings = {
  version: 1,
  fallback: defaults,
  migrations: {
    // v0 stored each schedule's next run inside settings; runtime state now lives in schedule.json.
    0: d => ({ ...d, schedules: Array.isArray(d?.schedules) ? d.schedules.map(({ next, ...s }) => s) : d?.schedules })
  },
  validate(data) {
    const base = defaults(),
      problems = [];
    if (!data || typeof data !== 'object') return { value: base, problems: ['settings were not an object'] };
    const value = { ...base };
    for (const key of BOOLEAN_SETTINGS) {
      if (key in data && !T.bool(data[key])) problems.push(`${key} was not true or false`);
      else if (key in data) value[key] = data[key];
    }
    if (T.str(data.engineDir)) value.engineDir = data.engineDir;
    else if ('engineDir' in data) problems.push('engineDir was not text');
    if (T.strArray(data.exclusions)) value.exclusions = data.exclusions;
    else if ('exclusions' in data) problems.push('exclusions were not a list of folders');
    if (Number.isInteger(data.staleAfterDays) && data.staleAfterDays >= 1 && data.staleAfterDays <= 30)
      value.staleAfterDays = data.staleAfterDays;
    else if ('staleAfterDays' in data) problems.push('staleAfterDays was out of range');
    value.schedules = base.schedules.map(fallback => {
      const stored = Array.isArray(data.schedules) ? data.schedules.find(s => s?.id === fallback.id) : undefined;
      if (!stored) {
        if ('schedules' in data) problems.push(`the ${fallback.id} schedule was missing`);
        return fallback;
      }
      const bad = invalidField(stored, SCHEDULE_SHAPE);
      if (bad) {
        problems.push(`the ${fallback.id} schedule had an invalid ${bad}`);
        return fallback;
      }
      return {
        id: fallback.id,
        enabled: stored.enabled,
        frequency: stored.frequency,
        time: stored.time,
        day: stored.day
      };
    });
    return { value, problems };
  }
};

// ---- Scan reports ----

const REPORT_STATUSES = ['completed', 'partial', 'error', 'cancelled', 'interrupted'];
const REPORT_SHAPE = {
  id: T.str,
  kind: T.oneOf('quick', 'full', 'custom'),
  started: T.date,
  finished: T.optDate,
  status: T.oneOf(...REPORT_STATUSES),
  files: T.count,
  threats: v =>
    Array.isArray(v) && v.every(t => T.str(t?.id) && T.str(t?.path) && T.str(t?.signature) && T.optStr(t?.detectionId)),
  warningCount: T.optCount,
  warnings: T.strArray,
  targets: T.strArray
};

const reports = {
  version: 1,
  fallback: () => [],
  migrations: {
    // v0 kept each threat's review status on the report; statuses now live in the detection store.
    0: list =>
      Array.isArray(list)
        ? list.map(r => ({
            ...r,
            threats: Array.isArray(r?.threats)
              ? r.threats.map(({ status, ...t }) => ({ ...t, detectionId: t.detectionId ?? t.id }))
              : r?.threats
          }))
        : list
  },
  validate: list => validList(list, REPORT_SHAPE, 'report')
};

// ---- Detections ----

const DETECTION_STATUSES = ['detected', 'missing', 'quarantined', 'restored', 'resolved'];
const detections = {
  version: 1,
  fallback: () => [],
  migrations: {},
  validate: list =>
    validList(
      list,
      {
        id: T.str,
        path: T.str,
        signature: T.str,
        status: T.oneOf(...DETECTION_STATUSES),
        firstSeen: T.date,
        lastSeen: T.date,
        sightings: T.count,
        reports: T.strArray,
        sha256: T.sha,
        revisions: v => v == null || (Array.isArray(v) && v.every(x => T.sha(x?.sha256))),
        audit: T.audit
      },
      'detection'
    )
};

// ---- Quarantine ----

const QUARANTINE_STATUSES = [
  'prepared',
  'copying',
  'quarantined',
  'restoring',
  'restored',
  'failed',
  'recovery-needed',
  'reviewed'
];
const quarantine = {
  version: 1,
  fallback: () => [],
  migrations: {
    0: list =>
      Array.isArray(list)
        ? list.map(q => ({
            id: q?.id,
            detectionId: q?.id,
            original: q?.original,
            stored: q?.stored,
            signature: q?.signature,
            sha256: null,
            size: null,
            created: q?.date,
            // v0 'pending' means metadata was saved but the move may not have finished.
            status: q?.status === 'pending' ? 'prepared' : q?.status === 'error' ? 'failed' : q?.status,
            error: q?.error ?? null,
            audit: [{ at: q?.date, action: 'migrated', detail: 'Imported from an earlier version.' }]
          }))
        : list
  },
  validate: list =>
    validList(
      list,
      {
        // The id and stored path are checked again before any file operation; a record whose stored path
        // is suspicious is kept (and flagged by the quarantine module) so its vault file stays tracked.
        id: T.str,
        detectionId: T.str,
        original: T.winPath,
        stored: T.str,
        signature: T.str,
        sha256: T.sha,
        storedSha256: T.sha,
        created: T.date,
        status: T.oneOf(...QUARANTINE_STATUSES),
        options: v => v == null || (Array.isArray(v) && v.every(o => ['finish', 'undo', 'dismiss'].includes(o))),
        audit: T.audit
      },
      'quarantine record'
    )
};

// ---- Signature updates ----

const updates = {
  version: 1,
  fallback: () => ({
    lastCheck: null,
    lastSuccess: null,
    lastFailure: null,
    failure: null,
    failures: 0,
    nextAttempt: null
  }),
  migrations: {
    0: d => ({ ...updates.fallback(), lastCheck: d?.lastUpdate ?? null, lastSuccess: d?.lastUpdate ?? null })
  },
  validate(data) {
    const value = updates.fallback(),
      problems = [];
    if (!data || typeof data !== 'object') return { value, problems: ['update state was not an object'] };
    for (const key of ['lastCheck', 'lastSuccess', 'lastFailure', 'nextAttempt']) {
      if (T.optDate(data[key])) value[key] = data[key] ?? null;
      else problems.push(`${key} was not a valid time`);
    }
    if (T.count(data.failures)) value.failures = data.failures;
    if (data.failure && T.str(data.failure.message) && T.str(data.failure.kind)) value.failure = data.failure;
    const cache = data.database;
    if (cache != null) {
      if (
        T.str(cache.fingerprint) &&
        T.optStr(cache.engine) &&
        (cache.verified === null || T.bool(cache.verified)) &&
        T.strArray(cache.failures ?? []) &&
        (cache.loadFailed == null || T.bool(cache.loadFailed))
      )
        value.database = cache;
      else problems.push('the database verification cache was malformed and will be rebuilt');
    }
    return { value, problems };
  }
};

// ---- Scheduler runtime and jobs ----

const RUNTIME_SHAPE = {
  fingerprint: T.optStr,
  next: T.optDate,
  lastAttempt: T.optDate,
  lastSuccess: T.optDate,
  lastOutcomeAt: T.optDate
};
const schedule = {
  version: 1,
  fallback: () => ({}),
  migrations: {},
  validate(data) {
    const value = {},
      problems = [];
    if (!data || typeof data !== 'object') return { value, problems: ['schedule state was not an object'] };
    for (const id of ['quick', 'full']) {
      if (!data[id]) continue;
      const bad = invalidField(data[id], RUNTIME_SHAPE);
      const pending = data[id].pending;
      if (bad) problems.push(`the ${id} schedule state had an invalid ${bad}`);
      else if (pending && (!T.date(pending.occurrence) || !T.count(pending.attempts) || !T.optDate(pending.retryAfter)))
        problems.push(`the ${id} schedule had an invalid pending retry`);
      else value[id] = data[id];
    }
    return { value, problems };
  }
};

// The scan currently running (manual or scheduled), journaled so a crash can be recovered, and a summary
// of the last successful scan that survives report retention.
const jobs = {
  version: 1,
  fallback: () => ({ current: null, lastSuccessfulScan: null }),
  migrations: {},
  validate(data) {
    const value = jobs.fallback(),
      problems = [];
    const current = data?.current;
    if (current != null) {
      const bad = invalidField(current, {
        // Used to locate the scan's log, so it must be a real scan id.
        reportId: T.uuid,
        kind: T.oneOf('quick', 'full', 'custom'),
        scheduleId: v => v == null || v === 'quick' || v === 'full',
        occurrence: T.optDate,
        started: T.date
      });
      if (bad) problems.push(`the running scan record had an invalid ${bad}`);
      else value.current = current;
    }
    const last = data?.lastSuccessfulScan;
    if (last && T.str(last.id) && T.date(last.finished)) value.lastSuccessfulScan = last;
    return { value, problems };
  }
};

module.exports = { settings, reports, detections, quarantine, updates, schedule, jobs, REPORT_STATUSES };
