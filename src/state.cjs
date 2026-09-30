// Loading, migration, and scan transactions for the persisted application state. Electron-free, so
// interruption at every persisted boundary can be tested directly.
const nodeFs = require('node:fs');
const schemas = require('./schemas.cjs');
const scheduler = require('./scheduler.cjs');
const detectionStore = require('./detections.cjs');

const MAX_REPORTS = 200;

const SPECS = {
  settings: schemas.settings,
  history: schemas.reports,
  detections: schemas.detections,
  quarantine: schemas.quarantine,
  updates: schemas.updates,
  schedule: schemas.schedule,
  jobs: schemas.jobs
};

// Files whose legacy (schema 0) form drives a migration are saved last, and everything derived from them
// is deterministic. A restart after any individual save therefore repeats the same migration and
// converges on the same result (R09.4).
const SAVE_ORDER = ['detections', 'quarantine', 'updates', 'jobs', 'schedule', 'settings', 'history'];

function loadState(store, { now = new Date(), dataRoot, fs = nodeFs } = {}) {
  const issues = [];
  const load = name => {
    const result = store.load(name, SPECS[name]);
    if (result.issue) issues.push(result.issue);
    return result;
  };
  const exists = name => fs.existsSync(store.file(name));
  const hadDetections = exists('detections'),
    hadSchedule = exists('schedule');
  const s = load('settings');
  const h = load('history');
  const state = {
    settings: s.value,
    reports: h.value,
    detections: load('detections').value,
    quarantine: load('quarantine').value,
    updates: load('updates').value,
    scheduleRuntime: null,
    jobs: load('jobs').value
  };
  // Version 1.0 kept detection status inside scan reports. Build the independent store once, and always
  // re-derive the (deterministic) report links while the reports are still in their legacy form.
  if (h.legacy) {
    const migrated = detectionStore.migrateLegacy(h.legacy, now.toISOString());
    if (!hadDetections) state.detections = migrated.detections;
    for (const r of state.reports) for (const t of r.threats) t.detectionId = migrated.idMap[t.id] ?? t.detectionId;
  }
  let runtime = load('schedule').value;
  if (!hadSchedule && Array.isArray(s.legacy?.schedules))
    runtime = Object.fromEntries(s.legacy.schedules.filter(x => x?.next).map(x => [x.id, { next: x.next }]));
  state.scheduleRuntime = scheduler.reconcile(state.settings.schedules, runtime, now);
  // Never scan the signature store or the quarantine itself.
  if (dataRoot) state.settings.exclusions = [...new Set([...state.settings.exclusions, dataRoot])];
  return { state, issues };
}

const storeValue = (state, name) =>
  ({
    settings: state.settings,
    history: state.reports,
    detections: state.detections,
    quarantine: state.quarantine,
    updates: state.updates,
    schedule: state.scheduleRuntime,
    jobs: state.jobs
  })[name];

/**
 * Applies a scan journal to the state. Idempotent: reports are upserted by id, sightings are recorded once
 * per scan, and scheduler settlement is recorded once per job, so replaying the same journal after an
 * interruption converges on the uninterrupted result (R09.1–R09.3).
 *
 * replay: { header, targets, detections: [{ eventId, path, signature, at }], progress, commit }
 */
function applyScan(state, replay, now) {
  const h = replay.header;
  const outcome = replay.commit;
  const existing = state.reports.find(r => r.id === h.reportId);
  // The stores already hold a finished report and only the journal deletion was lost: nothing to redo.
  if (existing && !outcome && existing.status !== 'interrupted') return existing;
  const report = {
    id: h.reportId,
    kind: h.kind,
    scheduled: !!h.scheduleId,
    started: h.started,
    targets: replay.targets || [],
    engineVersion: h.engineVersion,
    databaseVersion: h.databaseVersion,
    options: h.options,
    // The scope in force when the scan ran, so its coverage claims can be checked (R03.2).
    exclusions: h.exclusions || [],
    ...(outcome || {
      status: 'interrupted',
      finished: now.toISOString(),
      exitCode: null,
      files: replay.progress?.files ?? 0,
      warnings: ['Sentinel stopped before this scan finished. Detections found before it stopped are included.'],
      warningCount: 1
    }),
    threats: []
  };
  const seen = new Set();
  for (const event of replay.detections) {
    if (seen.has(event.eventId)) continue;
    seen.add(event.eventId);
    const d = detectionStore.observe(state.detections, {
      path: event.path,
      signature: event.signature,
      reportId: report.id,
      at: event.at,
      // A stable id makes every replay of this journal produce the same records.
      id: event.eventId
    });
    report.threats.push({ id: event.eventId, path: event.path, signature: event.signature, detectionId: d.id });
  }
  const index = state.reports.findIndex(r => r.id === report.id);
  if (index >= 0) state.reports[index] = report;
  else state.reports.unshift(report);
  state.reports = state.reports.slice(0, MAX_REPORTS);
  state.detections = detectionStore.prune(state.detections);
  if (h.scheduleId)
    scheduler.recordOutcome(
      state.scheduleRuntime,
      { id: report.id, scheduleId: h.scheduleId, occurrence: h.occurrence, started: h.started },
      report.status,
      now,
      report.error || null,
      { coversQuick: !!outcome?.coversQuick }
    );
  const success = report.status === 'completed' || report.status === 'partial';
  const last = state.jobs.lastSuccessfulScan;
  if (success && !h.options?.continuous && (!last || last.finished <= report.finished))
    state.jobs.lastSuccessfulScan = {
      id: report.id,
      kind: report.kind,
      finished: report.finished,
      status: report.status,
      files: report.files
    };
  // A journal from a 1.1.0-style running marker is superseded once applied.
  if (state.jobs.current?.reportId === report.id) state.jobs.current = null;
  return report;
}

// Checks report → detection and detection ↔ quarantine links (R09.5). A report threat whose detection is
// missing is re-opened for review (the conservative repair). Other broken links are reported, not guessed.
function verifyLinks(state) {
  const detectionIds = new Set(state.detections.map(d => d.id));
  const quarantineIds = new Set(state.quarantine.map(q => q.id));
  let repaired = 0;
  const ambiguous = [];
  for (const report of state.reports)
    for (const t of report.threats) {
      if (detectionIds.has(t.detectionId)) continue;
      const d = detectionStore.observe(state.detections, {
        path: t.path,
        signature: t.signature,
        reportId: report.id,
        at: report.finished || report.started,
        id: t.id
      });
      t.detectionId = d.id;
      detectionIds.add(d.id);
      repaired++;
    }
  for (const d of state.detections)
    if (d.quarantineId && !quarantineIds.has(d.quarantineId))
      ambiguous.push(`Detection ${d.signature} refers to a quarantine record that no longer exists.`);
  for (const q of state.quarantine)
    if (!detectionIds.has(q.detectionId))
      ambiguous.push(`Quarantine record for ${q.signature} has no matching detection; it is kept as-is.`);
  return { repaired, ambiguous };
}

module.exports = { loadState, applyScan, verifyLinks, storeValue, SPECS, SAVE_ORDER, MAX_REPORTS };
