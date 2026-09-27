// Durable scheduling rules. Pure functions over schedule configuration, persisted runtime state, and an
// injected clock, so every outcome can be tested without timers or processes.
//
// Policy:
// - When an occurrence arrives it becomes *pending* work and the following occurrence is planned.
//   Several missed occurrences (for example while the PC was off) collapse into one pending run.
// - Pending work stays until a scan for it succeeds (completed or partial). Failures retry with bounded
//   backoff: 15 min, 30 min, 1 h, 2 h, 4 h, then every 6 h, until success or the user intervenes.
// - A scan interrupted by quitting, sign-out, or a crash is retried shortly after the app runs again.
// - A user cancellation clears the pending occurrence; the next regular occurrence still runs.
// - When both are pending, the full scan runs first. It satisfies a quick occurrence that was due when
//   it started only when the finished scan's coverage evidence shows the quick-scan locations were
//   actually inspected (R03); otherwise the quick scan still runs.
// - Editing a schedule re-plans it from now and clears its pending retry.
const { nextRun } = require('./core.cjs');

const MINUTE = 60000;
const INTERRUPTED_RETRY = 2 * MINUTE;
const PRIORITY = ['full', 'quick'];

const fingerprint = s => [s.enabled, s.frequency, s.time, s.day].join('|');
const backoff = attempts => Math.min(15 * 2 ** (attempts - 1), 360) * MINUTE;
const iso = date => new Date(date).toISOString();

// Aligns runtime state with configuration. `runtime` entries without a fingerprint come from an
// earlier version; their planned (possibly overdue) run is kept so a missed occurrence is not lost.
function reconcile(config, runtime, now) {
  const out = {};
  for (const s of config) {
    const prev = runtime[s.id] || {};
    const fp = fingerprint(s);
    if (!s.enabled) out[s.id] = { ...prev, fingerprint: fp, next: null, pending: null };
    else if (prev.fingerprint === fp && prev.next) out[s.id] = { ...prev };
    else if (!prev.fingerprint && prev.next) out[s.id] = { ...prev, fingerprint: fp };
    else out[s.id] = { ...prev, fingerprint: fp, next: nextRun(s, now), pending: null };
  }
  return out;
}

// Turns arrived occurrences into pending work. Returns true when runtime changed.
function advance(config, runtime, now) {
  let changed = false;
  for (const s of config) {
    const r = runtime[s.id];
    if (!s.enabled || !r?.next || new Date(r.next) > now) continue;
    r.pending = r.pending
      ? { ...r.pending, occurrence: r.next }
      : { occurrence: r.next, attempts: 0, retryAfter: null, lastError: null };
    r.next = nextRun(s, now);
    changed = true;
  }
  return changed;
}

// The scheduled job that should start now, or null.
function nextJob(config, runtime, now) {
  for (const id of PRIORITY) {
    const s = config.find(c => c.id === id);
    const pending = runtime[id]?.pending;
    if (s?.enabled && pending && (!pending.retryAfter || new Date(pending.retryAfter) <= now))
      return { scheduleId: id, occurrence: pending.occurrence, attempt: pending.attempts + 1 };
  }
  return null;
}

function recordStart(runtime, job, now) {
  runtime[job.scheduleId].lastAttempt = iso(now);
}

// Applies a finished job. `status` is a report status, or 'failed-to-start'.
// Idempotent per job id, so replaying a scan journal after a crash cannot settle a job twice.
// `coversQuick` must be backed by coverage evidence from the finished scan (see coverage.cjs).
function recordOutcome(runtime, job, status, now, error = null, { coversQuick = false } = {}) {
  const r = runtime[job.scheduleId];
  if (!r) return;
  if (job.id) {
    if (r.lastJobId === job.id) return;
    r.lastJobId = job.id;
  }
  r.lastOutcome = status;
  r.lastOutcomeAt = iso(now);
  // Only occurrences that were due when the job started are settled by it.
  const settles = p => p && new Date(p.occurrence) <= new Date(job.started);
  if (status === 'completed' || status === 'partial') {
    r.lastSuccess = iso(now);
    if (settles(r.pending)) r.pending = null;
    const quick = runtime.quick;
    if (job.scheduleId === 'full' && coversQuick && quick && settles(quick.pending)) {
      quick.pending = null;
      quick.lastOutcome = 'covered';
      quick.lastOutcomeAt = iso(now);
    }
  } else if (status === 'cancelled') {
    if (settles(r.pending)) r.pending = null;
  } else if (r.pending) {
    if (status === 'interrupted') r.pending.retryAfter = iso(now.getTime() + INTERRUPTED_RETRY);
    else {
      r.pending.attempts++;
      r.pending.retryAfter = iso(now.getTime() + backoff(r.pending.attempts));
    }
    r.pending.lastError = error;
  }
}

// The next time a scheduled scan will run for each enabled schedule, for display and health.
function upcoming(config, runtime, now) {
  return config
    .filter(s => s.enabled && runtime[s.id])
    .map(s => {
      const r = runtime[s.id];
      const retry = r.pending && (r.pending.retryAfter ? new Date(r.pending.retryAfter) : now);
      return { id: s.id, at: iso(retry && retry < new Date(r.next) ? retry : r.next), retry: !!r.pending };
    })
    .sort((a, b) => new Date(a.at) - new Date(b.at));
}

module.exports = { reconcile, advance, nextJob, recordStart, recordOutcome, upcoming, backoff, fingerprint };
