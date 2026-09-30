const icons = {
  shield: '<path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6Z"/><path d="m8 12 3 3 5-6"/>',
  alert: '<path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6Z"/><path d="M12 8v5m0 3h.01"/>',
  grid: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  scan: '<path d="M8 3H3v5m13-5h5v5M3 16v5h5m8 0h5v-5M3 12h18"/><circle cx="12" cy="12" r="5"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  box: '<rect x="4" y="7" width="16" height="14" rx="2"/><path d="M3 3h18v4H3zm7 9h4"/>',
  activity: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  settings:
    '<path d="m10 3-1 3-3 1-3 3 2 2-1 4 3 3 3-1 2 3 3-1 1-3 3-1 2-3-2-3V7l-3-2-3 1Z"/><circle cx="12" cy="12" r="3"/>',
  bolt: '<path d="m13 2-9 12h7l-1 8L21 9h-8Z"/>',
  monitor: '<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/>',
  folder: '<path d="M3 7V5a2 2 0 0 1 2-2h5l2 3h7a2 2 0 0 1 2 2v11H3Z"/>',
  arrow: '<path d="M4 12h16m-6-6 6 6-6 6"/>',
  refresh: '<path d="M20 8a8 8 0 1 0 0 8M20 3v5h-5"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
  download: '<path d="M12 3v12m-5-5 5 5 5-5M4 17v4h16v-4"/>'
};
const icon = name => `<svg viewBox="0 0 24 24" aria-hidden="true">${icons[name] || icons.shield}</svg>`;
const esc = value =>
  String(value ?? '').replace(
    /[&<>"']/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]
  );
const date = value =>
  value
    ? new Date(value).toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' })
    : 'Not yet';
// Health details carry ISO times from the main process; show them in the user's locale.
const localize = text => String(text ?? '').replace(/\d{4}-\d{2}-\d{2}T[\d:.]+Z/g, iso => date(iso));
const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const labels = { quick: 'Quick scan', full: 'Full scan', custom: 'Custom scan' };
const views = [
  ['overview', 'grid', 'Overview'],
  ['scans', 'scan', 'Scan center'],
  ['schedules', 'clock', 'Schedules'],
  ['quarantine', 'box', 'Quarantine'],
  ['activity', 'activity', 'Activity'],
  ['settings', 'settings', 'Settings']
];
let state,
  current = 'overview',
  draft,
  toastTimer,
  stale = false;
// Actions currently awaiting the main process, keyed by action and value. The main process
// already rejects conflicting operations, so unrelated actions stay usable during long updates.
const pending = new Set();

function toast(message) {
  const el = document.querySelector('#toast');
  el.textContent = message;
  el.classList.add('visible');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('visible'), 6500);
}
async function call(action, payload) {
  const result = await window.sentinel.call(action, payload);
  if (!result.ok) throw Error(result.error);
  return result.data;
}

// ---- Building blocks ----

// `reason` explains a disabled button (shown as a tooltip and to screen readers).
function btn(text, action, value = '', cls = '', disabled = false, image = '', reason = '') {
  const why = disabled && reason ? ` title="${esc(reason)}" aria-description="${esc(reason)}"` : '';
  return `<button class="btn ${cls}" data-action="${action}" data-value="${esc(value)}" ${disabled ? 'disabled' : ''}${why}>${image ? icon(image) : ''}${text}</button>`;
}
function pill(text, cls = '') {
  return `<span class="pill ${cls}">${esc(text)}</span>`;
}
function heading(title, sub, right = '') {
  return `<div class="page-heading"><div><h1>${title}</h1><p>${sub}</p></div>${right}</div>`;
}
function toggle(key, title, description) {
  return `
    <div class="setting-row">
      <div><h3>${title}</h3><p>${description}</p></div>
      <input class="toggle" type="checkbox" aria-label="${title}" data-setting="${key}" ${draft[key] ? 'checked' : ''}>
    </div>`;
}
function facts(items) {
  return `<div class="facts">${items.map(([k, v]) => `<div>${k}<strong>${v}</strong></div>`).join('')}</div>`;
}
function scheduleText(s) {
  return `${s.frequency === 'daily' ? 'Every day' : 'Every ' + days[s.day]} at ${s.time}`;
}
const busyEngine = () => !!state.active || state.updating || !!state.installing;
// Scan availability comes from the main process's capability snapshot, the same one it enforces.
const capability = () => state.health.capability;
const blockedReason = {
  'engine-missing': 'Set up ClamAV in Settings to start scanning.',
  'engine-not-runnable': 'ClamAV could not start. Check the installation in Settings.',
  'database-missing': 'Download the signature database in Settings to start scanning.',
  'database-invalid': 'The signature database failed verification. Update the definitions to scan again.',
  'database-load-failed': 'ClamAV could not load the signature database. Recheck or update it to scan again.'
};
const verificationText = {
  verified: 'verified by sigtool',
  pending: 'verification in progress',
  unavailable: 'cannot be verified (no sigtool)',
  failed: 'failed verification'
};
const unresolved = () => state.detections.filter(d => d.status === 'detected' || d.status === 'missing');
const detectionById = id => state.detections.find(d => d.id === id);
const statusTone = { ok: '', off: 'amber', warn: 'amber', error: 'red' };
const healthPill = {
  ok: ['ALL CHECKS PASSED', ''],
  attention: ['NEEDS ATTENTION', 'amber'],
  problem: ['ACTION NEEDED', 'red'],
  setup: ['SETUP REQUIRED', 'amber']
};

// ---- Live values ----
// Elements marked data-live are updated in place by progress events, so the page is not
// rebuilt while a scan or update streams output (which would reset focus and selection).

const phaseText = {
  preparing: 'Finding scan locations',
  loading: 'Loading signatures',
  scanning: 'Scanning',
  cancelling: 'Stopping'
};
const live = {
  files: () => (state.active ? state.active.files.toLocaleString() + ' files checked' : ''),
  counts: () =>
    state.active ? `${state.active.threatCount ?? 0} detections · ${state.active.warningCount ?? 0} warnings` : '',
  phase: () =>
    state.active ? phaseText[state.active.status === 'cancelling' ? 'cancelling' : state.active.phase] || '' : '',
  current: () => state.active?.current ?? '',
  installOutput: () => state.installOutput || 'Starting…',
  updateOutput: () => state.updateOutput,
  monitorStatus: () =>
    state.monitoring?.connected
      ? state.monitoring.reason || 'Monitoring files'
      : state.monitoring?.reason || 'Disconnected',
  monitorQueue: () =>
    `${state.monitoring?.queued || 0} queued · ${state.monitoring?.active || 0} scanning · oldest ${state.monitoring?.oldestSeconds || 0}s`,
  monitorResources: () =>
    `${state.monitoring?.resources?.engineMB || 0} MB engine memory · ${state.monitoring?.resources?.freeMB || 0} MB system memory available · system CPU ${state.monitoring?.resources?.cpuPercent ?? '…'}%`,
  monitorCounts: () =>
    `${state.monitoring?.metrics?.scanned || 0} checked · ${state.monitoring?.metrics?.skipped || 0} skipped · ${state.monitoring?.metrics?.errors || 0} retry attempts`,
  monitorLatency: () =>
    state.monitoring?.p95Ms == null
      ? 'Waiting for measurements'
      : `95% of the last 100 verdicts within ${(state.monitoring.p95Ms / 1000).toFixed(1)}s of queueing`
};
function patch() {
  for (const el of document.querySelectorAll('[data-live]')) {
    const text = live[el.dataset.live]();
    if (el.textContent !== text) el.textContent = text;
  }
}

// ---- Views ----

function scans() {
  const cards = [
    ['quick', 'bolt', 'EVERYDAY CHECK', 'Check Desktop, Downloads, Documents, and temporary files.'],
    ['full', 'monitor', 'THOROUGH CHECK', 'Scan all local fixed drives for a comprehensive review.'],
    ['custom', 'folder', 'YOUR CHOICE', 'Choose a specific folder and scan everything inside it.']
  ];
  const disabled = busyEngine() || !capability().canScan;
  const reason = !capability().canScan
    ? blockedReason[capability().blocking[0]]
    : busyEngine()
      ? 'Wait for the current scan or update to finish.'
      : '';
  return `<div class="scan-grid">${cards
    .map(([kind, image, tag, desc]) => {
      const tone = kind === 'quick' ? 'green' : kind === 'custom' ? 'purple' : '';
      const button =
        kind === 'custom'
          ? btn('Choose folder', 'custom', kind, '', disabled, 'arrow', reason)
          : btn('Start ' + labels[kind].toLowerCase(), 'scan', kind, '', disabled, 'arrow', reason);
      return `
        <article class="card scan-card">
          <span class="tag">${tag}</span>
          <div class="icon-box ${tone}">${icon(image)}</div>
          <h3>${labels[kind]}</h3>
          <p>${desc}</p>
          ${button}
        </article>`;
    })
    .join('')}</div>`;
}

function activeScan() {
  const a = state.active;
  if (!a) return '';
  return `
    <section class="card panel scan-progress">
      <div class="row spread">
        <div><div class="eyebrow">SCAN IN PROGRESS · <span data-live="phase">${esc(live.phase())}</span></div><h2>${labels[a.kind]} ${a.scheduled ? '· scheduled' : ''}</h2></div>
        ${btn('Stop scan', 'cancel', '', 'small danger', a.status === 'cancelling')}
      </div>
      <div class="progress-track"><i></i></div>
      <div class="row spread">
        <strong data-live="files">${esc(live.files())}</strong>
        <span class="muted" data-live="counts">${esc(live.counts())}</span>
      </div>
      <p class="path" data-live="current">${esc(live.current())}</p>
      <p>Started ${date(a.started)}. Scanning time depends on file count and size, so no percentage is shown.</p>
    </section>`;
}

// Background work other than the scan card: what is happening now, so waiting actions make sense.
function operationsNotice() {
  const others = (state.operations || []).filter(o => o.type !== 'scan');
  if (!others.length) return '';
  return `<div class="notice operations">In progress: ${others.map(o => esc(o.label)).join(' · ')}</div>`;
}

function healthChecks() {
  const actionFor = check => {
    if (!check.action || check.status === 'ok') return '';
    if (check.action === 'update')
      return btn('Update now', 'update', '', 'small', busyEngine() || !capability().canUpdate, 'refresh');
    if (check.action === 'recheck')
      return btn(
        'Recheck database',
        'recheck-database',
        '',
        'small',
        busyEngine() || !state.engine.runnable,
        'refresh'
      );
    return btn('Review', 'navigate', check.action, 'small');
  };
  return `<div class="checks">${state.health.checks
    .map(
      c => `
        <div class="check">
          <span class="dot ${c.status}" aria-hidden="true"></span>
          <div><strong>${esc(c.label)}</strong>${c.detail ? `<p>${esc(localize(c.detail))}</p>` : ''}</div>
          <span class="sr-only">${c.status === 'ok' ? 'OK' : c.status === 'off' ? 'Off' : c.status === 'warn' ? 'Warning' : 'Problem'}</span>
          ${actionFor(c)}
        </div>`
    )
    .join('')}</div>`;
}

function overview() {
  const h = state.health;
  const [pillText, pillTone] = healthPill[h.state];
  const sub = {
    ok: 'Your schedule is enabled, definitions are current and verified, and your last scan completed.',
    attention: 'Sentinel is working, but something below needs a look.',
    problem: 'Something below needs your action.',
    setup: 'Set up the ClamAV engine and its signature database, then Sentinel can run your scheduled scans.'
  }[h.state];
  const firstAction = h.checks.find(c => c.status !== 'ok' && c.action);
  const action =
    h.state === 'setup'
      ? btn('Set up protection', 'navigate', 'settings', 'primary', false, 'arrow')
      : firstAction?.action === 'recheck'
        ? btn('Recheck database', 'recheck-database', '', 'primary', busyEngine(), 'refresh')
        : firstAction && firstAction.action !== 'update'
          ? btn('Review', 'navigate', firstAction.action, 'primary', false, 'arrow')
          : btn('Run quick scan', 'scan', 'quick', 'primary', busyEngine() || !capability().canScan, 'scan');

  const hero = `
    <section class="hero ${h.state}">
      <div class="hero-mark">${icon(h.state === 'ok' ? 'shield' : 'alert')}</div>
      <div class="hero-copy">${pill(pillText, pillTone)}<h2>${esc(h.headline)}</h2><p>${sub}</p></div>
      <div class="hero-actions">${action}<small>Powered by open-source ClamAV</small></div>
    </section>`;

  const metric = (tone, image, caption, value, detail) => `
    <div class="card metric">
      <div class="icon-box ${tone}">${icon(image)}</div>
      <div><div class="caption">${caption}</div><strong>${value}</strong><small>${detail}</small></div>
    </div>`;
  const db = state.database;
  const last = h.lastSuccessfulScan;
  const next = h.nextScan;
  const metrics = `<div class="metrics">${
    metric(
      'green',
      'clock',
      'NEXT SCHEDULED SCAN',
      next ? date(next.at) : 'Paused',
      next ? labels[next.id] + (next.retry ? ' · retry' : '') : 'No schedule is enabled'
    ) +
    metric(
      '',
      'check',
      'LAST SUCCESSFUL SCAN',
      last ? date(last.finished) : 'None yet',
      last
        ? `${labels[last.kind]} · ${last.files.toLocaleString()} file${last.files === 1 ? '' : 's'}`
        : 'Run a scan to establish a baseline'
    ) +
    metric(
      'purple',
      'refresh',
      'DEFINITIONS',
      state.updating
        ? 'Updating…'
        : db.buildTime
          ? 'Built ' + date(db.buildTime)
          : db.present
            ? 'Date unknown'
            : 'Not downloaded',
      db.version ? `Version ${db.version} · ${verificationText[capability().verification]}` : 'Downloaded during setup'
    )
  }</div>`;

  const routine = state.settings.schedules
    .map(
      s => `
        <div class="schedule-mini">
          <div class="icon-box">${icon(s.id === 'quick' ? 'bolt' : 'monitor')}</div>
          <div><strong>${labels[s.id]}</strong><p>${scheduleText(s)}</p></div>
          ${pill(s.enabled ? (state.schedule.runtime[s.id]?.pending?.attempts ? 'Retrying' : 'Scheduled') : 'Paused', s.enabled ? (state.schedule.runtime[s.id]?.pending?.attempts ? 'amber' : '') : 'neutral')}
        </div>`
    )
    .join('');

  return (
    heading(
      'Security overview',
      'What Sentinel has verified about this device, and what needs attention.',
      pill('WINDOWS DESKTOP', 'neutral')
    ) +
    hero +
    operationsNotice() +
    activeScan() +
    metrics +
    `<div class="bottom-grid">
      <section class="card panel">
        <div class="panel-top"><h2>Health checks</h2></div>
        <p class="muted">Scheduled, on-demand and continuous file scanning. User-space monitoring cannot prevent a file from executing.</p>
        ${healthChecks()}
      </section>
      <section class="card panel">
        <div class="panel-top"><h2>Your scan routine</h2><button class="link" data-action="navigate" data-value="schedules">Manage schedule →</button></div>
        ${routine}
      </section>
    </div>` +
    `<div class="section-title"><h2>Make a scan your own</h2><span>Three ways to check your device</span></div>` +
    scans()
  );
}

function scanCenter() {
  return (
    heading('Scan center', 'A quick check or a closer look. You’re in control.') +
    (!capability().canScan ? `<div class="notice warn">${blockedReason[capability().blocking[0]]}</div>` : '') +
    activeScan() +
    scans() +
    `<div class="notice scan-progress">Full scans inspect accessible files on local fixed drives. Windows permissions and ClamAV limits can prevent files from being scanned; review warnings in the scan report.</div>`
  );
}

function scheduleCard(s) {
  const runtime = state.schedule.runtime[s.id] || {};
  const retry = runtime.pending;
  const option = (value, text, selected) => `<option value="${value}" ${selected ? 'selected' : ''}>${text}</option>`;
  const outcome = {
    completed: 'Completed',
    partial: 'Completed with warnings',
    error: 'Failed',
    'failed-to-start': 'Could not start',
    cancelled: 'Cancelled by you',
    interrupted: 'Interrupted',
    covered: 'Covered by the full scan'
  }[runtime.lastOutcome];
  return `
    <section class="card panel">
      <div class="row spread">
        <div class="row">
          <div class="icon-box green">${icon(s.id === 'quick' ? 'bolt' : 'monitor')}</div>
          <div><h2>${labels[s.id]}</h2><p>${s.id === 'quick' ? 'Everyday folders and temporary files' : 'All local fixed drives'}</p></div>
        </div>
        <input aria-label="Enable ${labels[s.id]} schedule" type="checkbox" class="toggle" data-schedule="${s.id}" data-field="enabled" ${s.enabled ? 'checked' : ''}>
      </div>
      <div class="schedule-fields">
        <div class="field">
          <label for="frequency-${s.id}">Repeat</label>
          <select id="frequency-${s.id}" data-schedule="${s.id}" data-field="frequency">
            ${option('daily', 'Every day', s.frequency === 'daily')}${option('weekly', 'Every week', s.frequency === 'weekly')}
          </select>
        </div>
        <div class="field">
          <label for="day-${s.id}">Day (weekly schedules)</label>
          <select id="day-${s.id}" data-schedule="${s.id}" data-field="day">${days.map((d, i) => option(i, d, s.day === i)).join('')}</select>
        </div>
        <div class="field">
          <label for="time-${s.id}">Local time</label>
          <input id="time-${s.id}" type="time" value="${s.time}" data-schedule="${s.id}" data-field="time">
        </div>
      </div>
      ${
        retry
          ? `<div class="notice ${retry.attempts ? 'warn' : ''}">${
              retry.attempts
                ? `The run due ${date(retry.occurrence)} has not completed (${retry.attempts} failed attempt${retry.attempts === 1 ? '' : 's'}${retry.lastError ? ': ' + esc(retry.lastError) : ''}). Next attempt ${date(retry.retryAfter)}.`
                : `The run due ${date(retry.occurrence)} is waiting to start${retry.retryAfter ? ' at ' + date(retry.retryAfter) : ''}.`
            }</div>`
          : ''
      }
      ${facts([
        ['Next scheduled run', s.enabled && runtime.next ? date(runtime.next) : 'Paused'],
        ['Last attempt', date(runtime.lastAttempt)],
        ['Last result', outcome ? `${outcome} · ${date(runtime.lastOutcomeAt)}` : 'Not yet'],
        ['Last success', date(runtime.lastSuccess)]
      ])}
      <p>Uses this device’s local timezone. Saved changes re-plan the schedule from now.</p>
    </section>`;
}

function schedules() {
  return (
    heading(
      'Your scan routine',
      'Set it once. Let Sentinel keep the rhythm.',
      btn('Save changes', 'save', '', 'primary')
    ) +
    `<div class="notice">Schedules run while Sentinel is open or in the system tray. A run missed while the computer was off runs once when Sentinel is next running. Failed runs retry automatically, starting after 15 minutes and backing off to every 6 hours. When both are due, the full scan runs first and also covers the quick scan.</div>` +
    `<div class="stack">${draft.schedules.map(scheduleCard).join('')}</div>`
  );
}

function reviewQueue() {
  const open = unresolved();
  if (!open.length) return '';
  return `
    <section class="card panel">
      <div class="panel-top"><h2>Needs review</h2>${pill(open.length + ' unresolved', 'red')}</div>
      <p>Detections stay here until you act on them, even after older scan reports are removed.</p>
      ${open
        .map(
          d => `
            <div class="review-item">
              <div>
                <strong>${esc(d.signature)}</strong>
                <div class="path">${esc(d.path)}</div>
                <p>First seen ${date(d.firstSeen)}${d.sightings > 1 ? ` · seen in ${d.sightings} scans, most recently ${date(d.lastSeen)}` : ''}${d.status === 'missing' ? ' · <b>the file is no longer at this location</b>' : ''}</p>
              </div>
              ${
                d.status === 'missing'
                  ? btn('Mark resolved', 'resolve-detection', d.id, 'small')
                  : btn(
                      state.active ? 'Stop scan and quarantine' : 'Quarantine file',
                      'quarantine',
                      d.id,
                      'small danger'
                    )
              }
            </div>`
        )
        .join('')}
    </section>`;
}

function historyItem(h) {
  const tone = ['error', 'partial', 'interrupted'].includes(h.status)
    ? 'amber'
    : h.threats.length
      ? 'red'
      : h.status === 'cancelled'
        ? 'neutral'
        : '';
  const threats = h.threats
    .map(t => {
      const status = detectionById(t.detectionId)?.status || 'unknown';
      return `
        <div class="threat">
          <strong>${esc(t.signature)}</strong>
          <div class="path">${esc(t.path)}</div>
          ${pill(status === 'detected' ? 'Needs review' : status)}
        </div>`;
    })
    .join('');
  const warnings = h.warningCount ?? h.warnings.length;
  return `
    <details class="history-item">
      <summary>
        <div>
          <strong>${h.options?.continuous ? 'Continuous scan' : labels[h.kind]} ${h.scheduled ? '· scheduled' : ''}</strong>
          <small>${date(h.finished)} · ${h.files.toLocaleString()} files · ${h.threats.length} detections${warnings ? ` · ${warnings} warnings` : ''}</small>
        </div>
        ${pill(h.status, tone)}
      </summary>
      <div class="history-detail">
        <p class="path">${h.targets.map(esc).join(' · ')}</p>
        ${h.engineVersion ? `<p>${esc(h.engineVersion)} · definitions version ${esc(h.databaseVersion ?? 'unknown')}</p>` : ''}
        ${coverageNote(h)}
        ${h.warnings.length ? `<div class="notice warn">${h.warnings.map(esc).join('<br>')}${warnings > h.warnings.length ? `<br>…and ${warnings - h.warnings.length} more in the scan log.` : ''}</div>` : ''}
        ${h.logTruncated ? '<p>The scan log reached its size limit and was truncated.</p>' : ''}
        ${threats}
        <div class="row">${btn('Export report', 'export', h.id, 'small', false, 'download')}</div>
      </div>
    </details>`;
}

// What the scan actually inspected, stated without more certainty than the evidence supports.
function coverageNote(h) {
  const c = h.coverage;
  if (!c) return '';
  const text = {
    complete: 'Coverage: every file ClamAV reached in these locations was scanned, with no read problems reported.',
    gaps: `Coverage: completed with gaps. ${c.categories.access} file(s) could not be read${c.categories.limit ? ` and ${c.categories.limit} hit ClamAV size or archive limits` : ''}; see the warnings below.`,
    incomplete: `Coverage: incomplete. These locations could not be scanned: ${c.targetFailures.map(esc).join(', ')}.`,
    failed: 'Coverage: the scan did not finish, so these locations were not fully checked.'
  }[c.status];
  return `<div class="notice ${c.status === 'complete' ? '' : 'warn'}">${text}${c.warningsTruncated ? ' Only the first warnings are listed here; the scan log has all of them.' : ''}</div>`;
}

function activity() {
  const body = state.history.length
    ? state.history.map(historyItem).join('')
    : `<div class="wide-empty">${icon('activity')}<h2>Your story starts with a scan.</h2><p>Finished scans, skipped files, and threat detections appear here. Reports can be exported for your records.</p></div>`;
  return (
    heading(
      'Activity & reports',
      'The details behind every scan, in one place.',
      btn('Open scan logs', 'logs', '', '', false, 'folder')
    ) +
    `<div class="stack"><div id="live-review">${reviewQueue()}</div><section class="card panel"><div class="panel-top"><h2>Scan reports</h2><span class="muted">The latest 200 reports are kept</span></div>${body}</section></div>`
  );
}

function quarantineItem(q) {
  const tone = { quarantined: 'neutral', 'recovery-needed': 'amber', failed: 'red' }[q.status] || 'neutral';
  const label =
    {
      'recovery-needed': 'Needs review',
      reviewed: 'Reviewed',
      prepared: 'In progress',
      copying: 'In progress',
      restoring: 'Restoring'
    }[q.status] || q.status;
  const actions = [];
  if (q.status === 'quarantined') actions.push(btn('Restore file', 'restore', q.id, 'small'));
  if (q.status === 'recovery-needed') {
    if (q.options.includes('finish')) actions.push(btn('Finish quarantine', 'quarantine-finish', q.id, 'small danger'));
    if (q.options.includes('undo')) actions.push(btn('Undo quarantine', 'quarantine-undo', q.id, 'small'));
    if (q.options.includes('dismiss')) actions.push(btn('Mark reviewed', 'quarantine-dismiss', q.id, 'small'));
  }
  // Recheck re-reads the files and regenerates the available actions from what is there now.
  if (q.status === 'recovery-needed' || q.status === 'reviewed') {
    actions.push(btn('Recheck', 'quarantine-recheck', q.id, 'small', false, 'refresh'));
  }
  return `
    <div class="history-item">
      <div class="row spread"><h3>${esc(q.signature)}</h3>${pill(label, tone)}</div>
      <p class="path">${esc(q.original)}</p>
      <p>${date(q.created)}${q.size != null ? ` · ${q.size.toLocaleString()} bytes` : ''}${q.sha256 ? ` · SHA-256 ${esc(q.sha256.slice(0, 16))}…` : ''}</p>
      ${q.issue ? `<div class="notice warn">${esc(q.issue)}</div>` : ''}
      ${q.error ? `<p>${esc(q.error)}</p>` : ''}
      ${q.saveError ? `<div class="notice warn">This change could not be saved: ${esc(q.saveError)} Sentinel will reconcile it the next time it starts.</div>` : ''}
      ${q.status === 'restored' && q.restoreTarget && q.restoreTarget !== q.original ? `<p>Restored to <span class="path">${esc(q.restoreTarget)}</span></p>` : ''}
      ${actions.length ? `<div class="row">${actions.join('')}</div>` : ''}
    </div>`;
}

function quarantine() {
  const body = state.quarantine.length
    ? state.quarantine.map(quarantineItem).join('')
    : `<div class="wide-empty">${icon('box')}<h2>Nothing in quarantine.</h2><p>When a scan detects a threat, review it in Activity and choose whether to quarantine the file.</p></div>`;
  return (
    heading('Quarantine', 'Keep detected files out of their original location.') +
    `<div class="notice">Quarantine moves a file into Sentinel’s local storage with a non-executable extension after checking it is the same file that was detected. Files are never automatically deleted, and an interrupted operation keeps every copy until you decide. Restore only files you trust; restoring never replaces an existing file.</div>` +
    `<section class="card panel">${body}</section>`
  );
}

function engineSection() {
  const { engine, installing, updating, database: db, updates } = state;
  const steps = `
    <div class="setup-steps">
      <div class="step"><div class="step-number">1</div><h3>Install the engine</h3><p>Private, per-user installation. No administrator access required.</p></div>
      <div class="step"><div class="step-number">2</div><h3>Get fresh definitions</h3><p>Download ClamAV’s official malware signature database.</p></div>
      <div class="step"><div class="step-number">3</div><h3>Make it a routine</h3><p>Daily quick scans and weekly full scans are ready to go.</p></div>
    </div>`;
  const ready = engine.runnable && db.present;
  const primary = !engine.runnable
    ? installing
      ? btn('Cancel setup', 'cancel-install', '', 'danger', false)
      : btn('Install ClamAV & set up', 'install', '', 'primary', busyEngine(), 'download')
    : btn(updating ? 'Updating definitions…' : 'Update definitions', 'update', '', 'primary', busyEngine(), 'refresh');
  const staleOptions = [1, 2, 3, 5, 7, 14]
    .map(
      n => `<option value="${n}" ${draft.staleAfterDays === n ? 'selected' : ''}>${n} day${n === 1 ? '' : 's'}</option>`
    )
    .join('');
  return `
    <section class="card panel">
      <div class="panel-top">
        <div><div class="eyebrow">ENGINE & DEFINITIONS</div><h2>${ready ? 'Your ClamAV engine is ready' : 'Welcome. Let’s get you set up.'}</h2></div>
        ${pill(ready ? 'Ready' : 'Setup required', ready ? '' : 'amber')}
      </div>
      <p>Install the official ClamAV engine and its signature database with one click. Sentinel downloads the Windows engine from Cisco Talos and verifies its SHA-256 checksum.</p>
      ${
        engine.installed
          ? `<p class="path">${esc(engine.version || engine.error)}<br>${esc(engine.dir)}</p>` +
            facts([
              ['Definitions version', db.version ?? 'Unknown'],
              ['Definitions built', db.buildTime ? date(db.buildTime) : 'Unknown'],
              [
                'Signature check',
                capability().verification === 'failed'
                  ? 'Failed: ' + esc(db.failures.join(', '))
                  : verificationText[capability().verification] +
                    (db.loadFailed ? ' · ClamAV could not load it in the last scan' : '')
              ],
              ['Last update check', date(updates.lastCheck)],
              ['Last successful update', date(updates.lastSuccess)],
              [
                'Next automatic attempt',
                updates.nextAttempt
                  ? date(updates.nextAttempt)
                  : state.settings.autoUpdate
                    ? 'Within the hour'
                    : 'Automatic updates off'
              ]
            ])
          : steps
      }
      ${updates.failure ? `<div class="notice warn">${esc(updates.failure.message)} (${updates.failures} failed attempt${updates.failures === 1 ? '' : 's'} in a row)</div>` : ''}
      <div class="row">
        ${primary}
        ${btn('Use existing installation', 'engine', '', '', busyEngine())}
        ${btn('ClamAV website', 'download', '', 'small')}
      </div>
      ${installing || state.installOutput ? `<pre class="log" data-live="installOutput">${esc(live.installOutput())}</pre>` : ''}
      ${state.updateOutput ? `<pre class="log" data-live="updateOutput">${esc(live.updateOutput())}</pre>` : ''}
      <div class="setting-row">
        <div><h3>Keep definitions up to date</h3><p>Check hourly while Sentinel runs. Failed updates retry with increasing delays, up to every six hours, and the delay is kept across restarts.</p></div>
        <input class="toggle" type="checkbox" aria-label="Automatic signature updates" data-setting="autoUpdate" ${draft.autoUpdate ? 'checked' : ''}>
      </div>
      <div class="setting-row">
        <div><h3>Treat definitions as outdated after</h3><p>Based on when ClamAV built the definitions, not when Sentinel last checked for updates.</p></div>
        <select aria-label="Definitions outdated after" data-setting="staleAfterDays">${staleOptions}</select>
      </div>
    </section>`;
}

function storageNotice() {
  if (!state.storageIssues.length) return '';
  return `
    <div class="notice warn">
      <strong>Some saved data needed recovery.</strong>
      ${state.storageIssues.map(i => `<p>${esc(i.file)}: ${esc(i.message)}${i.preservedAs ? ` The original was kept as <span class="path">${esc(i.preservedAs)}</span>.` : ''}</p>`).join('')}
      <div class="row">${btn('Open data folder', 'data-folder', '', 'small', false, 'folder')}${btn('Dismiss', 'dismiss-storage-issues', '', 'small')}</div>
    </div>`;
}

function settings() {
  const exclusions = state.settings.exclusions
    .map(
      p => `
        <div class="setting-row">
          <span class="path">${esc(p)}</span>
          ${p === state.dataRoot ? pill('App data', 'neutral') : btn('Remove', 'remove-exclusion', p, 'small')}
        </div>`
    )
    .join('');
  return (
    heading('Settings', 'Protection that fits the way you work.', btn('Save preferences', 'save', '', 'primary')) +
    `<div class="stack">
      ${storageNotice()}
      ${monitorSection()}
      ${engineSection()}
      <section class="card panel">
        <h2>Desktop experience</h2>
        ${toggle('launchAtLogin', 'Launch at Windows sign-in', state.packaged ? 'Start quietly in the system tray so schedules can run.' : 'Available after installing the packaged Windows app.')}
        ${toggle('closeToTray', 'Keep running when the window closes', 'Continue scheduled scans and updates from the system tray.')}
        ${toggle('notifications', 'Desktop notifications', 'Get notified when scans finish or something needs attention. Repeated failures notify once.')}
      </section>
      <section class="card panel">
        <h2>Scan preferences</h2>
        ${toggle('scanArchives', 'Scan inside archives', 'Inspect supported compressed files. ClamAV size and recursion limits still apply.')}
        ${toggle('detectPUA', 'Detect potentially unwanted applications', 'Broader detection may include legitimate tools. Review results before quarantining.')}
      </section>
      <section class="card panel">
        <div class="panel-top"><h2>Excluded folders</h2>${btn('Add folder', 'exclude', '', 'small')}</div>
        <p>Excluded folders are skipped by future scans. Sentinel’s own data folder is always excluded to protect the quarantine and signature store.</p>
        ${exclusions}
      </section>
    </div>`
  );
}

function monitorSection() {
  const m = draft.monitoring;
  if (!m) return '';
  const toggle = (key, label, detail) =>
    `<div class="setting-row"><div><h3>${label}</h3><p>${detail}</p></div><input type="checkbox" class="toggle" data-monitor="${key}" aria-label="${label}" ${m[key] ? 'checked' : ''}></div>`;
  const number = (key, label, min, max, step = 1) =>
    `<div class="setting-row"><label for="monitor-${key}">${label}</label><input id="monitor-${key}" type="number" data-monitor="${key}" min="${min}" max="${max}" step="${step}" value="${m[key]}"></div>`;
  return `<section class="card panel">
    <h2>Continuous scanning & resources</h2>
    <p>Checks new and changed files after they settle. This does not block files from running. Keep your primary antivirus enabled.</p>
    ${toggle('enabled', 'Monitor file changes', 'Uses one persistent ClamAV engine. Defaults to Downloads and user/system Temp folders.')}
    ${toggle('highRiskOnly', 'Focus on executables, scripts and archives', 'Includes EXE, MSI, ZIP, BAT and PowerShell files. Turn off to scan every file type.')}
    ${toggle('autoQuarantine', 'Automatically quarantine confirmed threats', 'Moves hash-verified ClamAV threats into an isolated vault. Heuristic and community-rule matches require review.')}
    ${toggle('yaraEnabled', 'YARA community detection', 'Adds a curated Signature Base feed. Rules update every six hours and retain author attribution. Matches require review.')}
    ${toggle('staticAnalysis', 'Inspect executable structure', 'Radare2 checks PE sections and imports. Structural anomalies are review alerts, not proof of malware.')}
    ${toggle('telemetryEnabled', 'Local behavior snapshots', 'Uses osquery once per minute to summarize processes and connections and flag Office-launched interpreters. Short-lived activity can be missed.')}
    ${toggle('keepRunning', 'Continue after quitting Sentinel', 'Keeps the background scanner running. An installed Windows service continues independently of this setting.')}
    <div class="notice"><strong data-live="monitorStatus">${esc(live.monitorStatus())}</strong><p data-live="monitorQueue">${esc(live.monitorQueue())}</p><p data-live="monitorResources">${esc(live.monitorResources())}</p><p data-live="monitorCounts">${esc(live.monitorCounts())}</p><p data-live="monitorLatency">${esc(live.monitorLatency())}</p></div>
    <div class="row">${btn('Pause 15 minutes', 'monitor-pause', '15', 'small')}${btn('Pause one hour', 'monitor-pause', '60', 'small')}${btn('Resume', 'monitor-pause', '0', 'small')}</div>
    ${toggle('pauseOnBattery', 'Pause on battery', 'Queues changes and releases engine memory until AC power returns.')}
    ${toggle('idleOnly', 'Scan only while idle', 'Waits for the desktop session to report no input. When the desktop is disconnected, work stays queued.')}
    ${toggle('lowPriority', 'Lower scanner priority', 'Gives other applications scheduling preference. This is not a hard CPU cap.')}
    ${number('concurrency', 'Concurrent scans', 1, 4)}
    ${number('maxFileMB', 'Maximum file size (MB)', 1, 1024)}
    ${number('minFreeMemoryMB', 'Pause below available memory (MB)', 128, 32768)}
    ${number('maxCpuPercent', 'Pause at system CPU usage (%)', 10, 100)}
    ${number('maxQueue', 'Maximum queued files', 100, 20000)}
    ${number('settleMs', 'File settling delay (milliseconds)', 500, 30000, 100)}
    ${number('idleSeconds', 'Idle time before scanning (seconds)', 30, 3600)}
    <p>Files over the size limit are reported as skipped. Missed changes and queue overflow are repaired by periodic folder reconciliation.</p>
    <h3>Watched folders</h3><div id="monitor-folders">${monitorFolders()}</div>
    ${btn('Add monitored folder', 'monitor-folder', '', 'small')}
    <h3>Recent monitoring issues</h3><div id="monitor-issues">${monitorIssues()}</div>
    <div id="analysis-status">${analysisStatus()}</div>
    <p>Save preferences to apply folder and resource changes. Optional service installation instructions are included in the project documentation.</p>
  </section>`;
}
function monitorFolders() {
  return (
    (draft.monitoring?.folders || [])
      .map(
        (folder, i) =>
          `<div class="setting-row"><span class="path">${esc(folder)}</span>${btn('Remove', 'monitor-remove', String(i), 'small')}</div>`
      )
      .join('') || '<p>Downloads and user/system Temp folders will be used when monitoring is enabled.</p>'
  );
}
function analysisStatus() {
  const r = state.monitoring?.rules,
    b = state.monitoring?.behavior;
  return `<h3>Additional detection layers</h3><p>YARA rules: ${esc(r?.version ? r.version.slice(0, 12) + ' · ' + (r.updated || '') : 'No active feed')}${r?.error ? ' · ' + esc(r.error) : ''}</p><p>Behavior: ${esc(b?.enabled ? b.error || `${b.processes || 0} processes · ${b.connections || 0} connections · sampled ${b.at || 'pending'}` : 'Off')}</p>${(b?.alerts || []).map(a => `<p>${esc(a.message)}: ${esc(a.name)} (PID ${esc(a.pid)})</p>`).join('')}`;
}
function monitorIssues() {
  return (
    (state.monitoring?.recent || [])
      .map(e => `<p><span class="path">${esc(e.path)}</span> — ${esc(e.message)}</p>`)
      .join('') || '<p>No recent issues.</p>'
  );
}
function patchDetections() {
  const container = document.querySelector('#live-review');
  if (container) {
    const html = reviewQueue();
    if (container.innerHTML !== html) container.innerHTML = html;
  }
  const nav = document.querySelector('[data-action="navigate"][data-value="activity"]');
  if (nav) {
    nav.querySelector('.pill')?.remove();
    if (unresolved().length)
      nav.insertAdjacentHTML('beforeend', ` <span class="pill red">${unresolved().length}</span>`);
  }
}

const pages = { overview, scans: scanCenter, schedules, quarantine, activity, settings };

// The header badge is outside the page body, so status changes stay visible even while a report is
// expanded or a field is being edited, without rebuilding the page (R16).
function updateHealthBadge() {
  const el = document.querySelector('#health-badge');
  if (!el || !state) return;
  const [text, tone] = healthPill[state.health.state];
  el.className = `pill header-health ${tone}`;
  el.textContent = text;
  el.title = state.health.headline;
}

// Unsaved schedule or preference edits are never discarded silently (R16).
const editsSettings = () => current === 'schedules' || current === 'settings';
const dirty = () => editsSettings() && draft && JSON.stringify(draft) !== JSON.stringify(state.settings);
let pendingNavigation = null;
function askAboutUnsavedChanges(destination) {
  pendingNavigation = destination;
  if (document.querySelector('#unsaved')) return;
  document
    .querySelector('#main')
    .insertAdjacentHTML(
      'afterbegin',
      `<div id="unsaved" class="notice warn unsaved" role="alert"><span>You have unsaved changes on this page.</span><span class="row">${btn('Save and continue', 'unsaved-save', '', 'small primary')}${btn('Discard changes', 'unsaved-discard', '', 'small')}${btn('Stay here', 'unsaved-stay', '', 'small')}</span></div>`
    );
  window.scrollTo(0, 0);
}
function navigate(value) {
  current = value;
  pendingNavigation = null;
  draft = structuredClone(state.settings);
  render();
  window.scrollTo(0, 0);
}

function render() {
  if (!state) return;
  stale = false;
  document.querySelector('#crumb').textContent = views.find(v => v[0] === current)[2];
  document.querySelector('#app-version').textContent = 'v' + state.version;
  updateHealthBadge();
  const badge = unresolved().length;
  document.querySelector('#nav').innerHTML = views
    .map(
      ([key, image, label]) =>
        `<button data-action="navigate" data-value="${key}" class="${current === key ? 'active' : ''}" ${current === key ? 'aria-current="page"' : ''}>${icon(image)}${label}${key === 'activity' && badge ? ` <span class="pill red" aria-label="${badge} unresolved">${badge}</span>` : ''}</button>`
    )
    .join('');
  document.querySelector('#main').innerHTML = pages[current]();
}

// A state update is deferred while the user edits a field or reads an expanded report; it is applied as
// soon as that interaction ends so the page never stays out of date.
const interacting = () => document.activeElement?.matches('input,select') || !!document.querySelector('details[open]');
function renderWhenIdle() {
  if (interacting()) stale = true;
  else render();
}
document.addEventListener('focusout', () => setTimeout(() => stale && renderWhenIdle()));
document.addEventListener('toggle', () => stale && renderWhenIdle(), true);

// ---- Events ----

document.addEventListener('change', event => {
  const el = event.target;
  if (el.dataset.monitor) draft.monitoring[el.dataset.monitor] = el.type === 'checkbox' ? el.checked : Number(el.value);
  if (el.dataset.setting) draft[el.dataset.setting] = el.type === 'checkbox' ? el.checked : Number(el.value);
  if (el.dataset.schedule) {
    const s = draft.schedules.find(s => s.id === el.dataset.schedule);
    s[el.dataset.field] =
      el.type === 'checkbox' ? el.checked : el.dataset.field === 'day' ? Number(el.value) : el.value;
  }
});

// Buttons whose action maps to a different request.
const requests = {
  save: () => ['settings', draft],
  'quarantine-finish': id => ['quarantine-resolve', { id, action: 'finish' }],
  'quarantine-undo': id => ['quarantine-resolve', { id, action: 'undo' }],
  'quarantine-dismiss': id => ['quarantine-resolve', { id, action: 'dismiss' }]
};

document.addEventListener('click', async event => {
  const button = event.target.closest('[data-action]');
  if (!button) return;
  const { action, value } = button.dataset;
  if (action === 'monitor-folder') {
    try {
      const folder = await call('monitor-folder');
      if (folder) draft.monitoring.folders = [...new Set([...draft.monitoring.folders, folder])];
    } catch (err) {
      toast(err.message);
    }
    document.querySelector('#monitor-folders').innerHTML = monitorFolders();
    return;
  }
  if (action === 'monitor-remove') {
    draft.monitoring.folders.splice(Number(value), 1);
    document.querySelector('#monitor-folders').innerHTML = monitorFolders();
    return;
  }
  if (action === 'monitor-pause') {
    try {
      await call('monitor-pause', Number(value));
    } catch (err) {
      toast(err.message);
    }
    return;
  }
  if (action === 'navigate') {
    if (value !== current && dirty()) return askAboutUnsavedChanges(value);
    return navigate(value);
  }
  if (action === 'unsaved-stay') {
    pendingNavigation = null;
    return document.querySelector('#unsaved')?.remove();
  }
  if (action === 'unsaved-discard') return navigate(pendingNavigation);
  if (action === 'unsaved-save') {
    try {
      await call('settings', draft);
      state = await call('state');
      toast('Your preferences are saved.');
      return navigate(pendingNavigation);
    } catch (err) {
      return toast(err.message);
    }
  }
  const key = action + ':' + value;
  if (pending.has(key)) return;
  pending.add(key);
  button.disabled = true;
  try {
    const [name, payload] = requests[action] ? requests[action](value) : [action, value];
    await call(name, payload);
    state = await call('state');
    if (action === 'save') {
      draft = structuredClone(state.settings);
      toast('Your preferences are saved.');
    }
    if (['scan', 'custom'].includes(action)) current = 'scans';
    if (action === 'install' && state.engine.runnable) toast('ClamAV setup completed. You’re ready to scan.');
    if (action === 'update') toast('Signature database updated.');
    render();
  } catch (err) {
    toast(err.message);
    button.disabled = false;
  } finally {
    pending.delete(key);
  }
});

window.sentinel.subscribe((kind, data) => {
  if (kind === 'monitor') {
    if (!state) return;
    Object.assign(state, data);
    patch();
    updateHealthBadge();
    if (data.detections) patchDetections();
    const issues = document.querySelector('#monitor-issues');
    if (issues) issues.innerHTML = monitorIssues();
    const analysis = document.querySelector('#analysis-status');
    if (analysis) analysis.innerHTML = analysisStatus();
    return;
  }
  if (kind === 'progress') {
    if (!state) return;
    Object.assign(state, data);
    patch();
    return;
  }
  state = data;
  if (!draft) draft = structuredClone(state.settings);
  updateHealthBadge();
  patchDetections();
  renderWhenIdle();
});

call('state')
  .then(next => {
    state = next;
    draft = structuredClone(state.settings);
    render();
  })
  .catch(err => toast(err.message));
