const icons = {
  shield: '<path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6Z"/><path d="m8 12 3 3 5-6"/>',
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
  toastTimer;
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

function btn(text, action, value = '', cls = '', disabled = false, image = '') {
  return `<button class="btn ${cls}" data-action="${action}" data-value="${esc(value)}" ${disabled ? 'disabled' : ''}>${image ? icon(image) : ''}${text}</button>`;
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
function scheduleText(s) {
  return `${s.frequency === 'daily' ? 'Every day' : 'Every ' + days[s.day]} at ${s.time}`;
}
const busyEngine = () => !!state.active || state.updating || !!state.installing;

// ---- Live values ----
// Elements marked data-live are updated in place by progress events, so the page is not
// rebuilt while a scan or update streams output (which would reset focus and selection).

const live = {
  files: () => (state.active ? state.active.files.toLocaleString() + ' files checked' : ''),
  counts: () =>
    state.active ? `${state.active.threats.length} detections · ${state.active.warnings.length} warnings` : '',
  current: () => state.active?.current ?? '',
  installOutput: () => state.installOutput || 'Starting…',
  updateOutput: () => state.updateOutput
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
  const disabled = busyEngine() || !state.engine.ready;
  return `<div class="scan-grid">${cards
    .map(([kind, image, tag, desc]) => {
      const tone = kind === 'quick' ? 'green' : kind === 'custom' ? 'purple' : '';
      const button =
        kind === 'custom'
          ? btn('Choose folder', 'custom', kind, '', disabled, 'arrow')
          : btn('Start ' + labels[kind].toLowerCase(), 'scan', kind, '', disabled, 'arrow');
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
        <div><div class="eyebrow">SCAN IN PROGRESS</div><h2>${labels[a.kind]} ${a.scheduled ? '· scheduled' : ''}</h2></div>
        ${btn('Stop scan', 'cancel', '', 'small danger', a.status === 'cancelling')}
      </div>
      <div class="progress-track"><i></i></div>
      <div class="row spread">
        <strong data-live="files">${esc(live.files())}</strong>
        <span class="muted" data-live="counts">${esc(live.counts())}</span>
      </div>
      <p class="path" data-live="current">${esc(live.current())}</p>
      <p>Scanning time depends on file count and size. A percentage is not available.</p>
    </section>`;
}

function overview() {
  const ready = state.engine.ready;
  const last = state.history[0];
  const unresolved = state.history.flatMap(h => h.threats).filter(t => t.status === 'detected').length;
  const title = !ready
    ? 'A safer routine starts here.'
    : unresolved
      ? 'A few files need your attention.'
      : state.active
        ? 'Taking a closer look.'
        : 'Your next scan is covered.';
  const sub = !ready
    ? 'Set up the ClamAV engine, then let Sentinel take care of your daily and weekly scans.'
    : unresolved
      ? 'Review the detections from your scans and decide what to quarantine.'
      : 'A little peace of mind, on your schedule. Your scans and signature updates are managed here.';
  const status = pill(
    !ready ? 'SETUP REQUIRED' : unresolved ? 'REVIEW DETECTIONS' : 'SCHEDULED SCANNING',
    !ready || unresolved ? 'amber' : ''
  );
  const action = !ready
    ? btn('Set up protection', 'navigate', 'settings', 'primary', false, 'arrow')
    : unresolved
      ? btn('Review activity', 'navigate', 'activity', 'primary')
      : btn('Run quick scan', 'scan', 'quick', 'primary', !!state.active || state.updating, 'scan');

  const hero = `
    <section class="hero">
      <div class="hero-mark">${icon('shield')}</div>
      <div class="hero-copy">${status}<h2>${title}</h2><p>${sub}</p></div>
      <div class="hero-actions">${action}<small>Powered by open-source ClamAV</small></div>
    </section>`;

  const metric = (tone, image, caption, value, detail) => `
    <div class="card metric">
      <div class="icon-box ${tone}">${icon(image)}</div>
      <div><div class="caption">${caption}</div><strong>${value}</strong><small>${detail}</small></div>
    </div>`;
  const metrics = `<div class="metrics">${
    metric(
      'green',
      'shield',
      'SCAN ENGINE',
      ready ? 'Ready to scan' : 'Setup needed',
      state.engine.available ? esc(state.engine.version.split('/')[0]) : 'ClamAV is not installed'
    ) +
    metric(
      '',
      'clock',
      'LAST SCAN',
      last ? date(last.finished) : 'No scans yet',
      last ? labels[last.kind] + ' · ' + last.status : 'Your first scan is a fresh start'
    ) +
    metric(
      'purple',
      'refresh',
      'SIGNATURE DATABASE',
      state.updating ? 'Updating…' : state.lastUpdate ? 'Downloaded' : 'Not downloaded',
      state.lastUpdate ? 'Updated ' + date(state.lastUpdate) : 'Latest definitions on setup'
    )
  }</div>`;

  const routine = state.settings.schedules
    .map(
      s => `
        <div class="schedule-mini">
          <div class="icon-box">${icon(s.id === 'quick' ? 'bolt' : 'monitor')}</div>
          <div><strong>${labels[s.id]}</strong><p>${scheduleText(s)}</p></div>
          ${pill(s.enabled ? 'Scheduled' : 'Paused', s.enabled ? '' : 'neutral')}
        </div>`
    )
    .join('');
  const recent = `
    <div class="empty">
      ${icon(last ? 'check' : 'activity')}
      <div>
        <strong>${last ? labels[last.kind] + ' ' + last.status : 'A clean slate'}</strong>
        <p>${last ? last.files.toLocaleString() + ' files checked · ' + last.threats.length + ' detections' : 'Completed scans and detections will appear here.'}</p>
      </div>
    </div>`;

  return (
    heading(
      'Security overview',
      'A clear view of your device. A little more peace of mind.',
      pill('WINDOWS DESKTOP', 'neutral')
    ) +
    hero +
    activeScan() +
    metrics +
    `<div class="section-title"><h2>Make a scan your own</h2><span>Three ways to check your device</span></div>` +
    scans() +
    `<div class="bottom-grid">
      <section class="card panel">
        <div class="panel-top"><h2>Your scan routine</h2><button class="link" data-action="navigate" data-value="schedules">Manage schedule →</button></div>
        ${routine}
      </section>
      <section class="card panel">
        <div class="panel-top"><h2>Recent activity</h2><button class="link" data-action="navigate" data-value="activity">View all →</button></div>
        ${recent}
        <p>Scheduled and on-demand scanning. Real-time file monitoring is not included.</p>
      </section>
    </div>`
  );
}

function scanCenter() {
  return (
    heading('Scan center', 'A quick check or a closer look. You’re in control.') +
    (!state.engine.ready
      ? `<div class="notice warn">Finish engine setup in Settings before starting your first scan.</div>`
      : '') +
    activeScan() +
    scans() +
    `<div class="notice scan-progress">Full scans inspect accessible files on local fixed drives. Windows permissions and ClamAV limits can prevent files from being scanned; review warnings in the scan report.</div>`
  );
}

function scheduleCard(s) {
  const saved = state.settings.schedules.find(x => x.id === s.id);
  const option = (value, text, selected) => `<option value="${value}" ${selected ? 'selected' : ''}>${text}</option>`;
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
      <p>Next saved run: ${s.enabled ? date(saved.next) : 'Paused'} · Uses this device’s local timezone</p>
    </section>`;
}

function schedules() {
  return (
    heading(
      'Your scan routine',
      'Set it once. Let Sentinel keep the rhythm.',
      btn('Save changes', 'save', '', 'primary')
    ) +
    `<div class="notice">Schedules run while Sentinel is open or in the system tray. Missed scans run after the app resumes. Enable launch at sign-in in Settings to keep your routine running.</div>` +
    `<div class="stack">${draft.schedules.map(scheduleCard).join('')}</div>`
  );
}

function historyItem(h) {
  const tone = ['error', 'partial'].includes(h.status)
    ? 'amber'
    : h.threats.length
      ? 'red'
      : h.status === 'cancelled'
        ? 'neutral'
        : '';
  const threats = h.threats
    .map(
      t => `
        <div class="threat">
          <strong>${esc(t.signature)}</strong>
          <div class="path">${esc(t.path)}</div>
          ${t.status === 'detected' ? btn('Quarantine file', 'quarantine', t.id, 'small danger') : pill(t.status)}
        </div>`
    )
    .join('');
  return `
    <details class="history-item">
      <summary>
        <div>
          <strong>${labels[h.kind]} ${h.scheduled ? '· scheduled' : ''}</strong>
          <small>${date(h.finished)} · ${h.files.toLocaleString()} files · ${h.threats.length} detections</small>
        </div>
        ${pill(h.status, tone)}
      </summary>
      <div class="history-detail">
        <p class="path">${h.targets.map(esc).join(' · ')}</p>
        ${h.warnings.length ? `<div class="notice warn">${h.warnings.map(esc).join('<br>')}</div>` : ''}
        ${threats}
        <div class="row">${btn('Export report', 'export', h.id, 'small', false, 'download')}</div>
      </div>
    </details>`;
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
    ) + `<section class="card panel">${body}</section>`
  );
}

function quarantine() {
  const body = state.quarantine.length
    ? state.quarantine
        .map(
          q => `
            <div class="history-item">
              <div class="row spread"><h3>${esc(q.signature)}</h3>${pill(q.status, q.status === 'error' ? 'red' : 'neutral')}</div>
              <p class="path">${esc(q.original)}</p>
              <p>${date(q.date)}</p>
              ${q.error ? `<p>${esc(q.error)}</p>` : ''}
              ${q.status === 'quarantined' ? btn('Restore file', 'restore', q.id, 'small') : ''}
            </div>`
        )
        .join('')
    : `<div class="wide-empty">${icon('box')}<h2>Nothing in quarantine.</h2><p>When a scan detects a threat, review it in Activity and choose whether to quarantine the file.</p></div>`;
  return (
    heading('Quarantine', 'Keep detected files out of their original location.') +
    `<div class="notice">Quarantine moves a file into Sentinel’s local storage with a non-executable extension. Files are never automatically deleted. Restore only files you trust.</div>` +
    `<section class="card panel">${body}</section>`
  );
}

function engineSection() {
  const { engine, installing, updating } = state;
  const steps = `
    <div class="setup-steps">
      <div class="step"><div class="step-number">1</div><h3>Install the engine</h3><p>Private, per-user installation. No administrator access required.</p></div>
      <div class="step"><div class="step-number">2</div><h3>Get fresh definitions</h3><p>Download ClamAV’s official malware signature database.</p></div>
      <div class="step"><div class="step-number">3</div><h3>Make it a routine</h3><p>Daily quick scans and weekly full scans are ready to go.</p></div>
    </div>`;
  const primary = !engine.available
    ? btn(
        installing ? 'Installing ClamAV…' : 'Install ClamAV & set up',
        'install',
        '',
        'primary',
        !!installing,
        'download'
      )
    : btn(updating ? 'Updating definitions…' : 'Update definitions', 'update', '', 'primary', busyEngine(), 'refresh');
  return `
    <section class="card panel">
      <div class="panel-top">
        <div><div class="eyebrow">ENGINE & DEFINITIONS</div><h2>${engine.ready ? 'Your ClamAV engine is ready' : 'Welcome. Let’s get you set up.'}</h2></div>
        ${pill(engine.ready ? 'Ready' : 'Setup required', engine.ready ? '' : 'amber')}
      </div>
      <p>Install the official ClamAV engine and its signature database with one click. Sentinel downloads the Windows engine from Cisco Talos and verifies its SHA-256 checksum.</p>
      ${engine.ready ? `<p class="path">${esc(engine.version)}<br>${esc(engine.dir)}</p>` : steps}
      <div class="row">
        ${primary}
        ${btn('Use existing installation', 'engine', '', '', busyEngine())}
        ${btn('ClamAV website', 'download', '', 'small')}
      </div>
      ${installing || state.installOutput ? `<pre class="log" data-live="installOutput">${esc(live.installOutput())}</pre>` : ''}
      ${state.updateOutput ? `<pre class="log" data-live="updateOutput">${esc(live.updateOutput())}</pre>` : ''}
      <div class="setting-row">
        <div><h3>Keep definitions up to date</h3><p>Check hourly while Sentinel runs. Failed updates retry with increasing delays, up to every six hours.</p></div>
        <input class="toggle" type="checkbox" aria-label="Automatic signature updates" data-setting="autoUpdate" ${draft.autoUpdate ? 'checked' : ''}>
      </div>
      <p>Last successful update: ${date(state.lastUpdate)}</p>
    </section>`;
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
      ${engineSection()}
      <section class="card panel">
        <h2>Desktop experience</h2>
        ${toggle('launchAtLogin', 'Launch at Windows sign-in', state.packaged ? 'Start quietly in the system tray so schedules can run.' : 'Available after installing the packaged Windows app.')}
        ${toggle('closeToTray', 'Keep running when the window closes', 'Continue scheduled scans and updates from the system tray.')}
        ${toggle('notifications', 'Desktop notifications', 'Get notified when scans finish or something needs attention.')}
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

const pages = { overview, scans: scanCenter, schedules, quarantine, activity, settings };

function render() {
  if (!state) return;
  document.querySelector('#crumb').textContent = views.find(v => v[0] === current)[2];
  document.querySelector('#app-version').textContent = 'v' + state.version;
  document.querySelector('#nav').innerHTML = views
    .map(
      ([key, image, label]) =>
        `<button data-action="navigate" data-value="${key}" class="${current === key ? 'active' : ''}" ${current === key ? 'aria-current="page"' : ''}>${icon(image)}${label}</button>`
    )
    .join('');
  document.querySelector('#main').innerHTML = pages[current]();
}

// ---- Events ----

document.addEventListener('change', event => {
  const el = event.target;
  if (el.dataset.setting) draft[el.dataset.setting] = el.checked;
  if (el.dataset.schedule) {
    const s = draft.schedules.find(s => s.id === el.dataset.schedule);
    s[el.dataset.field] =
      el.type === 'checkbox' ? el.checked : el.dataset.field === 'day' ? Number(el.value) : el.value;
  }
});

document.addEventListener('click', async event => {
  const button = event.target.closest('[data-action]');
  if (!button) return;
  const { action, value } = button.dataset;
  if (action === 'navigate') {
    current = value;
    draft = structuredClone(state.settings);
    render();
    window.scrollTo(0, 0);
    return;
  }
  const key = action + ':' + value;
  if (pending.has(key)) return;
  pending.add(key);
  button.disabled = true;
  try {
    await call(action === 'save' ? 'settings' : action, action === 'save' ? draft : value);
    state = await call('state');
    if (action === 'save') {
      draft = structuredClone(state.settings);
      toast('Your preferences are saved.');
    }
    if (['scan', 'custom'].includes(action)) current = 'scans';
    if (action === 'install') toast('ClamAV setup completed. You’re ready to scan.');
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
  if (kind === 'progress') {
    if (!state) return;
    Object.assign(state, data);
    patch();
    return;
  }
  state = data;
  if (!draft) draft = structuredClone(state.settings);
  // Avoid rebuilding the page while the user is editing a field or reading an expanded report.
  if (!document.activeElement?.matches('input,select') && !document.querySelector('details[open]')) render();
});

call('state')
  .then(next => {
    state = next;
    draft = structuredClone(state.settings);
    render();
  })
  .catch(err => toast(err.message));
