const { app, BrowserWindow, Tray, Menu, ipcMain, dialog, shell, Notification, powerMonitor } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { spawn, execFile } = require('node:child_process');
const { pathToFileURL } = require('node:url');
const { validateSettings, scanArgs, parseLine } = require('./core.cjs');
const { install } = require('./installer.cjs');
const { createStore } = require('./store.cjs');
const scheduler = require('./scheduler.cjs');
const detectionStore = require('./detections.cjs');
const { createQuarantine } = require('./quarantine.cjs');
const { startScan, reportStatus } = require('./scanner.cjs');
const databaseInfo = require('./database.cjs');
const { assess, capability, classifyUpdateFailure } = require('./health.cjs');
const { identify } = require('./files.cjs');
const { createJournal } = require('./journal.cjs');
const logFiles = require('./logs.cjs');
const { createCoordinator, OperationConflict } = require('./operations.cjs');
const { assessCoverage, coversTargets } = require('./coverage.cjs');
const { createFatalHandler, nextCrashState } = require('./fatal.cjs');
const { loadState, applyScan, verifyLinks, SPECS, SAVE_ORDER } = require('./state.cjs');

app.setAppUserModelId('com.wellspring.sentinel');
// The smoke test module is not packaged, so the flag only works from a source checkout.
const smokeArg = process.argv.find(a => a.startsWith('--smoke-test'));
const smoke = !app.isPackaged && !!smokeArg;
// '--smoke-test' runs the standard checks; '--smoke-test=crash-start' and '=crash-recover' run a
// two-launch crash-recovery scenario against the profile named by SENTINEL_SMOKE_PROFILE.
const smokeMode = smoke ? smokeArg.split('=')[1] || 'standard' : null;
if (smoke) app.disableHardwareAcceleration();
if (smoke)
  app.setPath(
    'userData',
    process.env.SENTINEL_SMOKE_PROFILE || path.join(os.tmpdir(), 'sentinel-smoke-' + process.pid)
  );

const HOUR = 3600000;
const UPDATE_TIMEOUT = 20 * 60000;
const SHUTDOWN_TIMEOUT = 10000;

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  const root = app.getPath('userData');
  const db = path.join(root, 'database');
  const logs = path.join(root, 'logs');
  const { scans: scanLogs, app: appLogs } = logFiles.layout(logs);
  const vault = path.join(root, 'quarantine');
  const page = pathToFileURL(path.join(__dirname, '../ui/index.html')).href;
  const icon = path.join(__dirname, '../assets/icon.png');
  const store = createStore(root);
  const journal = createJournal(path.join(root, 'journal'));

  // ---- State ----
  // Persisted
  let settings, reports, detections, quarantineRecords, updates, scheduleRuntime, jobs;
  // Runtime
  let engine = { installed: false, runnable: false };
  let database = { present: false, missing: ['main', 'daily'], files: [], verified: null, failures: [] };
  let active = null; // the scan report in progress
  let activeScan = null; // { handle, control, done }
  let update = null; // { proc, done }
  let installation = null; // { abort, done }
  let updateOutput = '',
    installOutput = '';
  let storageIssues = [];
  let win, tray, tickTimer;
  let ticking = false,
    shuttingDown = false,
    shutdownComplete = false,
    shutdownPromise = null;
  let lastEmit = 0,
    progressTimer = null;

  // Every scan, update, install, database check, file operation, and hashing pass runs through the
  // coordinator, which enforces the conflict matrix and lets shutdown wait for running work (R08).
  const operations = createCoordinator();
  // Execution policy comes from the same capability snapshot the UI and tray show (R01).
  const currentCapability = () => capability({ engine, database, now: new Date(), settings });
  const ready = () => currentCapability().canScan;
  const withWindow = fn => {
    if (win && !win.isDestroyed()) return fn(win);
  };
  const dialogParent = () => withWindow(w => w) || undefined;

  // ---- Persistence ----
  const current = {
    settings: () => settings,
    history: () => reports,
    detections: () => detections,
    quarantine: () => quarantineRecords,
    updates: () => updates,
    schedule: () => scheduleRuntime,
    jobs: () => jobs
  };
  function persist(...names) {
    for (const name of names) store.save(name, current[name](), SPECS[name].version);
  }
  const persistAll = () => persist(...SAVE_ORDER);
  // Storage problems are shown once each (R13), not appended on every retry.
  function addStorageIssue(issue) {
    if (storageIssues.some(i => i.file === issue.file && i.message === issue.message)) return;
    storageIssues = [...storageIssues, issue].slice(-20);
  }
  // For saves after work already happened: the failure is surfaced, but cleanup and the original
  // outcome are never lost because of it.
  function persistQuietly(...names) {
    try {
      persist(...names);
      return true;
    } catch (err) {
      addStorageIssue({ file: err.file ? path.basename(err.file) : names.join(', '), message: err.message });
      notify('Sentinel could not save its data', err.message, 'storage');
      return false;
    }
  }

  // Mutable view of the state for the transaction helpers in state.cjs.
  const stateView = () => ({
    settings,
    reports,
    detections,
    quarantine: quarantineRecords,
    updates,
    scheduleRuntime,
    jobs
  });
  function adopt(view) {
    reports = view.reports;
    detections = view.detections;
  }

  function loadAll() {
    const now = new Date();
    const { state: loaded, issues } = loadState(store, { now, dataRoot: root });
    issues.forEach(addStorageIssue);
    ({ settings, reports, detections, updates, scheduleRuntime, jobs } = loaded);
    quarantineRecords = loaded.quarantine;
    const view = stateView();
    const links = verifyLinks(view);
    adopt(view);
    if (links.repaired)
      addStorageIssue({
        file: 'detections',
        message: `${links.repaired} detection link(s) were missing and were reopened for review.`
      });
    for (const message of links.ambiguous) addStorageIssue({ file: 'quarantine', message });
    persistQuietly(...SAVE_ORDER);
  }

  // Applies every scan journal left behind by a crash or failed save. Idempotent, so a crash during this
  // recovery is repaired by running it again. A journal is deleted only after the stores are saved.
  function recoverJournals() {
    const now = new Date();
    for (const id of journal.list()) {
      let replay;
      try {
        replay = journal.read(id);
      } catch (err) {
        addStorageIssue({ file: 'journal', message: 'A scan journal could not be read: ' + err.message });
        continue;
      }
      if (!replay.header) {
        journal.remove(id); // torn before the scan was acknowledged
        continue;
      }
      const view = stateView();
      applyScan(view, replay, now);
      adopt(view);
      if (persistQuietly(...SAVE_ORDER)) journal.remove(id);
    }
    recoverLegacyRunningScan(now);
  }

  // Version 1.1.0 marked a running scan in jobs.json and relied on its log. Convert such a marker into a
  // journal replay; the log is read with a hard size bound (R13).
  function recoverLegacyRunningScan(now) {
    const job = jobs.current;
    if (!job) return;
    const detectionsFromLog = [];
    let files = 0;
    try {
      const fd = fs.openSync(path.join(scanLogs, job.reportId + '.log'), 'r');
      try {
        const size = Math.min(fs.fstatSync(fd).size, 64 * 1048576);
        const buffer = Buffer.alloc(size);
        fs.readSync(fd, buffer, 0, size, 0);
        buffer
          .toString('utf8')
          .split(/\r?\n/)
          .forEach((line, index) => {
            const parsed = parseLine(line.trim());
            if (parsed.type === 'file') files++;
            if (parsed.type === 'threat')
              detectionsFromLog.push({
                eventId: `${job.reportId}-${index}`,
                path: parsed.path,
                signature: parsed.signature,
                at: now.toISOString()
              });
          });
      } finally {
        fs.closeSync(fd);
      }
    } catch {}
    const view = stateView();
    applyScan(
      view,
      { header: job, targets: job.targets || [], detections: detectionsFromLog, progress: { files }, commit: null },
      now
    );
    adopt(view);
    jobs.current = null;
    persistQuietly(...SAVE_ORDER);
  }

  // ---- Publishing state ----
  function lastScanSummaries() {
    return { lastScan: reports[0] || null, lastSuccessfulScan: jobs.lastSuccessfulScan };
  }
  function health() {
    const now = new Date();
    const { lastScan, lastSuccessfulScan } = lastScanSummaries();
    return assess({
      now,
      busy: { scanning: !!active, updating: !!update, installing: !!installation },
      engine,
      database,
      settings,
      updates,
      upcoming: scheduler.upcoming(settings.schedules, scheduleRuntime, now),
      pendingRetries: settings.schedules
        .filter(s => s.enabled && scheduleRuntime[s.id]?.pending)
        .map(s => ({ id: s.id, ...scheduleRuntime[s.id].pending })),
      lastSuccessfulScan,
      lastScan,
      unresolved: detections.filter(detectionStore.isUnresolved).length,
      quarantineReview: quarantineRecords.filter(q => q.status === 'recovery-needed').length,
      storageIssues: storageIssues.length
    });
  }
  function state() {
    return {
      settings,
      history: reports,
      detections,
      quarantine: quarantineRecords,
      schedule: {
        runtime: scheduleRuntime,
        upcoming: scheduler.upcoming(settings.schedules, scheduleRuntime, new Date())
      },
      updates,
      database: { ...database, files: undefined },
      engine,
      health: health(),
      active,
      operations: operations.active(),
      updating: !!update,
      installing: !!installation,
      updateOutput,
      installOutput,
      storageIssues,
      dataRoot: root,
      packaged: app.isPackaged,
      version: app.getVersion()
    };
  }
  // Forced publishes send the full state after a state change. Frequent progress output is
  // throttled and sends only the fields that change during a scan, update, or install.
  function publish(force = false) {
    if (force) {
      clearTimeout(progressTimer);
      progressTimer = null;
      lastEmit = Date.now();
      const next = state();
      if (tray && !tray.isDestroyed()) tray.setToolTip(next.health.tooltip);
      withWindow(w => w.webContents.send('state', next));
    } else if (!progressTimer) {
      progressTimer = setTimeout(
        () => {
          progressTimer = null;
          lastEmit = Date.now();
          withWindow(w => w.webContents.send('progress', { active, updateOutput, installOutput }));
        },
        Math.max(0, 300 - (Date.now() - lastEmit))
      );
    }
  }

  // Repeated failures of the same kind notify once, not on every retry.
  const notified = new Map();
  function notify(title, body, topic = null) {
    if (topic) {
      if (notified.get(topic) === body) return;
      notified.set(topic, body);
    }
    if (settings?.notifications && Notification.isSupported()) new Notification({ title, body, icon }).show();
  }
  const clearNotified = topic => notified.delete(topic);

  // ---- Processes ----
  function run(exe, args, options = {}) {
    return new Promise((resolve, reject) =>
      execFile(
        exe,
        args,
        { windowsHide: true, timeout: 15000, maxBuffer: 4 * 1024 * 1024, ...options },
        (err, stdout, stderr) => {
          if (err) {
            err.output = `${stdout}\n${stderr}`;
            reject(err);
          } else resolve(`${stdout}\n${stderr}`.trim());
        }
      )
    );
  }
  // Force-terminates a process Sentinel started (and its children), by PID only.
  function forceKill(pid) {
    if (pid) execFile('taskkill.exe', ['/PID', String(pid), '/T', '/F'], { windowsHide: true }, () => {});
  }

  // ---- Engine and database ----
  async function detectEngine() {
    const candidates = [
      settings.engineDir,
      path.join(process.env.ProgramFiles || 'C:\\Program Files', 'ClamAV'),
      'C:\\ClamAV',
      ...(process.env.PATH || '').split(path.delimiter)
    ].filter(Boolean);
    let found = null;
    for (const dir of candidates) {
      const exe = path.join(dir, 'clamscan.exe');
      if (!fs.existsSync(exe)) continue;
      try {
        found = { installed: true, runnable: true, dir, version: (await run(exe, ['--version'])).split(/\r?\n/)[0] };
        break;
      } catch (err) {
        found ??= { installed: true, runnable: false, dir, error: 'clamscan.exe did not start: ' + err.message };
      }
    }
    engine = found || { installed: false, runnable: false };
    refreshDatabase();
    publish(true);
    return engine;
  }

  // Reads database headers immediately, then verifies signatures in the background. Verification and
  // load results are cached per database generation *and* engine identity (R01.4), and a check that was
  // superseded by a database change is re-run for the new generation (R15).
  const engineKey = () => `${engine.dir || ''}|${engine.version || ''}`;
  let verifying = null;
  function databaseCache(info) {
    const cached = updates.database;
    return cached?.fingerprint === info.fingerprint && cached.engine === engineKey() ? cached : null;
  }
  function refreshDatabase() {
    const info = databaseInfo.inspect(db);
    const cached = databaseCache(info);
    const sigtool = engine.installed ? path.join(engine.dir, 'sigtool.exe') : null;
    database = {
      ...info,
      verified: cached?.verified ?? null,
      failures: cached?.failures ?? [],
      loadFailed: !!cached?.loadFailed,
      verifyUnavailable: !!sigtool && !fs.existsSync(sigtool)
    };
    if (info.unreadable.length) Object.assign(database, { verified: false, failures: info.unreadable });
    else if (database.verified === null && info.present && sigtool && !database.verifyUnavailable) verifyDatabase(info);
  }
  function verifyDatabase(info, owned = false) {
    if (verifying) return verifying;
    // Never verify while definitions are being replaced; the update refreshes and re-verifies afterwards.
    const op = owned ? null : operations.tryBegin('verify', 'Verifying definitions');
    if (!owned && !op) return Promise.resolve();
    const sigtool = path.join(engine.dir, 'sigtool.exe');
    const key = engineKey();
    verifying = databaseInfo
      .verify(info.files, sigtool, (exe, args) => run(exe, args, { timeout: 120000 }))
      .then(result => {
        if (databaseInfo.inspect(db).fingerprint !== info.fingerprint || engineKey() !== key) return;
        const loadFailed = databaseCache(info)?.loadFailed ?? database.loadFailed;
        updates.database = {
          fingerprint: info.fingerprint,
          engine: key,
          ...result,
          loadFailed,
          verifiedAt: new Date().toISOString()
        };
        Object.assign(database, result);
        persistQuietly('updates');
      })
      .catch(() => {})
      .finally(() => {
        verifying = null;
        op?.end();
        // The files changed while being checked: verify the generation that is there now.
        refreshDatabase();
        publish(true);
      });
    return verifying;
  }
  function recordDatabaseLoad(failed) {
    database.loadFailed = failed;
    const cached = databaseCache(database);
    updates.database = cached
      ? { ...cached, loadFailed: failed }
      : {
          fingerprint: database.fingerprint,
          engine: engineKey(),
          verified: database.verified,
          failures: database.failures,
          loadFailed: failed
        };
  }
  // Repair path for a database ClamAV failed to load (R01.3): re-verify signatures, then run a
  // controlled load by scanning a small harmless file with this exact database.
  function recheckDatabase() {
    return operations.run('verify', 'Rechecking definitions', recheckDatabaseNow);
  }
  async function recheckDatabaseNow() {
    if (!engine.runnable) throw Error('Set up ClamAV first.');
    refreshDatabase();
    if (!database.present) throw Error('The signature database is missing. Update the definitions.');
    if (updates.database && updates.database.fingerprint === database.fingerprint) updates.database.verified = null;
    database.verified = null;
    if (!database.verifyUnavailable) await verifyDatabase(databaseInfo.inspect(db), true);
    const sample = path.join(root, 'load-check.txt');
    fs.writeFileSync(sample, 'Sentinel database load check. This file is harmless.');
    let loaded;
    try {
      await run(path.join(engine.dir, 'clamscan.exe'), ['--no-summary', '--database=' + db, sample], {
        timeout: 300000
      });
      loaded = true;
    } catch (err) {
      loaded = err.code === 1; // exit 1 means a match, which still proves the database loaded
    } finally {
      fs.rmSync(sample, { force: true });
    }
    recordDatabaseLoad(!loaded);
    persistQuietly('updates');
    publish(true);
    if (!loaded) throw Error('ClamAV still cannot load this database. Update the definitions to replace it.');
  }

  // ---- Signature updates ----
  function updateDue(now) {
    if (!settings.autoUpdate) return false;
    if (updates.nextAttempt && now < new Date(updates.nextAttempt)) return false;
    return !updates.lastCheck || now - new Date(updates.lastCheck) > HOUR;
  }
  // `owned` is set when an install already holds the operation that covers this update.
  function updateSignatures({ owned = false } = {}) {
    return owned ? runUpdate() : operations.run('update', 'Updating definitions', runUpdate);
  }
  async function runUpdate() {
    if (!engine.installed) throw Error('Set up ClamAV in Settings first.');
    const exe = path.join(engine.dir, 'freshclam.exe');
    const config = path.join(root, 'freshclam.conf');
    fs.writeFileSync(config, 'DatabaseMirror database.clamav.net\nDatabaseDirectory "' + db + '"\n');
    updateOutput = 'Connecting to the ClamAV signature service…';
    updates.lastCheck = new Date().toISOString();
    let output = '';
    update = { proc: null, done: null };
    update.done = new Promise(resolve => {
      let proc,
        settled = false;
      const finish = (code, error) => {
        if (settled) return;
        settled = true;
        clearTimeout(watchdog);
        resolve({ ok: !error && code === 0, code, error });
      };
      const watchdog = setTimeout(() => {
        output += '\nThe update did not finish within 20 minutes and was stopped.';
        forceKill(proc?.pid);
        finish(null, Error('Update timed out.'));
      }, UPDATE_TIMEOUT);
      try {
        proc = spawn(exe, ['--config-file=' + config, '--stdout'], { windowsHide: true });
      } catch (err) {
        return finish(null, err);
      }
      update.proc = proc;
      const append = data => {
        // Only a bounded tail is kept for classifying failures (R13).
        output = (output + data.toString()).slice(-65536);
        updateOutput = (updateOutput + '\n' + data.toString()).slice(-12000);
        publish();
      };
      proc.stdout.on('data', append);
      proc.stderr.on('data', append);
      proc.on('error', err => finish(null, err));
      proc.on('close', code => finish(code));
    });
    publish(true);
    const result = await update.done;
    const now = new Date();
    try {
      if (result.ok) {
        Object.assign(updates, { lastSuccess: now.toISOString(), failures: 0, failure: null, nextAttempt: null });
        clearNotified('update');
      } else {
        updates.failures++;
        updates.lastFailure = now.toISOString();
        updates.failure = shuttingDown
          ? { kind: 'cancelled', message: 'The update was stopped because Sentinel closed.' }
          : classifyUpdateFailure(output, result.error);
        // Persisted backoff survives restarts, so relaunching cannot cause a retry storm.
        const minutes = Math.min(15 * 2 ** (updates.failures - 1), 360);
        const floor = updates.failure.kind === 'rate-limit' ? 240 : 0;
        updates.nextAttempt = new Date(now.getTime() + Math.max(minutes, floor) * 60000).toISOString();
        updateOutput += '\n' + updates.failure.message;
      }
      persistQuietly('updates');
    } finally {
      update = null;
      refreshDatabase();
      publish(true);
    }
    if (!result.ok) throw Error(updates.failure.message);
  }

  const BLOCKING_MESSAGES = {
    'engine-missing': 'Set up ClamAV in Settings before scanning.',
    'engine-not-runnable': 'ClamAV could not start. Check the installation in Settings.',
    'database-missing': 'Download the signature database before scanning.',
    'database-invalid': 'The signature database failed verification. Update the definitions before scanning.',
    'database-load-failed': 'ClamAV could not load the signature database. Recheck or update it before scanning.'
  };
  const blockingMessage = reason => BLOCKING_MESSAGES[reason] || 'Scanning is not available right now.';

  // ---- Scanning ----
  const SCAN_NAMES = { quick: 'quick scan', full: 'full scan', custom: 'custom scan' };
  // Quick-scan locations, including redirected known folders reported by Windows.
  function quickTargets() {
    return [
      ...new Set(
        ['Desktop', 'Downloads', 'Documents']
          .map(n => path.join(os.homedir(), n))
          .concat(
            app.getPath('desktop'),
            app.getPath('documents'),
            app.getPath('downloads'),
            process.env.TEMP || os.tmpdir()
          )
      )
    ].filter(p => fs.existsSync(p));
  }
  async function targetsFor(kind, custom, signal) {
    if (kind === 'custom') return custom;
    if (kind === 'quick') return quickTargets();
    const output = await run(
      'powershell.exe',
      [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { $_.DeviceID + '\\' }"
      ],
      { signal }
    );
    const drives = output.split(/\r?\n/).filter(p => /^[A-Z]:\\$/i.test(p));
    if (!drives.length) throw Error('No local fixed drives could be found.');
    return drives;
  }

  function pruneLogs() {
    logFiles.pruneScanLogs(scanLogs, [...reports.map(r => r.id), ...(active ? [active.id] : [])]);
  }

  // Starts a scan and returns once it is running (or has failed to start). The result is recorded when
  // the scan finishes; `job` links a scheduled occurrence to its outcome.
  async function scan(kind, custom, job = null) {
    if (!['quick', 'full', 'custom'].includes(kind)) throw Error('Unknown scan type.');
    const cap = currentCapability();
    if (!cap.canScan) throw Error(blockingMessage(cap.blocking[0]));
    const op = operations.begin('scan', (job ? 'Scheduled ' : '') + SCAN_NAMES[kind]);
    const started = new Date();
    const report = {
      id: crypto.randomUUID(),
      kind,
      scheduled: !!job,
      started: started.toISOString(),
      status: 'running',
      phase: 'preparing',
      current: 'Preparing scan…',
      files: 0,
      threats: [],
      warnings: [],
      warningCount: 0,
      targets: [],
      engineVersion: engine.version,
      databaseVersion: database.version,
      options: {
        scanArchives: settings.scanArchives,
        detectPUA: settings.detectPUA,
        exclusions: settings.exclusions.length
      }
    };
    // The scan's journal is its durable record. No journal, no scan: a scan must never run untracked.
    const header = {
      reportId: report.id,
      kind,
      scheduleId: job?.scheduleId ?? null,
      occurrence: job?.occurrence ?? null,
      started: report.started,
      engineVersion: report.engineVersion,
      databaseVersion: report.databaseVersion,
      options: report.options,
      // The scope actually in force, so coverage claims can be checked against it later (R03.2).
      exclusions: [...settings.exclusions]
    };
    let writer;
    try {
      writer = journal.begin(report.id, header);
    } catch (err) {
      op.end();
      throw err;
    }
    const evidence = { writer, header, targets: [], detections: [], failure: null, op };
    active = report;
    const control = { abort: new AbortController(), cancelReason: null };
    let finished;
    activeScan = { control, handle: null, done: new Promise(resolve => (finished = resolve)) };
    publish(true);

    const complete = result => {
      clearInterval(progressTimer);
      finishScan(report, result, evidence);
      finished();
    };
    let targets;
    try {
      targets = await targetsFor(kind, custom, control.abort.signal);
      if (!targets?.length) throw Error('No scan locations are available.');
      scanArgs(settings, db, targets); // validates targets
    } catch (err) {
      complete({
        exitCode: null,
        error: control.cancelReason ? null : err.message,
        cancelReason: control.cancelReason,
        files: 0,
        threats: [],
        warnings: control.cancelReason ? [] : [err.message],
        warningCount: control.cancelReason ? 0 : 1
      });
      if (control.cancelReason) return report.id;
      err.recorded = true; // finishScan already recorded the outcome
      throw err;
    }
    report.targets = evidence.targets = targets;
    try {
      writer.append('targets', { targets });
    } catch (err) {
      evidence.failure = err.message;
    }
    // Periodic progress lets an interrupted report keep a meaningful file count.
    const progressTimer = setInterval(() => {
      try {
        writer.append('progress', { files: report.files });
      } catch {}
    }, 30000);
    let handle;
    handle = startScan({
      exe: path.join(engine.dir, 'clamscan.exe'),
      args: scanArgs(settings, db, targets),
      logPath: path.join(scanLogs, report.id + '.log'),
      spawn,
      forceKill,
      // A detection is acknowledged only once it is durable. If evidence cannot be recorded, the scan
      // stops rather than continuing to find things it cannot keep (R06).
      onThreat: threat => {
        const event = {
          eventId: crypto.randomUUID(),
          path: threat.path,
          signature: threat.signature,
          at: new Date().toISOString()
        };
        try {
          writer.append('detection', event);
          evidence.detections.push(event);
          report.threatCount = evidence.detections.length;
          // Smoke crash scenario: die abruptly once evidence is durable, before the scan can commit.
          if (smokeMode === 'crash-start') process.exit(0);
        } catch (err) {
          evidence.failure ??= err.message;
          handle?.cancel('evidence');
        }
      },
      onProgress: snapshot => {
        Object.assign(report, {
          phase: snapshot.phase,
          current: snapshot.current,
          files: snapshot.files,
          warningCount: snapshot.warningCount
        });
        publish();
      }
    });
    activeScan.handle = handle;
    withWindow(w => w.setProgressBar(2));
    handle.done.then(complete, err =>
      complete({ exitCode: null, error: err.message, files: 0, threats: [], warnings: [err.message], warningCount: 1 })
    );
    return report.id;
  }

  // Commits the scan: write the outcome to the journal, apply the journal's contents to the stores in one
  // idempotent transaction, save, and only then delete the journal (R09). A failure at any point leaves
  // the journal for startup recovery, which converges on the same result.
  function finishScan(report, result, evidence) {
    const now = new Date();
    let applied = report;
    try {
      let status = reportStatus(result);
      let error = result.error || null;
      if (result.cancelReason === 'evidence') {
        status = 'error';
        error = 'The scan was stopped because detections could not be saved: ' + evidence.failure;
        addStorageIssue({ file: 'journal', message: error });
      }
      // Coverage is separate from process outcome (R03): what was inspected, and what was not.
      const coverage = assessCoverage({
        status,
        targets: evidence.targets,
        warnings: result.warnings,
        warningCount: result.warningCount
      });
      if (coverage.targetFailures.length && coverage.targetFailures.length === evidence.targets.length) {
        status = 'error';
        error ??= 'None of the scan locations could be read.';
      }
      // A full scan settles a pending quick scan only if its evidence shows the quick locations were inspected.
      const coversQuick =
        evidence.header.kind === 'full' &&
        coversTargets(
          {
            status,
            targets: evidence.targets,
            warnings: result.warnings,
            warningCount: result.warningCount,
            exclusions: evidence.header.exclusions
          },
          quickTargets(),
          { sameExclusions: settings.exclusions }
        );
      const outcome = {
        status,
        coverage,
        finished: now.toISOString(),
        exitCode: result.exitCode,
        files: result.files,
        warnings: error && !result.warnings.includes(error) ? [error, ...result.warnings] : result.warnings,
        warningCount: result.warningCount,
        logTruncated: !!result.logTruncated,
        logError: result.logError || null,
        error,
        coversQuick
      };
      try {
        evidence.writer.append('commit', { outcome });
      } catch (err) {
        evidence.failure ??= err.message;
      }
      evidence.writer.close();
      if (result.databaseError) recordDatabaseLoad(true);
      else if (status === 'completed' || status === 'partial') recordDatabaseLoad(false);
      const view = stateView();
      applied = applyScan(
        view,
        {
          header: evidence.header,
          targets: evidence.targets,
          detections: evidence.detections,
          progress: { files: result.files },
          commit: outcome
        },
        now
      );
      adopt(view);
    } finally {
      // Cleanup happens even if recording the result failed.
      active = null;
      activeScan = null;
      evidence.op.end();
      if (persistQuietly(...SAVE_ORDER)) journal.remove(report.id);
      withWindow(w => w.setProgressBar(-1));
      publish(true);
      setImmediate(pruneLogs);
    }
    if (applied.status !== 'interrupted')
      notify(
        'Sentinel scan ' + applied.status,
        applied.threats.length
          ? applied.threats.length + ' detection(s) need review.'
          : applied.files.toLocaleString() +
              ' files scanned. ' +
              (applied.status === 'completed' ? 'No threats detected.' : 'Review the scan report.')
      );
    identifyDetections();
  }

  // Records size and hash for new detections so quarantine can confirm it acts on the same file. A file
  // that has already disappeared is marked missing rather than treated as clean.
  async function identifyDetections() {
    const op = operations.tryBegin('identify', 'Recording file identity');
    if (!op) {
      if (!operations.isClosed()) setTimeout(identifyDetections, 5000).unref();
      return;
    }
    try {
      for (const d of detections.filter(x => x.status === 'detected' && !x.sha256 && !x.identifyError)) {
        try {
          const found = await identify(d.path);
          if (!found)
            detectionStore.transition(d, 'missing', new Date().toISOString(), 'missing', 'The file was not found.');
          else detectionStore.recordIdentity(d, found, new Date().toISOString());
        } catch (err) {
          d.identifyError = err.code || err.message;
        }
      }
      persistQuietly('detections');
      publish(true);
    } finally {
      op.end();
    }
  }

  function cancelScan(reason) {
    if (!activeScan) return;
    activeScan.control.cancelReason = reason;
    if (active) active.status = 'cancelling';
    if (activeScan.handle) activeScan.handle.cancel(reason);
    else activeScan.control.abort.abort();
    publish(true);
  }

  // ---- Scheduler ----
  async function tick() {
    if (ticking || shuttingDown || smoke || safeMode) return;
    ticking = true;
    try {
      const now = new Date();
      if (scheduler.advance(settings.schedules, scheduleRuntime, now)) persistQuietly('schedule');
      if (!engine.runnable) return;
      const job = scheduler.nextJob(settings.schedules, scheduleRuntime, now);
      if (job && ready() && !operations.conflictsWith('scan')) {
        job.started = now.toISOString();
        scheduler.recordStart(scheduleRuntime, job, now);
        try {
          await scan(job.scheduleId, null, job);
          clearNotified('schedule');
        } catch (err) {
          // Failures after the scan was journaled are recorded by finishScan; this handles refusals.
          if (!err.recorded) scheduler.recordOutcome(scheduleRuntime, job, 'failed-to-start', now, err.message);
          persistQuietly('schedule');
          notify('Scheduled scan could not start', err.message, 'schedule');
          publish(true);
        }
      } else if (updateDue(now) && !operations.conflictsWith('update')) {
        try {
          await updateSignatures();
        } catch (err) {
          if (!(err instanceof OperationConflict)) notify('Signature update needs attention', err.message, 'update');
        }
      }
    } finally {
      ticking = false;
    }
  }

  // ---- Quarantine ----
  // Created after loading, because it operates on the loaded records array.
  let quarantine;
  const createQuarantineManager = () =>
    createQuarantine({
      vault,
      records: quarantineRecords,
      persist: () => persist('quarantine'),
      onDetection: (detectionId, status, record) => {
        const d = detections.find(x => x.id === detectionId);
        if (!d || d.status === status) return;
        const at = new Date().toISOString();
        if (status === 'quarantined') d.quarantineId = record.id;
        detectionStore.transition(
          d,
          status,
          at,
          status === 'detected' ? 'quarantine-not-completed' : status,
          record.id
        );
        persistQuietly('detections');
      }
    });

  async function confirm(options) {
    const answer = await dialog.showMessageBox(dialogParent(), {
      type: 'warning',
      defaultId: 0,
      cancelId: 0,
      ...options
    });
    return answer.response;
  }

  // Explains up front why a file operation cannot start (R16), before a dialog is shown.
  function assertFileOperationAllowed() {
    const blocker = operations.conflictsWith('file');
    if (blocker) throw Error(`Wait for “${blocker.label}” to finish.`);
  }

  async function quarantineDetection(id) {
    assertFileOperationAllowed();
    const d = detections.find(x => x.id === id);
    if (!d || d.status !== 'detected') throw Error('This detection is no longer awaiting review.');
    const response = await confirm({
      buttons: ['Cancel', 'Quarantine file'],
      title: 'Quarantine detected file?',
      message: d.signature,
      detail: d.path + '\n\nThis moves the file to Sentinel’s quarantine. Programs using it may stop working.'
    });
    if (response !== 1) return;
    // Permission is acquired after the dialog and the detection re-checked, since a scan may have started
    // or the detection changed while the dialog was open (R08.3).
    const op = operations.begin('file', 'Quarantining a file');
    try {
      if (d.status !== 'detected') throw Error('This detection is no longer awaiting review.');
      const record = await quarantine.quarantine(d);
      if (record.saveError) notify('Quarantine completed, but was not saved', record.saveError);
      if (record.status === 'recovery-needed')
        notify('Quarantine needs your review', record.issue || 'Open Quarantine in Sentinel to decide what to keep.');
    } catch (err) {
      if (err.reason === 'missing') {
        detectionStore.transition(d, 'missing', new Date().toISOString(), 'missing', 'Not found when quarantining.');
        persistQuietly('detections');
      }
      throw err;
    } finally {
      op.end();
      publish(true);
    }
  }

  async function restoreRecord(id) {
    assertFileOperationAllowed();
    const r = quarantineRecords.find(q => q.id === id && q.status === 'quarantined');
    if (!r) throw Error('This file is no longer in quarantine.');
    const occupied = fs.existsSync(r.original);
    const response = await confirm({
      buttons: ['Cancel', occupied ? 'Restore to another location…' : 'Restore file'],
      message: 'Restore a detected file?',
      detail:
        r.original +
        (occupied ? '\n\nA file already exists at the original location and will not be replaced.' : '') +
        '\n\nRestore only if you trust this file. The detection was: ' +
        r.signature
    });
    if (response !== 1) return;
    let target = null;
    if (occupied) {
      const chosen = await dialog.showSaveDialog(dialogParent(), {
        title: 'Restore to another location',
        defaultPath: path.join(path.dirname(r.original), 'Restored ' + path.basename(r.original))
      });
      if (chosen.canceled) return;
      target = chosen.filePath;
    }
    try {
      await operations.run('file', 'Restoring a file', () => quarantine.restore(id, target));
    } finally {
      publish(true);
    }
  }

  async function resolveQuarantine({ id, action }) {
    assertFileOperationAllowed();
    const r = quarantineRecords.find(q => q.id === id && q.status === 'recovery-needed');
    if (!r) throw Error('This item no longer needs review.');
    if (action !== 'dismiss') {
      const response = await confirm({
        buttons: ['Cancel', action === 'finish' ? 'Finish quarantine' : 'Undo quarantine'],
        message: action === 'finish' ? 'Finish quarantining this file?' : 'Undo this quarantine?',
        detail:
          action === 'finish'
            ? r.original + '\n\nThe original will be removed. An identical, verified copy stays in quarantine.'
            : r.original + '\n\nThe duplicate in quarantine will be removed. The original file stays where it is.'
      });
      if (response !== 1) return;
    }
    try {
      await operations.run('file', 'Resolving a quarantine review', () => quarantine.resolve(id, action));
    } finally {
      publish(true);
    }
  }

  // ---- Installation ----
  async function installEngine() {
    if (engine.runnable) throw Error('ClamAV is already installed.');
    const op = operations.begin('install', 'Installing ClamAV');
    const abort = new AbortController();
    let finished;
    installation = { abort, done: new Promise(resolve => (finished = resolve)) };
    installOutput = 'Finding the latest official Windows release…';
    publish(true);
    try {
      const engineDir = await install(
        root,
        message => {
          installOutput = message;
          publish();
        },
        abort.signal
      );
      settings.engineDir = engineDir;
      persist('settings');
      await detectEngine();
      if (!engine.runnable)
        throw Error(
          'ClamAV was downloaded but could not start. Check the installation or Windows runtime requirements.'
        );
      installOutput = 'Engine installed. Downloading the signature database…';
      publish(true);
      await updateSignatures({ owned: true });
      installOutput = 'Setup complete. ClamAV and its signature database are ready.';
    } catch (err) {
      installOutput = abort.signal.aborted
        ? 'Setup was cancelled. You can start it again at any time.'
        : 'Setup needs attention: ' + err.message;
      throw abort.signal.aborted ? Error('Setup was cancelled.') : err;
    } finally {
      installation = null;
      op.end();
      finished();
      publish(true);
    }
  }

  // ---- Lifecycle ----
  function show() {
    withWindow(w => {
      w.show();
      if (w.isMinimized()) w.restore();
      w.focus();
    });
  }

  // The single, idempotent shutdown path: stop scheduling, stop owned processes, wait (bounded) for
  // reports to be written, then allow the app to exit. Anything unfinished stays journaled for recovery.
  function shutdown() {
    if (shutdownPromise) return shutdownPromise;
    shuttingDown = true;
    operations.close(); // no new operation is accepted from here on
    clearInterval(tickTimer);
    const waits = [];
    if (activeScan) {
      cancelScan('shutdown');
      waits.push(activeScan.done);
    }
    if (update) {
      if (update.proc && !update.proc.kill()) forceKill(update.proc.pid);
      waits.push(update.done);
    }
    if (installation) {
      installation.abort.abort();
      waits.push(installation.done);
    }
    // File operations and hashing are awaited too; anything still running at the limit is journaled.
    waits.push(operations.drain(SHUTDOWN_TIMEOUT));
    shutdownPromise = Promise.race([
      Promise.allSettled(waits),
      new Promise(resolve => setTimeout(resolve, SHUTDOWN_TIMEOUT))
    ]).then(() => {
      // Anything still running is killed outright; its journal entry is recovered at the next start.
      if (activeScan?.handle) forceKill(activeScan.handle.pid);
      if (update?.proc) forceKill(update.proc.pid);
    });
    return shutdownPromise;
  }

  // ---- Fatal faults (R12) ----
  // After an uncaught fault the process may hold broken invariants, so it stops mutating, kills its own
  // child processes, keeps diagnostics, records the crash, and exits nonzero. The next start recovers
  // from the journals. Crash state is written with plain synchronous writes, independent of the store.
  const startedAt = new Date().toISOString();
  const crashFile = path.join(root, 'crash-state.json');
  const readCrashState = () => {
    try {
      return JSON.parse(fs.readFileSync(crashFile, 'utf8'));
    } catch {
      return null;
    }
  };
  const writeCrashState = value => {
    try {
      fs.writeFileSync(crashFile, JSON.stringify(value, null, 2));
    } catch {}
  };
  const fatal = createFatalHandler({
    stopMutations: () => {
      shuttingDown = true;
      operations.close();
      clearInterval(tickTimer);
    },
    killChildren: () => {
      if (activeScan?.handle) forceKill(activeScan.handle.pid);
      if (update?.proc) forceKill(update.proc.pid);
    },
    writeDiagnostics: text => logFiles.appendAppError(appLogs, text),
    markCrash: () =>
      writeCrashState({
        ...nextCrashState(readCrashState(), { startedAt, crashedAt: new Date().toISOString() }),
        acknowledged: false
      }),
    exit: code => app.exit(code)
  });
  process.on('uncaughtException', err => fatal.handle(err, 'uncaughtException'));
  process.on('unhandledRejection', reason => fatal.handle(reason, 'unhandledRejection'));

  // Reports the previous crash once, and decides whether this launch starts in safe mode.
  let safeMode = false;
  function reviewPreviousCrash() {
    const crash = readCrashState();
    if (!crash) return;
    safeMode = !!crash.safeMode;
    if (!crash.acknowledged)
      addStorageIssue({
        file: 'app',
        message:
          `Sentinel closed unexpectedly at ${crash.lastCrash}. Details are in logs\\app\\errors.log. ` +
          'Any scan that was running has been recovered from its journal.' +
          (safeMode
            ? ' Automatic scans and updates are paused for this session because Sentinel crashed repeatedly at startup.'
            : '')
      });
    writeCrashState({ ...crash, acknowledged: true });
    // Staying up past the startup window ends a crash loop.
    setTimeout(() => {
      const current = readCrashState();
      if (current) writeCrashState({ ...current, consecutiveStartupCrashes: 0, safeMode: false });
    }, 60000).unref();
  }

  app.on('second-instance', show);
  app.whenReady().then(async () => {
    [root, db, logs, vault].forEach(p => fs.mkdirSync(p, { recursive: true }));
    logFiles.migrateLayout(logs);
    const firstRun = !fs.existsSync(store.file('settings'));
    loadAll();
    reviewPreviousCrash();
    quarantine = createQuarantineManager();
    recoverJournals();
    pruneLogs();
    if (firstRun && app.isPackaged && !smoke) {
      settings.launchAtLogin = true;
      app.setLoginItemSettings({ openAtLogin: true, args: ['--hidden'] });
      persistQuietly('settings');
    }
    win = new BrowserWindow({
      width: 1320,
      height: 880,
      minWidth: 1040,
      minHeight: 720,
      backgroundColor: '#f5f7fb',
      title: 'Sentinel AV',
      icon,
      autoHideMenuBar: true,
      show: false,
      webPreferences: {
        preload: path.join(__dirname, 'preload.cjs'),
        nodeIntegration: false,
        contextIsolation: true,
        sandbox: true
      }
    });
    win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    // A renderer crash does not affect scans or file operations in this process: log it and reload the
    // window a bounded number of times.
    let rendererReloads = 0;
    win.webContents.on('render-process-gone', (_, details) => {
      logFiles.appendAppError(appLogs, `renderer gone: ${details.reason} (exit ${details.exitCode})`);
      if (rendererReloads++ < 3 && !shuttingDown) setTimeout(() => withWindow(w => w.reload()), 1000);
    });
    win.webContents.on('will-navigate', (event, url) => {
      if (url !== page) event.preventDefault();
    });
    win.webContents.session.setPermissionRequestHandler((_, __, callback) => callback(false));
    win.on('close', event => {
      if (!shuttingDown && settings.closeToTray) {
        event.preventDefault();
        win.hide();
      }
    });
    // Windows sign-out or shutdown: stop owned processes now; journals make the rest recoverable.
    win.on('session-end', () => {
      if (activeScan?.handle) forceKill(activeScan.handle.pid);
      if (update?.proc) forceKill(update.proc.pid);
      persistQuietly('schedule', 'jobs', 'updates');
    });
    win.once('ready-to-show', () => {
      if (!process.argv.includes('--hidden')) win.show();
    });
    tray = new Tray(icon);
    const trayScan = kind => () => scan(kind).catch(e => notify('Unable to scan', e.message));
    tray.setContextMenu(
      Menu.buildFromTemplate([
        { label: 'Open Sentinel AV', click: show },
        { type: 'separator' },
        { label: 'Run quick scan', click: trayScan('quick') },
        { label: 'Run full scan', click: trayScan('full') },
        { type: 'separator' },
        { label: 'Quit Sentinel AV', click: () => app.quit() }
      ])
    );
    tray.on('double-click', show);

    const actions = {
      state: () => state(),
      install: () => installEngine(),
      'cancel-install': () => {
        if (!installation) return;
        installation.abort.abort();
        if (update?.proc) update.proc.kill();
      },
      scan: kind => scan(kind),
      custom: async () => {
        const selected = await dialog.showOpenDialog(dialogParent(), {
          title: 'Choose a folder to scan',
          properties: ['openDirectory']
        });
        if (!selected.canceled) return scan('custom', selected.filePaths);
      },
      cancel: () => cancelScan('user'),
      settings: payload => {
        const next = validateSettings(payload, settings);
        if (next.launchAtLogin !== settings.launchAtLogin) {
          if (!app.isPackaged) throw Error('Install the packaged app to enable launch at sign-in.');
          app.setLoginItemSettings({ openAtLogin: next.launchAtLogin, args: ['--hidden'] });
        }
        const runtime = scheduler.reconcile(next.schedules, scheduleRuntime, new Date());
        store.save('settings', next, SPECS.settings.version);
        settings = next;
        scheduleRuntime = runtime;
        persistQuietly('schedule');
        publish(true);
      },
      engine: async () => {
        if (operations.conflictsWith('install')) throw Error('Wait for the current operation to finish.');
        const selected = await dialog.showOpenDialog(dialogParent(), {
          title: 'Select clamscan.exe in your ClamAV installation',
          properties: ['openFile'],
          filters: [{ name: 'ClamAV scanner', extensions: ['exe'] }]
        });
        if (selected.canceled) return;
        if (path.basename(selected.filePaths[0]).toLowerCase() !== 'clamscan.exe') throw Error('Select clamscan.exe.');
        await operations.run('install', 'Changing the ClamAV installation', async () => {
          settings.engineDir = path.dirname(selected.filePaths[0]);
          persist('settings');
          await detectEngine();
        });
      },
      exclude: async () => {
        const selected = await dialog.showOpenDialog(dialogParent(), {
          title: 'Exclude a folder from future scans',
          properties: ['openDirectory']
        });
        if (selected.canceled) return;
        settings.exclusions = [...new Set([...settings.exclusions, ...selected.filePaths])];
        persist('settings');
        publish(true);
      },
      'remove-exclusion': payload => {
        if (payload === root) return;
        settings.exclusions = settings.exclusions.filter(p => p !== payload);
        persist('settings');
        publish(true);
      },
      update: () => updateSignatures(),
      download: () => shell.openExternal('https://www.clamav.net/downloads'),
      quarantine: id => quarantineDetection(id),
      restore: id => restoreRecord(id),
      'quarantine-resolve': payload => resolveQuarantine(payload),
      'quarantine-recheck': async id => {
        try {
          await operations.run('file', 'Rechecking a quarantine item', () => quarantine.recheck(id));
        } finally {
          publish(true);
        }
      },
      'recheck-database': () => recheckDatabase(),
      'resolve-detection': id => {
        const d = detections.find(x => x.id === id && x.status === 'missing');
        if (!d) throw Error('Only detections whose file is missing can be marked resolved.');
        detectionStore.transition(
          d,
          'resolved',
          new Date().toISOString(),
          'marked-resolved',
          'The file was no longer present.'
        );
        persist('detections');
        publish(true);
      },
      'dismiss-storage-issues': () => {
        storageIssues = [];
        publish(true);
      },
      logs: () => shell.openPath(logs),
      'data-folder': () => shell.openPath(root),
      export: async id => {
        const item = reports.find(s => s.id === id);
        if (!item) throw Error('Report not found.');
        const selected = await dialog.showSaveDialog(dialogParent(), {
          defaultPath: 'Sentinel-' + item.id + '.json',
          filters: [{ name: 'JSON report', extensions: ['json'] }]
        });
        if (selected.canceled) return;
        const threats = item.threats.map(t => ({ ...t, status: detections.find(d => d.id === t.detectionId)?.status }));
        fs.writeFileSync(selected.filePath, JSON.stringify({ ...item, threats }, null, 2));
      }
    };
    ipcMain.handle('sentinel', async (event, action, payload) => {
      if (
        event.sender !== win?.webContents ||
        event.senderFrame !== win.webContents.mainFrame ||
        event.senderFrame.url !== page
      )
        throw Error('Untrusted request.');
      try {
        if (!Object.hasOwn(actions, action)) throw Error('Unknown action.');
        return { ok: true, data: await actions[action](payload) };
      } catch (err) {
        return { ok: false, error: err.message };
      }
    });

    await win.loadFile(path.join(__dirname, '../ui/index.html'));
    await detectEngine();
    quarantine
      .recover()
      .then(changed => {
        if (changed.some(r => r.status === 'recovery-needed'))
          notify('A quarantine operation needs review', 'Open Quarantine in Sentinel to decide what to keep.');
        publish(true);
      })
      .catch(err => storageIssues.push({ file: 'quarantine', message: 'Recovery could not finish: ' + err.message }));
    identifyDetections();
    tickTimer = setInterval(tick, 30000);
    powerMonitor.on('resume', tick);
    tick();
    if (smoke)
      require('./smoke.cjs')(win, {
        mode: smokeMode,
        win,
        db,
        detectEngine,
        scan,
        state,
        shutdown,
        setEngineDir: dir => {
          settings.engineDir = dir;
        },
        isScanning: () => !!active,
        latestReport: () => reports[0],
        // Electron's app.quit() ignores process.exitCode, so the result is passed to app.exit() explicitly
        // after the normal shutdown path has run.
        throwUncaught: message =>
          setTimeout(() => {
            throw Error(message);
          }),
        quit: code =>
          shutdown().finally(() => {
            shutdownComplete = true;
            app.exit(code);
          })
      });
  });

  app.on('before-quit', event => {
    if (shutdownComplete) return;
    event.preventDefault();
    shutdown().finally(() => {
      shutdownComplete = true;
      app.quit();
    });
  });
  app.on('window-all-closed', () => {
    if (!settings?.closeToTray || shuttingDown) app.quit();
  });
}
