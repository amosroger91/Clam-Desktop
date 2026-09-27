const { app, BrowserWindow, Tray, Menu, ipcMain, dialog, shell, Notification, powerMonitor } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { spawn, execFile } = require('node:child_process');
const { pathToFileURL } = require('node:url');
const { defaults, nextRun, validateSettings, scanArgs, parseLine, saveJson } = require('./core.cjs');
const { install } = require('./installer.cjs');

app.setAppUserModelId('com.wellspring.sentinel');
// The smoke test module is not packaged, so the flag only works from a source checkout.
const smoke = !app.isPackaged && process.argv.includes('--smoke-test');
if (smoke) app.disableHardwareAcceleration();
if (smoke) app.setPath('userData', path.join(os.tmpdir(), 'sentinel-smoke-' + process.pid));
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  let win,
    tray,
    settings,
    history,
    quarantine,
    active = null,
    child = null,
    quitting = false;
  let updating = false,
    updateOutput = '',
    engine = { available: false, ready: false },
    lastUpdate = null;
  let scanRetryAfter = 0,
    updateRetryAfter = 0,
    updateFailures = 0,
    lastEmit = 0,
    progressTimer = null;
  let installing = false,
    installOutput = '';
  const root = app.getPath('userData');
  const db = path.join(root, 'database');
  const logs = path.join(root, 'logs');
  const vault = path.join(root, 'quarantine');
  const page = pathToFileURL(path.join(__dirname, '../ui/index.html')).href;
  const icon = path.join(__dirname, '../assets/icon.png');
  const file = name => path.join(root, name + '.json');
  function read(name, fallback) {
    try {
      return JSON.parse(fs.readFileSync(file(name), 'utf8'));
    } catch (err) {
      if (err.code !== 'ENOENT') {
        try {
          fs.copyFileSync(file(name), file(name) + '.corrupt-' + Date.now());
        } catch {}
      }
      return fallback;
    }
  }
  function state() {
    return {
      settings,
      history,
      quarantine,
      active,
      engine,
      updating,
      updateOutput,
      lastUpdate,
      installing,
      installOutput,
      dataRoot: root,
      packaged: app.isPackaged,
      version: app.getVersion(),
      platform: process.platform
    };
  }
  // Forced publishes send the full state after a state change. Frequent progress output is
  // throttled and sends only the fields that change during a scan, update, or install.
  function publish(force = false) {
    if (tray)
      tray.setToolTip(
        'Sentinel AV • ' +
          (active
            ? 'Scanning'
            : installing
              ? 'Installing ClamAV'
              : updating
                ? 'Updating signatures'
                : engine.ready
                  ? 'Ready to scan'
                  : 'Setup required')
      );
    if (force) {
      clearTimeout(progressTimer);
      progressTimer = null;
      lastEmit = Date.now();
      if (win && !win.isDestroyed()) win.webContents.send('state', state());
    } else if (!progressTimer) {
      progressTimer = setTimeout(
        () => {
          progressTimer = null;
          lastEmit = Date.now();
          if (win && !win.isDestroyed()) win.webContents.send('progress', { active, updateOutput, installOutput });
        },
        Math.max(0, 300 - (Date.now() - lastEmit))
      );
    }
  }
  function notify(title, body) {
    if (settings.notifications && Notification.isSupported()) new Notification({ title, body, icon }).show();
  }
  function run(exe, args) {
    return new Promise((resolve, reject) =>
      execFile(exe, args, { windowsHide: true, timeout: 15000, maxBuffer: 1024 * 1024 }, (err, stdout) =>
        err ? reject(err) : resolve(stdout.trim())
      )
    );
  }
  async function detectEngine() {
    const candidates = [
      settings.engineDir,
      path.join(process.env.ProgramFiles || 'C:\\Program Files', 'ClamAV'),
      'C:\\ClamAV',
      ...(process.env.PATH || '').split(path.delimiter)
    ].filter(Boolean);
    engine = { available: false, ready: false };
    for (const dir of candidates) {
      const exe = path.join(dir, 'clamscan.exe');
      if (!fs.existsSync(exe)) continue;
      try {
        const version = await run(exe, ['--version']);
        const hasDatabase = fs.readdirSync(db).some(n => /\.(cvd|cld)$/.test(n));
        engine = { available: true, ready: hasDatabase, dir, version, database: db };
        break;
      } catch {}
    }
    publish(true);
    return engine;
  }
  async function updateSignatures() {
    if (updating || active) throw Error('Wait for the current operation to finish.');
    if (!engine.available) throw Error('Choose your ClamAV installation in Settings first.');
    const exe = path.join(engine.dir, 'freshclam.exe');
    if (!fs.existsSync(exe)) throw Error('freshclam.exe is missing from this ClamAV installation.');
    const config = path.join(root, 'freshclam.conf');
    fs.writeFileSync(config, 'DatabaseMirror database.clamav.net\nDatabaseDirectory "' + db + '"\n');
    updating = true;
    updateOutput = 'Connecting to the ClamAV signature service…';
    publish(true);
    await new Promise((resolve, reject) => {
      const proc = spawn(exe, ['--config-file=' + config, '--stdout'], { windowsHide: true });
      child = proc;
      const append = data => {
        updateOutput = (updateOutput + '\n' + data.toString()).slice(-12000);
        publish();
      };
      proc.stdout.on('data', append);
      proc.stderr.on('data', append);
      let settled = false;
      const finish = async error => {
        if (settled) return;
        settled = true;
        updating = false;
        child = null;
        if (!error) {
          lastUpdate = new Date().toISOString();
          saveJson(file('updates'), { lastUpdate });
        } else updateOutput += '\n' + error.message;
        await detectEngine();
        publish(true);
        error ? reject(error) : resolve();
      };
      proc.on('error', finish);
      proc.on('close', code =>
        finish(code === 0 ? null : Error('Signature update failed (exit ' + code + '). See the update log.'))
      );
    });
  }
  async function targetsFor(kind, custom) {
    if (kind === 'custom') return custom;
    if (kind === 'quick')
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
    const output = await run('powershell.exe', [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { $_.DeviceID + '\\' }"
    ]);
    const drives = output.split(/\r?\n/).filter(p => /^[A-Z]:\\$/i.test(p));
    if (!drives.length) throw Error('No local fixed drives could be found.');
    return drives;
  }
  function pruneLogs() {
    const keep = new Set(history.map(h => h.id + '.log'));
    if (active) keep.add(active.id + '.log');
    try {
      for (const name of fs.readdirSync(logs))
        if (name.endsWith('.log') && !keep.has(name)) fs.rmSync(path.join(logs, name), { force: true });
    } catch {}
  }
  async function scan(kind, custom, scheduled = false) {
    if (!['quick', 'full', 'custom'].includes(kind)) throw Error('Unknown scan type.');
    if (active || updating || installing) throw Error('Another operation is already running.');
    if (!engine.ready) throw Error('Set up ClamAV and download signatures before scanning.');
    // Reserve the operation before asynchronous drive discovery.
    active = {
      id: crypto.randomUUID(),
      kind,
      scheduled,
      started: new Date().toISOString(),
      status: 'preparing',
      files: 0,
      threats: [],
      warnings: [],
      current: 'Preparing scan…',
      targets: []
    };
    publish(true);
    let targets;
    try {
      targets = await targetsFor(kind, custom);
      if (!targets?.length) throw Error('No scan locations are available.');
    } catch (err) {
      active = null;
      publish(true);
      throw err;
    }
    const item = active;
    item.targets = targets;
    item.status = 'running';
    const logPath = path.join(logs, item.id + '.log');
    const log = fs.createWriteStream(logPath);
    log.on('error', err => {
      item.warnings.push('Could not write scan log: ' + err.message);
    });
    const proc = spawn(path.join(engine.dir, 'clamscan.exe'), scanArgs(settings, db, targets), { windowsHide: true });
    child = proc;
    let buffer = '',
      finished = false;
    function line(text) {
      const parsed = parseLine(text.trim());
      if (parsed.type === 'scanning') item.current = parsed.path;
      if (parsed.type === 'file') {
        item.files++;
        item.current = parsed.path;
      }
      if (parsed.type === 'count') item.files = parsed.count;
      if (parsed.type === 'threat') {
        item.files++;
        item.threats.push({ ...parsed, id: crypto.randomUUID(), status: 'detected' });
      }
      if (parsed.type === 'warning' && item.warnings.length < 200) item.warnings.push(parsed.message);
    }
    proc.stdout.on('data', data => {
      log.write(data);
      buffer += data.toString();
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop();
      lines.forEach(line);
      publish();
    });
    proc.stderr.on('data', data => {
      log.write(data);
      data
        .toString()
        .split(/\r?\n/)
        .filter(Boolean)
        .forEach(t => {
          if (item.warnings.length < 200) item.warnings.push(t);
        });
      publish();
    });
    function finish(code, error) {
      if (finished) return;
      finished = true;
      if (buffer) line(buffer);
      log.end();
      item.finished = new Date().toISOString();
      item.exitCode = code;
      item.status =
        item.status === 'cancelling'
          ? 'cancelled'
          : error || ![0, 1].includes(code)
            ? 'error'
            : item.warnings.length
              ? 'partial'
              : 'completed';
      if (error) item.warnings.push(error.message);
      history.unshift(item);
      history = history.slice(0, 200);
      saveJson(file('history'), history);
      active = null;
      child = null;
      log.once('close', pruneLogs);
      if (win) win.setProgressBar(-1);
      publish(true);
      notify(
        'Sentinel scan ' + item.status,
        item.threats.length
          ? item.threats.length + ' detection(s) need review.'
          : item.files.toLocaleString() +
              ' files scanned. ' +
              (item.status === 'completed' ? 'No threats detected.' : 'Review the scan report.')
      );
    }
    proc.on('error', err => finish(null, err));
    proc.on('close', code => finish(code));
    if (win) win.setProgressBar(2);
    publish(true);
    return item.id;
  }
  async function tick() {
    if (smoke || active || updating || installing || !engine.available) return;
    const now = Date.now();
    const due = settings.schedules
      .filter(s => s.enabled && new Date(s.next) <= now)
      .sort((a, b) => new Date(a.next) - new Date(b.next))[0];
    if (due && engine.ready && now >= scanRetryAfter) {
      try {
        await scan(due.id, null, true);
        // Settings may have been replaced while drives were being discovered.
        const schedule = settings.schedules.find(s => s.id === due.id);
        schedule.next = nextRun(schedule);
        saveJson(file('settings'), settings);
        publish(true);
      } catch (err) {
        scanRetryAfter = Date.now() + 3600000;
        notify('Scheduled scan could not start', err.message);
      }
    } else if (
      settings.autoUpdate &&
      now >= updateRetryAfter &&
      (!lastUpdate || now - new Date(lastUpdate).getTime() > 3600000)
    ) {
      try {
        await updateSignatures();
        updateFailures = 0;
      } catch (err) {
        // Back off 15 min, 30 min, 1 h … up to 6 h between failed attempts.
        updateRetryAfter = Date.now() + Math.min(900000 * 2 ** updateFailures++, 21600000);
        notify('Signature update needs attention', err.message);
      }
    }
  }
  function show() {
    if (win) {
      win.show();
      if (win.isMinimized()) win.restore();
      win.focus();
    }
  }
  async function quarantineThreat(id) {
    if (active) throw Error('Wait for the scan to finish before quarantining files.');
    const threat = history.flatMap(s => s.threats).find(t => t.id === id);
    if (!threat || threat.status !== 'detected') throw Error('Detection is no longer available.');
    const answer = await dialog.showMessageBox(win, {
      type: 'warning',
      buttons: ['Cancel', 'Quarantine file'],
      defaultId: 0,
      cancelId: 0,
      title: 'Quarantine detected file?',
      message: threat.signature,
      detail: threat.path + '\n\nThis moves the file to Sentinel’s quarantine. Programs using it may stop working.'
    });
    if (answer.response !== 1) return;
    const stat = fs.lstatSync(threat.path);
    if (!stat.isFile() || stat.isSymbolicLink()) throw Error('Only regular files can be quarantined.');
    const destination = path.join(vault, threat.id + '.quarantine');
    // Persist recovery metadata before moving the file.
    const record = {
      id: threat.id,
      original: threat.path,
      stored: destination,
      signature: threat.signature,
      date: new Date().toISOString(),
      status: 'pending'
    };
    quarantine.unshift(record);
    saveJson(file('quarantine'), quarantine);
    try {
      try {
        fs.renameSync(threat.path, destination);
      } catch (err) {
        if (err.code !== 'EXDEV') throw err;
        fs.copyFileSync(threat.path, destination, fs.constants.COPYFILE_EXCL);
        fs.unlinkSync(threat.path);
      }
      record.status = 'quarantined';
      threat.status = 'quarantined';
    } catch (err) {
      record.status = 'error';
      record.error = err.message;
      throw err;
    } finally {
      saveJson(file('quarantine'), quarantine);
      saveJson(file('history'), history);
      publish(true);
    }
  }
  // Resolve records left 'pending' by a crash between saving metadata and moving the file.
  function reconcileQuarantine() {
    const pending = quarantine.filter(q => q.status === 'pending');
    for (const record of pending) {
      const stored = fs.existsSync(record.stored),
        original = fs.existsSync(record.original);
      if (stored && !original) {
        record.status = 'quarantined';
        history
          .flatMap(s => s.threats)
          .filter(t => t.id === record.id)
          .forEach(t => {
            t.status = 'quarantined';
          });
      } else {
        // A copy may be incomplete; the original is still in place, so discard it and allow a retry.
        if (stored)
          try {
            fs.unlinkSync(record.stored);
          } catch {}
        record.status = 'error';
        record.error = 'Quarantine was interrupted. The file was left in its original location.';
      }
    }
    if (pending.length) {
      saveJson(file('quarantine'), quarantine);
      saveJson(file('history'), history);
    }
  }
  async function restore(id) {
    const record = quarantine.find(q => q.id === id && q.status === 'quarantined');
    if (!record) throw Error('Quarantined file not found.');
    const answer = await dialog.showMessageBox(win, {
      type: 'warning',
      buttons: ['Cancel', 'Restore file'],
      defaultId: 0,
      cancelId: 0,
      message: 'Restore a detected file?',
      detail: record.original + '\n\nRestore only if you trust this file. The detection was: ' + record.signature
    });
    if (answer.response !== 1) return;
    fs.copyFileSync(record.stored, record.original, fs.constants.COPYFILE_EXCL);
    fs.unlinkSync(record.stored);
    record.status = 'restored';
    history
      .flatMap(s => s.threats)
      .filter(t => t.id === id)
      .forEach(t => {
        t.status = 'restored';
      });
    saveJson(file('quarantine'), quarantine);
    saveJson(file('history'), history);
    publish(true);
  }
  app.on('second-instance', show);
  app.whenReady().then(async () => {
    [root, db, logs, vault].forEach(p => fs.mkdirSync(p, { recursive: true }));
    // Merge over defaults so preferences added in later versions are always present.
    settings = { ...defaults(), ...read('settings', {}) };
    history = read('history', []);
    quarantine = read('quarantine', []);
    reconcileQuarantine();
    pruneLogs();
    if (!fs.existsSync(file('settings')) && app.isPackaged && !smoke) {
      settings.launchAtLogin = true;
      app.setLoginItemSettings({ openAtLogin: true, args: ['--hidden'] });
    }
    lastUpdate = read('updates', {}).lastUpdate || null;
    // Never scan the signature store or the quarantine itself.
    settings.exclusions = [...new Set([...settings.exclusions, root])];
    saveJson(file('settings'), settings);
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
    win.webContents.on('will-navigate', (event, url) => {
      if (url !== page) event.preventDefault();
    });
    win.webContents.session.setPermissionRequestHandler((_, __, callback) => callback(false));
    win.on('close', event => {
      if (!quitting && settings.closeToTray) {
        event.preventDefault();
        win.hide();
      }
    });
    win.once('ready-to-show', () => {
      if (!process.argv.includes('--hidden')) win.show();
    });
    tray = new Tray(icon);
    tray.setContextMenu(
      Menu.buildFromTemplate([
        { label: 'Open Sentinel AV', click: show },
        { type: 'separator' },
        { label: 'Run quick scan', click: () => scan('quick').catch(e => notify('Unable to scan', e.message)) },
        { label: 'Run full scan', click: () => scan('full').catch(e => notify('Unable to scan', e.message)) },
        { type: 'separator' },
        { label: 'Quit Sentinel AV', click: () => app.quit() }
      ])
    );
    tray.on('double-click', show);
    ipcMain.handle('sentinel', async (event, action, payload) => {
      if (
        event.sender !== win.webContents ||
        event.senderFrame !== win.webContents.mainFrame ||
        event.senderFrame.url !== page
      )
        throw Error('Untrusted request.');
      try {
        let result;
        switch (action) {
          case 'state':
            result = state();
            break;
          case 'install': {
            if (installing || active || updating) throw Error('Another operation is already running.');
            if (engine.available) throw Error('ClamAV is already installed.');
            installing = true;
            installOutput = 'Finding the latest official Windows release…';
            publish(true);
            try {
              settings.engineDir = await install(root, message => {
                installOutput = message;
                publish();
              });
              saveJson(file('settings'), settings);
              await detectEngine();
              if (!engine.available)
                throw Error(
                  'ClamAV was downloaded but could not start. Check the installation or Windows runtime requirements.'
                );
              installOutput = 'Engine installed. Downloading the signature database…';
              publish(true);
              await updateSignatures();
              installOutput = 'Setup complete. ClamAV and its signature database are ready.';
            } catch (err) {
              installOutput = 'Setup needs attention: ' + err.message;
              throw err;
            } finally {
              installing = false;
              publish(true);
            }
            break;
          }
          case 'scan':
            result = await scan(payload);
            break;
          case 'custom': {
            const selected = await dialog.showOpenDialog(win, {
              title: 'Choose a folder to scan',
              properties: ['openDirectory']
            });
            if (!selected.canceled) result = await scan('custom', selected.filePaths);
            break;
          }
          case 'cancel':
            if (active && child) {
              active.status = 'cancelling';
              child.kill();
              publish(true);
            }
            break;
          case 'settings': {
            const next = validateSettings(payload, settings);
            if (next.launchAtLogin !== settings.launchAtLogin) {
              if (!app.isPackaged) throw Error('Install the packaged app to enable launch at sign-in.');
              app.setLoginItemSettings({ openAtLogin: next.launchAtLogin, args: ['--hidden'] });
            }
            settings = next;
            saveJson(file('settings'), settings);
            publish(true);
            break;
          }
          case 'engine': {
            if (active || updating || installing) throw Error('Wait for the current operation to finish.');
            const selected = await dialog.showOpenDialog(win, {
              title: 'Select clamscan.exe in your ClamAV installation',
              properties: ['openFile'],
              filters: [{ name: 'ClamAV scanner', extensions: ['exe'] }]
            });
            if (!selected.canceled) {
              if (path.basename(selected.filePaths[0]).toLowerCase() !== 'clamscan.exe')
                throw Error('Select clamscan.exe.');
              settings.engineDir = path.dirname(selected.filePaths[0]);
              saveJson(file('settings'), settings);
              await detectEngine();
            }
            break;
          }
          case 'exclude': {
            const selected = await dialog.showOpenDialog(win, {
              title: 'Exclude a folder from future scans',
              properties: ['openDirectory']
            });
            if (!selected.canceled) {
              settings.exclusions = [...new Set([...settings.exclusions, ...selected.filePaths])];
              saveJson(file('settings'), settings);
              publish(true);
            }
            break;
          }
          case 'remove-exclusion':
            if (payload !== root) {
              settings.exclusions = settings.exclusions.filter(p => p !== payload);
              saveJson(file('settings'), settings);
              publish(true);
            }
            break;
          case 'update':
            await updateSignatures();
            break;
          case 'download':
            await shell.openExternal('https://www.clamav.net/downloads');
            break;
          case 'quarantine':
            await quarantineThreat(payload);
            break;
          case 'restore':
            await restore(payload);
            break;
          case 'logs':
            await shell.openPath(logs);
            break;
          case 'export': {
            const item = history.find(s => s.id === payload);
            if (!item) throw Error('Report not found.');
            const selected = await dialog.showSaveDialog(win, {
              defaultPath: 'Sentinel-' + item.id + '.json',
              filters: [{ name: 'JSON report', extensions: ['json'] }]
            });
            if (!selected.canceled) fs.writeFileSync(selected.filePath, JSON.stringify(item, null, 2));
            break;
          }
          default:
            throw Error('Unknown action.');
        }
        return { ok: true, data: result };
      } catch (err) {
        return { ok: false, error: err.message };
      }
    });
    await win.loadFile(path.join(__dirname, '../ui/index.html'));
    await detectEngine();
    setInterval(tick, 30000).unref();
    powerMonitor.on('resume', tick);
    tick();
    if (smoke)
      require('./smoke.cjs')(win, {
        db,
        detectEngine,
        scan,
        setEngineDir: dir => {
          settings.engineDir = dir;
        },
        isScanning: () => !!active,
        latestReport: () => history[0],
        quit: () => {
          quitting = true;
          app.quit();
        }
      });
  });
  app.on('before-quit', event => {
    quitting = true;
    if (child) {
      event.preventDefault();
      if (active) active.status = 'cancelling';
      const proc = child;
      proc.once('close', () => {
        child = null;
        app.quit();
      });
      proc.kill();
    }
  });
  app.on('window-all-closed', () => {
    if (!settings?.closeToTray || quitting) app.quit();
  });
}
