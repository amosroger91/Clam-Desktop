// Runs under Node (or Electron's RunAsNode), independently of any BrowserWindow.
const fs = require('node:fs');
const path = require('node:path');
const { once } = require('node:events');
const { createStore } = require('./store.cjs');
const { Clamd } = require('./clamd.cjs');
const { MonitorQueue } = require('./monitor-queue.cjs');
const { watchFolders } = require('./monitor-watch.cjs');
const prefsModule = require('./monitor-settings.cjs');
const resources = require('./monitor-resources.cjs');
const databaseInfo = require('./database.cjs');
const rpc = require('./monitor-rpc.cjs');
const { updateDefinitions } = require('./monitor-update.cjs');
const { queueSpec } = require('./monitor-state.cjs');
const { AnalysisPipeline, findTool } = require('./analysis-tools.cjs');
const { createRuleFeed } = require('./rule-feed.cjs');
const { createQuarantine } = require('./quarantine.cjs');
const { createBehavior } = require('./behavior.cjs');

const plainSpec = fallback => ({
  version: 1,
  fallback,
  migrations: {},
  validate: data => {
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw Error('Invalid monitor state');
    return { value: data, problems: [] };
  }
});

async function run(root, { inspectDatabase = databaseInfo.inspect, sampleResources = resources.sample } = {}) {
  if (!path.isAbsolute(root)) throw Error('An absolute profile directory is required');
  if (process.env.SENTINEL_HOST_GATE) {
    const gate = process.env.SENTINEL_HOST_GATE;
    if (path.dirname(gate) !== path.join(root, 'monitor')) throw Error('Invalid service host gate');
    for (let i = 0; !fs.existsSync(gate) && i < 100; i++) await new Promise(resolve => setTimeout(resolve, 100));
    if (!fs.existsSync(gate)) throw Error('Service host did not attach the process job');
    fs.unlinkSync(gate);
  }
  const dir = path.join(root, 'monitor'),
    store = createStore(dir),
    secret = rpc.token(root);
  let queue,
    watcher,
    engine,
    config,
    timer,
    busy = false,
    stopping = false,
    fault = null;
  let leaseUntil = 0,
    session = null,
    sampleAt = 0,
    sample = { freeMB: 0, battery: null };
  let lastWalk = 0,
    retryAt = 0,
    engineKey = '',
    leaseId = null;
  let epoch = 0;
  let updater = null,
    updateState = { nextAttempt: 0, failures: 0 },
    databaseFault = null;
  const manual = new Map();
  let pipeline,
    rules,
    behavior,
    rulesNext = 0,
    rulesUpdating = null;
  let autoRecords = [],
    autoVault;
  let saveTimer;
  let queueState = {},
    durableEvents = 0,
    dirty = false;
  const persist = state => {
    queueState = state;
    dirty = true;
    // Detections are flushed synchronously in this isolated process before they are returned over IPC.
    clearTimeout(saveTimer);
    if (state.outbox.length > durableEvents) {
      store.save('queue', queueState, 1);
      durableEvents = state.outbox.length;
      dirty = false;
      return;
    }
    saveTimer = setTimeout(() => {
      try {
        flush();
      } catch (err) {
        fault = err.message;
        if (queue) queue.paused = true;
      }
    }, 100);
  };
  const flush = () => {
    clearTimeout(saveTimer);
    if (dirty) {
      store.save('queue', queueState, 1);
      durableEvents = queueState.outbox?.length || 0;
      dirty = false;
    }
  };
  async function stopEngine(cancelWaiting = true) {
    for (const job of manual.values()) {
      if (!cancelWaiting && !job.running) continue;
      job.abort.abort();
      job.reject(Error('Scanner paused for maintenance'));
      clearTimeout(job.timer);
    }
    for (const [id, job] of manual) if (cancelWaiting || job.running) manual.delete(id);
    if (queue) await queue.pause();
    if (engine) await engine.stop();
    engine = null;
  }
  async function configure(next) {
    if (!next || typeof next !== 'object') throw Error('Invalid monitor configuration');
    const prefs = prefsModule.validate(next.prefs);
    prefs.pauseUntil = next.prefs.pauseUntil || null;
    if (prefs.pauseUntil && !Number.isFinite(Date.parse(prefs.pauseUntil))) throw Error('Invalid pause time');
    for (const p of [next.engineDir, next.database, ...(next.exclusions || [])])
      if (typeof p !== 'string' || !path.isAbsolute(p) || /[\r\n\0"]/.test(p)) throw Error('Invalid monitoring path');
    if (!Array.isArray(next.exclusions) || next.exclusions.length > 1000) throw Error('Invalid exclusions');
    if (typeof next.scanArchives !== 'boolean' || typeof next.detectPUA !== 'boolean')
      throw Error('Invalid scan options');
    const normalized = { ...next, prefs };
    if (JSON.stringify(normalized) === JSON.stringify(config)) return;
    epoch++;
    if (updater) {
      updater.cancel();
      await updater.done.catch(() => {});
    }
    await stopEngine();
    watcher?.close();
    if (queue) {
      queueState = queue.snapshot();
      flush();
    }
    const oldConfig = config;
    config = normalized;
    if (next.toolsRoot && (!path.isAbsolute(next.toolsRoot) || /[\r\n\0]/.test(next.toolsRoot)))
      throw Error('Invalid analysis tools path');
    rules = createRuleFeed(path.join(dir, 'rules'), findTool(next.toolsRoot, 'yr.exe'));
    behavior = createBehavior(next.toolsRoot);
    pipeline = new AnalysisPipeline({
      toolsRoot: next.toolsRoot,
      rules,
      prefs,
      clam: { scan: (file, options) => engine.scan(file, options) }
    });
    if (next.verifiedFingerprint && next.verifiedFingerprint === inspectDatabase(next.database).fingerprint)
      databaseFault = null;
    store.save('config', config, 1);
    queue = new MonitorQueue({
      prefs,
      folders: prefs.folders,
      exclusions: [...next.exclusions, root],
      state: queueState,
      scan: (file, options) => pipeline.scan(file, options),
      onThreat: async event => {
        if (prefs.autoQuarantine && event.action === 'quarantine' && event.sha256) {
          if (autoRecords.length >= 500)
            throw Error('Automatic quarantine record limit reached; review existing records');
          const record = await autoVault.quarantine(event);
          event.quarantineStatus = record.status;
        }
      },
      save: persist,
      emit: () => setImmediate(tick)
    });
    if (
      oldConfig &&
      (oldConfig.scanArchives !== config.scanArchives ||
        oldConfig.detectPUA !== config.detectPUA ||
        oldConfig.prefs.maxFileMB !== config.prefs.maxFileMB ||
        oldConfig.prefs.yaraEnabled !== prefs.yaraEnabled ||
        oldConfig.prefs.staticAnalysis !== prefs.staticAnalysis ||
        oldConfig.prefs.highRiskOnly !== prefs.highRiskOnly)
    )
      queue.cache.clear();
    watcher = prefs.enabled ? watchFolders(queue, { onError: (file, err) => queue.note(file, err.message) }) : null;
    engineKey = '';
    retryAt = 0;
  }
  function status() {
    flush();
    const sessionKnown = !!session && Date.now() - session.at < 30000;
    const policy = config
      ? prefsModule.resourceReason(config.prefs, {
          ...sample,
          sessionKnown,
          idleSeconds: sessionKnown ? session.idleSeconds : 0
        })
      : 'Not configured';
    const reason =
      fault ||
      databaseFault ||
      (queue?.outbox.length >= 1000 ? 'Detection inbox full; open Sentinel to review pending detections' : null) ||
      (updater
        ? 'Updating definitions in the background'
        : config?.blocked
          ? 'Engine or definitions need attention'
          : leaseUntil > Date.now()
            ? 'Paused for desktop file or database operation'
            : policy);
    return {
      connected: true,
      pid: process.pid,
      enginePid: engine?.proc?.pid,
      engineReady: !!engine?.ready,
      reason: reason || (engine?.ready ? null : 'Loading scan engine'),
      fault,
      resources: sample,
      reconciling: !!watcher?.walking,
      ...queue?.status(),
      events: queue?.outbox.slice(0, 100) || [],
      folders: config?.prefs.folders || [],
      definitionVersion: engineKey,
      service: process.env.SENTINEL_SERVICE === '1',
      quarantine: autoRecords.slice(0, 500),
      rules: rules?.status(),
      behavior: behavior?.status()
    };
  }
  // Mutating commands are serialized so pause/configure cannot race engine startup or each other.
  let commands = Promise.resolve();
  const server = rpc.server(root, secret, (action, payload) => {
    if (action === 'scan') {
      const current = config && status();
      if (
        !config?.prefs.enabled ||
        leaseUntil > Date.now() ||
        (current.reason && current.reason !== 'Loading scan engine')
      )
        throw Object.assign(Error(current?.reason || 'Background scanning is unavailable'), {
          code: 'SCANNER_UNAVAILABLE'
        });
      if (
        typeof payload?.file !== 'string' ||
        !path.isAbsolute(payload.file) ||
        /[\r\n\0]/.test(payload.file) ||
        typeof payload.id !== 'string' ||
        manual.size >= 4 ||
        manual.has(payload.id)
      )
        throw Error('Invalid or excessive scan request');
      return new Promise((resolve, reject) => {
        const job = { file: payload.file, abort: new AbortController(), resolve, reject, running: false };
        job.timer = setTimeout(() => {
          job.abort.abort();
          manual.delete(payload.id);
          reject(Error('Scan deadline exceeded'));
        }, 150000);
        manual.set(payload.id, job);
        setImmediate(tick);
      });
    }
    if (action === 'cancel-scan') {
      const job = manual.get(payload);
      if (job) {
        job.abort.abort();
        clearTimeout(job.timer);
        job.reject(Error('Scan cancelled'));
        manual.delete(payload);
      }
      return true;
    }
    const execute = async () => {
      if (action === 'status') {
        if (payload && Number.isFinite(payload.idleSeconds) && payload.idleSeconds >= 0)
          session = { idleSeconds: payload.idleSeconds, at: Date.now() };
        return status();
      }
      if (action === 'configure') {
        await configure(payload);
        return status();
      }
      if (action === 'ack') {
        if (!Array.isArray(payload) || payload.length > 100 || payload.some(x => typeof x !== 'string'))
          throw Error('Invalid acknowledgment');
        queue?.acknowledge(payload);
        flush();
        return true;
      }
      if (action === 'auto-restore' || action === 'auto-recheck' || action === 'auto-resolve') {
        if (leaseUntil <= Date.now()) throw Error('A desktop maintenance lease is required');
        if (typeof payload?.id !== 'string') throw Error('Invalid quarantine request');
        if (action === 'auto-restore') return autoVault.restore(payload.id, payload.target);
        if (action === 'auto-recheck') return autoVault.recheck(payload.id);
        return autoVault.resolve(payload.id, payload.action);
      }
      if (action === 'lease') {
        if (typeof payload?.id !== 'string') throw Error('Invalid maintenance lease');
        if (leaseUntil > Date.now() && leaseId !== payload.id)
          throw Error('Another desktop operation owns the scanner');
        epoch++;
        leaseId = payload.id;
        leaseUntil = Date.now() + 30000;
        if (updater) {
          updater.cancel();
          await updater.done.catch(() => {});
        }
        await stopEngine();
        return true;
      }
      if (action === 'release') {
        if (payload === leaseId) {
          leaseUntil = 0;
          leaseId = null;
          retryAt = 0;
        }
        return true;
      }
      if (action === 'stop') {
        setImmediate(() => shutdown());
        return true;
      }
      throw Error('Unknown monitor action');
    };
    const result = commands.then(execute);
    commands = result.catch(() => {});
    return result;
  });
  // Binding precedes reading/writing state: only one agent per profile may own the durable queue.
  server.listen(rpc.address(root));
  await once(server, 'listening');
  const vaultFolder = path.join(dir, 'quarantine');
  fs.mkdirSync(vaultFolder, { recursive: true, mode: 0o700 });
  const vaultState = store.load('quarantine', require('./schemas.cjs').quarantine);
  autoRecords = vaultState.value;
  if (vaultState.issue) fault = vaultState.issue.message;
  autoVault = createQuarantine({
    vault: vaultFolder,
    records: autoRecords,
    persist: () => store.save('quarantine', autoRecords, 1)
  });
  await autoVault.recover();
  const persisted = store.load('queue', queueSpec);
  if (persisted.issue) fault = persisted.issue.message;
  queueState = persisted.value;
  updateState = store.load(
    'updates',
    plainSpec(() => ({ nextAttempt: 0, failures: 0 }))
  ).value;
  databaseFault = typeof updateState.databaseFault === 'string' ? updateState.databaseFault : null;
  const loaded = store.load(
    'config',
    plainSpec(() => null)
  );
  if (loaded.value) await configure(loaded.value);
  async function tick() {
    if (busy || stopping) return;
    busy = true;
    const tickEpoch = epoch;
    try {
      if (Date.now() - sampleAt > 15000) {
        sampleAt = Date.now();
        sample = await sampleResources(engine?.proc?.pid);
      }
      await commands;
      if (!config || !queue) return;
      if (
        !config.prefs.keepRunning &&
        process.env.SENTINEL_SERVICE !== '1' &&
        session &&
        Date.now() - session.at > 90000
      ) {
        await shutdown();
        return;
      }
      if (config.prefs.telemetryEnabled && !status().reason) behavior.tick(true).catch(() => {});
      if (config.prefs.yaraEnabled && !rulesUpdating && Date.now() >= rulesNext) {
        rulesNext = Date.now() + 6 * 3600000;
        const updatingRules = rules;
        rulesUpdating = updatingRules
          .update()
          .then(
            () => {
              queue.cache.clear();
              queue.reconcileNeeded = true;
            },
            err => queue.note('YARA feed', err.message)
          )
          .finally(() => {
            rulesUpdating = null;
          });
      }
      if (
        !updater &&
        config.prefs.enabled &&
        config.autoUpdate &&
        !fault &&
        !stopping &&
        leaseUntil <= Date.now() &&
        (!session || Date.now() - session.at > 30000) &&
        Date.now() >= updateState.nextAttempt
      ) {
        await stopEngine();
        // Check again after cancellation/drain, since a desktop lease may have arrived in the meantime.
        if (leaseUntil > Date.now() || tickEpoch !== epoch) return;
        updater = updateDefinitions(config, dir);
        const work = updater;
        work.done
          .then(
            () => {
              databaseFault = null;
              updateState = { nextAttempt: Date.now() + 3600000, failures: 0 };
              engineKey = '';
              queue.cache.clear();
              queue.reconcileNeeded = true;
            },
            err => {
              if (err.databaseChanged)
                databaseFault = 'Definitions changed during an unsuccessful update; verification is required';
              updateState.failures++;
              updateState.nextAttempt =
                Date.now() + Math.min(6 * 3600000, 15 * 60000 * 2 ** Math.min(updateState.failures - 1, 5));
              if (/429|cool.?down|rate limit/i.test(err.message))
                updateState.nextAttempt = Math.max(updateState.nextAttempt, Date.now() + 4 * 3600000);
              queue.note('Definitions', err.message);
            }
          )
          .finally(() => {
            if (updater === work) updater = null;
            updateState.databaseFault = databaseFault;
            store.save('updates', updateState, 1);
            setImmediate(tick);
          });
        return;
      }
      const s = status();
      const info = inspectDatabase(config.database);
      if ((s.reason && s.reason !== 'Loading scan engine') || !info.present || config.blocked) {
        await stopEngine();
        return;
      }
      const key = info.fingerprint;
      if (key !== engineKey) {
        await stopEngine(false);
        engineKey = key;
        queue.databaseVersion = key;
        queue.reconcileNeeded = true;
      }
      queue.databaseVersion = key + '|' + (config.prefs.yaraEnabled ? rules.active()?.version || 'unavailable' : 'off');
      if (Date.now() < retryAt) return;
      if (!engine)
        engine = new Clamd({
          dir,
          database: config.database,
          engineDir: config.engineDir,
          prefs: config.prefs,
          options: config
        });
      // Engine startup is outside the command chain; check the maintenance lease again afterwards.
      const startingEngine = engine,
        startingEpoch = epoch;
      await startingEngine.start();
      if (startingEngine !== engine || startingEpoch !== epoch || leaseUntil > Date.now() || stopping) return;
      queue.paused = false;
      queue.externalActive = [...manual.values()].filter(j => j.running).length;
      await queue.pump();
      // Newly changed files get the next available slot before background directory sweeps.
      if (queue.running.size + queue.externalActive < config.prefs.concurrency) {
        const next = [...manual.entries()].find(([, j]) => !j.running);
        if (next) {
          const [id, job] = next;
          job.running = true;
          pipeline
            .scan(job.file, { signal: job.abort.signal })
            .then(job.resolve, job.reject)
            .finally(() => {
              clearTimeout(job.timer);
              manual.delete(id);
              setImmediate(tick);
            });
        }
      }
      if (watcher && (queue.reconcileNeeded || Date.now() - lastWalk > 300000)) {
        lastWalk = Date.now();
        watcher.reconcile().catch(err => {
          fault = err.message;
        });
      }
    } catch (err) {
      if (tickEpoch === epoch) {
        queue?.note('Scanner', err.message);
        retryAt = Date.now() + 30000;
        await stopEngine();
      }
    } finally {
      busy = false;
    }
  }
  async function shutdown() {
    if (stopping) return;
    stopping = true;
    clearInterval(timer);
    watcher?.close();
    if (updater) {
      updater.cancel();
      await updater.done.catch(() => {});
    }
    await stopEngine();
    flush();
    server.close();
  }
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
  process.on('uncaughtException', err => {
    fault = err.message;
    shutdown().finally(() => process.exit(1));
  });
  process.on('unhandledRejection', err => {
    fault = String(err);
    shutdown().finally(() => process.exit(1));
  });
  process.on('exit', () => {
    try {
      engine?.proc?.kill();
    } catch {}
  });
  timer = setInterval(tick, 500);
  tick();
  return { shutdown, status };
}

if (require.main === module)
  (process.argv.includes('--stop')
    ? rpc.request(process.argv[2], rpc.token(process.argv[2]), 'stop').catch(err => {
        if (!['ENOENT', 'ECONNREFUSED'].includes(err.code)) throw err;
      })
    : run(process.argv[2])
  ).catch(err => {
    if (err.code !== 'EADDRINUSE') console.error(err.message);
    process.exit(err.code === 'EADDRINUSE' ? 0 : 1);
  });
module.exports = { run };
