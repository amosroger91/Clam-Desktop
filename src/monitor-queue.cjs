const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const key = file => path.resolve(file).toLowerCase();
const inside = (file, dir) => key(file) === key(dir) || key(file).startsWith(key(dir) + path.sep);
const fingerprint = stat => `${stat.dev}:${stat.ino}:${stat.size}:${stat.mtimeMs}:${stat.ctimeMs}`;
const highRisk = file =>
  /\.(exe|dll|msi|msp|msix|zip|7z|rar|iso|bat|cmd|ps1|vbs|js|jse|scr|com|hta|lnk|jar)$/i.test(file);

// All queue mutations occur in the background process. In-flight entries stay persisted until their
// verdict and outbox event have been saved, so an abrupt stop simply retries them on the next start.
class MonitorQueue {
  constructor({
    prefs,
    folders,
    exclusions,
    scan,
    onThreat = async () => {},
    save = () => {},
    emit = () => {},
    state = {},
    now = Date.now
  }) {
    Object.assign(this, { prefs, folders, exclusions, scan, onThreat, save, emit, now });
    this.pending = new Map((state.pending || []).slice(0, prefs.maxQueue).map(e => [key(e.path), e]));
    this.cache = new Map((state.cache || []).slice(-20000));
    this.outbox = state.outbox || [];
    this.metrics = { scanned: 0, detections: 0, errors: 0, skipped: 0, overflows: 0, ...state.metrics };
    this.recent = state.recent || [];
    this.running = new Map();
    this.reconcileNeeded = true;
    this.paused = true;
    this.databaseVersion = '';
    this.latencies = [];
  }
  allowed(file) {
    return this.folders.some(dir => inside(file, dir)) && !this.exclusions.some(dir => inside(file, dir));
  }
  snapshot() {
    return {
      pending: [...this.pending.values()],
      cache: [...this.cache].slice(-20000),
      outbox: this.outbox,
      metrics: this.metrics,
      recent: this.recent
    };
  }
  persist() {
    this.save(this.snapshot());
  }
  enqueue(file, priority = 0) {
    file = path.resolve(file);
    if (!this.allowed(file)) return false;
    if (this.prefs.highRiskOnly && !highRisk(file)) return false;
    const id = key(file),
      old = this.pending.get(id);
    if (!old && this.pending.size >= this.prefs.maxQueue) {
      this.metrics.overflows++;
      this.reconcileNeeded = true;
      return false;
    }
    const now = this.now();
    this.pending.set(id, {
      path: file,
      firstSeen: old?.firstSeen || now,
      due: now + this.prefs.settleMs,
      priority: Math.max(priority, old?.priority || 0),
      attempts: old?.attempts || 0,
      revision: (old?.revision || 0) + 1
    });
    this.persist();
    return true;
  }
  async consider(file, priority = 0) {
    if (!this.allowed(file) || this.pending.has(key(file))) return;
    try {
      const stat = await fs.promises.lstat(file);
      if (!stat.isFile() || stat.isSymbolicLink()) return;
      const cached = this.cache.get(key(file));
      if (cached === this.databaseVersion + '|' + fingerprint(stat)) return;
      this.enqueue(file, priority);
    } catch (err) {
      if (!['ENOENT', 'ENOTDIR'].includes(err.code)) this.note(file, err.message);
    }
  }
  note(file, message) {
    this.recent = [{ path: file, message, at: new Date(this.now()).toISOString() }, ...this.recent].slice(0, 50);
  }
  async pump() {
    if (this.paused || this.outbox.length >= 1000) return;
    const slots = Math.max(0, this.prefs.concurrency - this.running.size - (this.externalActive || 0));
    const entries = [...this.pending.entries()]
      .filter(([id, e]) => !this.running.has(id) && e.due <= this.now())
      .sort((a, b) => b[1].priority - a[1].priority || a[1].firstSeen - b[1].firstSeen)
      .slice(0, slots);
    for (const [id, entry] of entries) {
      const abort = new AbortController();
      const task = this.process(id, entry, abort.signal).finally(() => {
        this.running.delete(id);
        this.emit();
      });
      this.running.set(id, { abort, task, path: entry.path });
    }
  }
  async process(id, entry, signal) {
    let forget = false;
    try {
      if (!this.allowed(entry.path)) {
        forget = true;
        return;
      }
      const before = await fs.promises.lstat(entry.path);
      if (!before.isFile() || before.isSymbolicLink()) {
        forget = true;
        return;
      }
      const actual = await fs.promises.realpath(entry.path);
      if (!this.allowed(actual) || key(actual) !== key(entry.path)) {
        this.note(entry.path, 'Skipped a redirected path');
        forget = true;
        this.metrics.skipped++;
        return;
      }
      if (before.size > this.prefs.maxFileMB * 1048576) {
        this.note(entry.path, 'File exceeds the configured size limit; not scanned');
        this.metrics.skipped++;
        forget = true;
        // Remember the unsupported version to avoid continuously requeuing it. A policy change clears cache.
        this.cache.set(id, this.databaseVersion + '|' + fingerprint(before));
        return;
      }
      if (this.now() - before.mtimeMs < this.prefs.settleMs) {
        entry.due = this.now() + this.prefs.settleMs;
        return;
      }
      const version = this.databaseVersion;
      const verdict = await this.scan(entry.path, { signal });
      if (signal.aborted) throw Error('Scan cancelled');
      const after = await fs.promises.lstat(entry.path);
      // A verdict for bytes that changed underneath the engine cannot certify the new file.
      if (fingerprint(before) !== fingerprint(after)) {
        entry.due = this.now() + this.prefs.settleMs;
        this.note(entry.path, 'File changed during scan; queued again');
        return;
      }
      if (!verdict.clean) {
        const event = {
          id: crypto.randomUUID(),
          path: entry.path,
          signature: verdict.signature,
          at: new Date(this.now()).toISOString(),
          size: after.size,
          fingerprint: fingerprint(after)
        };
        Object.assign(event, { sha256: verdict.sha256, engine: verdict.engine, action: verdict.action || 'review' });
        this.outbox.push(event);
        this.metrics.detections++;
        this.persist(); // Durably announce the detection before any quarantine mutation.
        try {
          await this.onThreat(event);
        } catch (err) {
          event.quarantineError = err.message;
        }
      }
      this.metrics.scanned++;
      this.recent = this.recent.filter(e => e.path !== entry.path);
      this.latencies.push(this.now() - entry.firstSeen);
      this.latencies = this.latencies.slice(-100);
      this.cache.delete(id);
      this.cache.set(id, version + '|' + fingerprint(after));
      if (this.cache.size > 20000) this.cache.delete(this.cache.keys().next().value);
      forget = true;
    } catch (err) {
      if (['ENOENT', 'ENOTDIR'].includes(err.code)) forget = true;
      else if (signal.aborted) {
        entry.due = this.now() + this.prefs.settleMs;
      } else {
        entry.attempts++;
        entry.due = this.now() + Math.min(600000, 2000 * 2 ** Math.min(entry.attempts, 9));
        this.metrics.errors++;
        this.note(entry.path, err.message);
      }
    } finally {
      // Do not consume a newer filesystem event that arrived while this scan was in flight.
      if (forget && this.pending.get(id) === entry) this.pending.delete(id);
      this.persist();
    }
  }
  async pause() {
    this.paused = true;
    for (const work of this.running.values()) work.abort.abort();
    await Promise.allSettled([...this.running.values()].map(work => work.task));
  }
  acknowledge(ids) {
    const received = new Set(ids);
    this.outbox = this.outbox.filter(e => !received.has(e.id));
    this.persist();
  }
  status() {
    const oldest = Math.min(this.now(), ...[...this.pending.values()].map(e => e.firstSeen));
    const sorted = [...this.latencies].sort((a, b) => a - b);
    return {
      queued: this.pending.size,
      active: this.running.size,
      oldestSeconds: Math.round((this.now() - oldest) / 1000),
      pendingDetections: this.outbox.length,
      metrics: this.metrics,
      recent: this.recent.slice(0, 10),
      p95Ms: sorted.length ? sorted[Math.ceil(sorted.length * 0.95) - 1] : null
    };
  }
}

module.exports = { MonitorQueue, fingerprint, inside, highRisk };
