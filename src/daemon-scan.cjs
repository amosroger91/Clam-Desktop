const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { inside, fingerprint } = require('./monitor-queue.cjs');

// Cooperative directory scanning: one low-priority file at a time leaves the daemon's scheduler free
// to service filesystem events between files. No second signature database is loaded.
function startDaemonScan({ targets, exclusions, client, onThreat, onProgress, logPath }) {
  const result = { exitCode: 0, files: 0, threats: [], warnings: [], warningCount: 0, phase: 'scanning', current: '' };
  let cancelled = false,
    requestId = null;
  const log = fs.createWriteStream(logPath);
  let bytes = 0;
  log.on('error', err => {
    result.logError = err.message;
  });
  const write = text => {
    if (bytes > 64 * 1048576 || log.destroyed) {
      result.logTruncated = true;
      return;
    }
    bytes += Buffer.byteLength(text);
    log.write(text);
  };
  const warning = text => {
    result.warningCount++;
    if (result.warnings.length < 200) result.warnings.push(text);
    write(text + '\n');
  };
  async function visit(file) {
    if (cancelled || result.error || exclusions.some(dir => inside(file, dir))) return;
    let stat;
    try {
      stat = await fs.promises.lstat(file);
    } catch (err) {
      warning(file + ': ' + err.message + ' ERROR');
      return;
    }
    if (stat.isSymbolicLink()) {
      warning(file + ': symbolic link skipped ERROR');
      return;
    }
    if (stat.isDirectory()) {
      try {
        for await (const entry of await fs.promises.opendir(file)) {
          if (cancelled || result.error) break;
          await visit(path.join(file, entry.name));
        }
      } catch (err) {
        warning(file + ': ' + err.message + ' ERROR');
      }
      return;
    }
    if (!stat.isFile()) return;
    result.current = file;
    onProgress(result);
    try {
      requestId = crypto.randomUUID();
      const verdict = await client.call('scan', { file, id: requestId }, 180000);
      const after = await fs.promises.lstat(file);
      if (fingerprint(stat) !== fingerprint(after)) throw Error('File changed during scan; retry required');
      result.files++;
      if (!verdict.clean) {
        const threat = { path: file, signature: verdict.signature };
        await onThreat(threat);
        result.threats.push(threat);
        result.exitCode = 1;
        write(`${file}: ${verdict.signature} FOUND\n`);
      } else write(file + ': OK\n');
    } catch (err) {
      if (!cancelled) warning(file + ': ' + err.message + ' ERROR');
      if (err.code === 'SCANNER_UNAVAILABLE') {
        result.error = err.message;
        result.exitCode = 2;
      }
    } finally {
      requestId = null;
      onProgress(result);
    }
  }
  const done = (async () => {
    try {
      for (const target of targets) await visit(target);
    } catch (err) {
      result.error = err.message;
      result.exitCode = 2;
    }
    result.phase = 'finished';
    await new Promise(resolve => {
      if (log.destroyed || log.closed) return resolve();
      const timer = setTimeout(resolve, 3000);
      log.once('close', () => {
        clearTimeout(timer);
        resolve();
      });
      log.end();
    });
    return result;
  })();
  return {
    pid: null,
    done,
    cancel(reason = 'user') {
      cancelled = true;
      result.cancelReason = reason;
      if (requestId) client.call('cancel-scan', requestId).catch(() => {});
    }
  };
}

module.exports = { startDaemonScan };
