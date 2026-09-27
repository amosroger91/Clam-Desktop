// Runs one clamscan process and turns its output into scan progress and a final result.
// Electron-free so it can be tested with a fake process.
const nodeFs = require('node:fs');
const { StringDecoder } = require('node:string_decoder');
const { parseLine } = require('./core.cjs');

const MAX_WARNINGS = 200;
const MAX_LINE = 32 * 1024;
const DATABASE_FAILURE =
  /cli_load|cl_load|Can't load|Malformed database|database initialization error|No supported database/i;

// Splits a byte stream into complete lines. Multi-byte characters split across chunks are preserved,
// and unusually long lines are cut so malformed output cannot grow memory without bound.
function lineFramer(onLine) {
  const decoder = new StringDecoder('utf8');
  let buffer = '';
  const emit = text => {
    const lines = (buffer + text).split(/\r?\n/);
    buffer = lines.pop();
    if (buffer.length > MAX_LINE) buffer = buffer.slice(0, MAX_LINE);
    for (const line of lines) if (line) onLine(line.length > MAX_LINE ? line.slice(0, MAX_LINE) : line);
  };
  return {
    write: chunk => emit(decoder.write(chunk)),
    end: () => {
      emit(decoder.end());
      if (buffer) onLine(buffer);
      buffer = '';
    }
  };
}

/**
 * Starts a scan. Returns { pid, cancel(reason), done } where done resolves (never rejects) with:
 * { exitCode, error, cancelReason, files, threats, warnings, warningCount, databaseError, logTruncated }
 */
function startScan({
  exe,
  args,
  logPath,
  spawn,
  fs = nodeFs,
  forceKill = () => {},
  onProgress = () => {},
  killTimeoutMs = 5000,
  maxLogBytes = 64 * 1024 * 1024
}) {
  const result = {
    exitCode: null,
    error: null,
    cancelReason: null,
    phase: 'loading',
    current: 'Loading signature database…',
    files: 0,
    threats: [],
    warnings: [],
    warningCount: 0,
    databaseError: false,
    logTruncated: false
  };
  let resolveDone;
  const done = new Promise(resolve => (resolveDone = resolve));

  // Log writing respects backpressure and a size cap; the log never blocks completion.
  const log = fs.createWriteStream(logPath);
  let logBytes = 0,
    logFailed = false;
  log.on('error', err => {
    logFailed = true;
    warn('Could not write the scan log: ' + err.message);
  });

  let proc;
  function writeLog(chunk) {
    if (logFailed || result.logTruncated) return;
    if (logBytes + chunk.length > maxLogBytes) {
      result.logTruncated = true;
      log.write(`\n[Sentinel: log truncated after ${Math.round(maxLogBytes / 1048576)} MB]\n`);
      return;
    }
    logBytes += chunk.length;
    if (!log.write(chunk) && proc?.stdout?.pause) {
      proc.stdout.pause();
      log.once('drain', () => proc.stdout.resume());
    }
  }

  function warn(message) {
    result.warningCount++;
    if (result.warnings.length < MAX_WARNINGS) result.warnings.push(message);
    if (DATABASE_FAILURE.test(message)) result.databaseError = true;
  }

  function line(text, fromStderr) {
    const parsed = parseLine(text.trim());
    if (parsed.type === 'scanning' || parsed.type === 'file' || parsed.type === 'threat') result.phase = 'scanning';
    if (parsed.type === 'scanning') result.current = parsed.path;
    else if (parsed.type === 'file') {
      result.files++;
      result.current = parsed.path;
    } else if (parsed.type === 'threat') {
      result.files++;
      result.threats.push({ path: parsed.path, signature: parsed.signature });
    } else if (parsed.type === 'count') result.files = parsed.count;
    else if (parsed.type === 'warning') warn(parsed.message);
    // stderr carries LibClamAV messages; informational lines there are not treated as warnings,
    // but database failures are recorded whichever stream reports them.
    else if (fromStderr && DATABASE_FAILURE.test(text)) result.databaseError = true;
  }

  const stdout = lineFramer(t => line(t, false));
  const stderr = lineFramer(t => line(t, true));
  let finished = false,
    killTimer = null;

  function finish(exitCode, error) {
    if (finished) return;
    finished = true;
    clearTimeout(killTimer);
    stdout.end();
    stderr.end();
    result.exitCode = exitCode;
    if (error) {
      result.error = error.message;
      warn(error.message);
    }
    result.phase = 'finished';
    // Resolve after the log is flushed and closed, but never wait on it indefinitely.
    let settled = false;
    const settle = () => {
      if (!settled) {
        settled = true;
        resolveDone(result);
      }
    };
    log.once('close', settle);
    log.once('error', settle);
    setTimeout(settle, 3000).unref?.();
    log.end();
  }

  try {
    proc = spawn(exe, args, { windowsHide: true });
  } catch (err) {
    finish(null, err);
    return { pid: null, cancel: () => {}, done, snapshot: () => result };
  }
  proc.stdout.on('data', chunk => {
    writeLog(chunk);
    stdout.write(chunk);
    onProgress(result);
  });
  proc.stderr.on('data', chunk => {
    writeLog(chunk);
    stderr.write(chunk);
    onProgress(result);
  });
  proc.on('error', err => finish(null, err));
  proc.on('close', code => finish(code));

  function cancel(reason = 'user') {
    if (finished || result.cancelReason) return;
    result.cancelReason = reason;
    result.phase = 'cancelling';
    let signalled = false;
    try {
      signalled = proc.kill();
    } catch {}
    // A process that ignores the request (or could not be signalled) is force-terminated by PID.
    killTimer = setTimeout(() => forceKill(proc.pid), signalled ? killTimeoutMs : 0);
    killTimer.unref?.();
  }

  return { pid: proc.pid, cancel, done, snapshot: () => result };
}

// Maps a finished scan to a report status.
function reportStatus(result) {
  if (result.cancelReason === 'shutdown') return 'interrupted';
  if (result.cancelReason) return 'cancelled';
  if (result.error || ![0, 1].includes(result.exitCode)) return 'error';
  return result.warningCount ? 'partial' : 'completed';
}

module.exports = { startScan, reportStatus, lineFramer };
