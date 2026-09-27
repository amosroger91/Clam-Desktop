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
  // Called synchronously for each detection as it is parsed, so it can be made durable immediately.
  onThreat = () => {},
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
    logTruncated: false,
    logError: null
  };
  let resolveDone;
  const done = new Promise(resolve => (resolveDone = resolve));

  // The diagnostic log respects backpressure and a size cap, but it is never allowed to stall the
  // scanner: the stream that caused the pressure is paused, and every paused stream resumes on drain,
  // log failure, log close, or cancellation. Parsing continues when the log is unavailable.
  const log = fs.createWriteStream(logPath);
  const paused = new Set();
  let logBytes = 0,
    logUsable = true;
  function resumeAll() {
    for (const stream of paused) stream.resume();
    paused.clear();
  }
  function stopLogging(message) {
    if (!logUsable) return;
    logUsable = false;
    if (message) {
      result.logError = message;
      warn('Could not write the scan log: ' + message);
    }
    resumeAll();
  }
  log.on('drain', resumeAll);
  log.on('error', err => stopLogging(err.message));
  log.on('close', () => stopLogging(null));

  let proc;
  function writeLog(chunk, source) {
    if (!logUsable || result.logTruncated) return;
    if (logBytes + chunk.length > maxLogBytes) {
      result.logTruncated = true;
      log.write(`\n[Sentinel: log truncated after ${Math.round(maxLogBytes / 1048576)} MB]\n`);
      return;
    }
    logBytes += chunk.length;
    if (!log.write(chunk) && logUsable && source?.pause) {
      source.pause();
      paused.add(source);
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
      const threat = { path: parsed.path, signature: parsed.signature };
      result.threats.push(threat);
      try {
        onThreat(threat);
      } catch (err) {
        result.evidenceError ??= err.message;
      }
    } else if (parsed.type === 'count') result.files = parsed.count;
    else if (parsed.type === 'warning') warn(parsed.message);
    // stderr carries LibClamAV messages; informational lines there are not treated as warnings,
    // but database failures are recorded whichever stream reports them.
    else if (fromStderr && DATABASE_FAILURE.test(text)) result.databaseError = true;
  }

  const stdout = lineFramer(t => line(t, false));
  const stderr = lineFramer(t => line(t, true));
  let finished = false,
    finalized = false,
    killTimer = null;

  // Completion runs once. Output still buffered in a paused stream is parsed before the report is
  // finalized (bounded, so a stuck stream cannot hold completion forever).
  function finish(exitCode, error) {
    if (finished) return;
    finished = true;
    clearTimeout(killTimer);
    resumeAll();
    let turns = 0;
    const pending = () =>
      [proc?.stdout, proc?.stderr].some(
        s => s && !s.readableEnded && ((s.readableLength ?? 0) > 0 || (s.writableLength ?? 0) > 0)
      );
    const waitForOutput = () => (pending() && turns++ < 100 ? setImmediate(waitForOutput) : finalize(exitCode, error));
    waitForOutput();
  }

  function finalize(exitCode, error) {
    finalized = true;
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
    if (finalized) return;
    writeLog(chunk, proc.stdout);
    stdout.write(chunk);
    onProgress(result);
  });
  proc.stderr.on('data', chunk => {
    if (finalized) return;
    writeLog(chunk, proc.stderr);
    stderr.write(chunk);
    onProgress(result);
  });
  proc.on('error', err => finish(null, err));
  proc.on('close', code => finish(code));

  function cancel(reason = 'user') {
    if (finished || result.cancelReason) return;
    result.cancelReason = reason;
    result.phase = 'cancelling';
    resumeAll();
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
