// Fatal-fault policy (R12). After an uncaught exception or unhandled rejection the process may hold broken
// invariants, so it must not keep coordinating file operations. The handler stops accepting mutations,
// terminates owned child processes, preserves diagnostics, records the crash, and exits nonzero. Recovery
// happens on the next clean start from the durable journals, never inside the faulted process.

const STARTUP_WINDOW_MS = 60000;
const SAFE_MODE_AFTER = 3;

function createFatalHandler({ stopMutations, killChildren, writeDiagnostics, markCrash, exit }) {
  let fatal = false;
  const attempt = fn => {
    try {
      fn();
    } catch {}
  };
  function handle(error, origin) {
    if (fatal) return;
    fatal = true;
    attempt(stopMutations);
    attempt(killChildren);
    const detail = error instanceof Error ? error.stack || `${error.name}: ${error.message}` : String(error);
    attempt(() => writeDiagnostics(`${origin}: ${detail.startsWith('Error') ? detail : 'Error: ' + detail}`));
    attempt(markCrash);
    exit(1);
  }
  return { handle, isFatal: () => fatal };
}

// Tracks consecutive crashes that happen shortly after startup. After SAFE_MODE_AFTER of them, the next
// launch starts in safe mode (no automatic scans or updates) instead of repeating the same failure.
function nextCrashState(previous, { startedAt, crashedAt }) {
  const early = new Date(crashedAt) - new Date(startedAt) < STARTUP_WINDOW_MS;
  const consecutiveStartupCrashes = early ? (previous?.consecutiveStartupCrashes ?? 0) + 1 : 0;
  return {
    lastCrash: crashedAt,
    consecutiveStartupCrashes,
    safeMode: consecutiveStartupCrashes >= SAFE_MODE_AFTER
  };
}

module.exports = { createFatalHandler, nextCrashState, SAFE_MODE_AFTER, STARTUP_WINDOW_MS };
