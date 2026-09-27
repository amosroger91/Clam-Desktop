const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createFatalHandler, nextCrashState, SAFE_MODE_AFTER } = require('../src/fatal.cjs');

function harness(overrides = {}) {
  const calls = [];
  const handler = createFatalHandler({
    stopMutations: () => calls.push('stop'),
    killChildren: () => calls.push('kill'),
    writeDiagnostics: text => calls.push('diagnostics:' + text.split('\n')[0]),
    markCrash: () => calls.push('mark'),
    exit: code => calls.push('exit:' + code),
    ...overrides
  });
  return { calls, handler };
}

test('R12: a fatal fault stops mutations, kills children, keeps diagnostics, and exits nonzero', () => {
  const { calls, handler } = harness();
  handler.handle(Error('completion callback threw'), 'uncaughtException');
  assert.deepEqual(calls, [
    'stop',
    'kill',
    'diagnostics:uncaughtException: Error: completion callback threw',
    'mark',
    'exit:1'
  ]);
  assert.equal(handler.isFatal(), true);
});

test('R12: handling is idempotent; a second fault does not re-run cleanup', () => {
  const { calls, handler } = harness();
  handler.handle(Error('first'), 'uncaughtException');
  handler.handle(Error('second'), 'unhandledRejection');
  assert.equal(calls.filter(c => c.startsWith('exit')).length, 1);
});

test('R12: failures while logging or cleaning up still end in a nonzero exit', () => {
  const { calls, handler } = harness({
    writeDiagnostics: () => {
      throw Object.assign(Error('disk full'), { code: 'ENOSPC' });
    },
    killChildren: () => {
      throw Error('taskkill missing');
    }
  });
  handler.handle('a rejected startup promise', 'unhandledRejection');
  assert.deepEqual(calls, ['stop', 'mark', 'exit:1']);
});

test('R12: repeated crashes soon after start enter safe mode instead of looping', () => {
  const start = t => new Date(Date.UTC(2026, 8, 27, 12, t)).toISOString();
  let state = null;
  for (let i = 0; i < SAFE_MODE_AFTER; i++) {
    assert.equal(state?.safeMode ?? false, false);
    state = nextCrashState(state, { startedAt: start(i * 2), crashedAt: start(i * 2) });
  }
  assert.equal(state.safeMode, true);
  // A crash long after startup is not a startup crash loop.
  const later = nextCrashState(null, { startedAt: start(0), crashedAt: start(30) });
  assert.equal(later.consecutiveStartupCrashes, 0);
  assert.equal(later.safeMode, false);
});
