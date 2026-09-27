// Operation coordinator (R08, Q1). Every scan, update, install, database check, file operation, and
// detection hashing runs as a tracked operation with an id, a type, and a label. Conflicting operations
// never overlap; once shutdown begins no new operation is accepted, and shutdown can wait (bounded) for
// running ones. Native dialogs are never held as locks: callers ask for permission after confirmation.
const crypto = require('node:crypto');

// Symmetric conflict matrix.
//   scan     a ClamAV scan (reads files, loads the database)
//   update   FreshClam replacing the database
//   install  downloading and installing the engine (includes its first update)
//   verify   sigtool verification or a controlled database load check
//   file     quarantine, restore, or resolving a quarantine review (moves user files)
//   identify hashing detected files to record their identity
const CONFLICTS = {
  scan: ['scan', 'update', 'install', 'file'],
  update: ['scan', 'update', 'install', 'verify'],
  install: ['scan', 'update', 'install', 'verify'],
  verify: ['update', 'install', 'verify'],
  file: ['scan', 'file', 'identify'],
  identify: ['file', 'identify']
};

class OperationConflict extends Error {
  constructor(message, reason) {
    super(message);
    this.name = 'OperationConflict';
    this.reason = reason;
  }
}

// `onChange` is called whenever an operation starts or ends, so status displays never go stale.
function createCoordinator({ now = () => new Date(), onChange = () => {} } = {}) {
  const running = new Map();
  let closed = false;
  let waiters = [];

  const conflictsWith = type => [...running.values()].find(op => CONFLICTS[type].includes(op.type)) || null;

  function begin(type, label = type) {
    if (!CONFLICTS[type]) throw Error('Unknown operation type: ' + type);
    if (closed) throw new OperationConflict('Sentinel is closing.', 'closing');
    const blocker = conflictsWith(type);
    if (blocker) throw new OperationConflict(`Wait for “${blocker.label}” to finish.`, 'conflict');
    const op = { id: crypto.randomUUID(), type, label, started: now().toISOString() };
    running.set(op.id, op);
    onChange();
    op.end = () => {
      if (!running.delete(op.id)) return;
      onChange();
      if (!running.size) {
        waiters.forEach(resolve => resolve());
        waiters = [];
      }
    };
    return op;
  }

  function tryBegin(type, label) {
    try {
      return begin(type, label);
    } catch (err) {
      if (err instanceof OperationConflict) return null;
      throw err;
    }
  }

  async function run(type, label, fn) {
    const op = begin(type, label);
    try {
      return await fn(op);
    } finally {
      op.end();
    }
  }

  // Resolves with the operations still running when everything finished or the time limit passed.
  function drain(timeoutMs) {
    if (!running.size) return Promise.resolve([]);
    return new Promise(resolve => {
      const timer = setTimeout(() => resolve(active()), timeoutMs);
      waiters.push(() => {
        clearTimeout(timer);
        resolve([]);
      });
    });
  }

  const active = () => [...running.values()].map(({ id, type, label, started }) => ({ id, type, label, started }));

  return {
    begin,
    tryBegin,
    run,
    drain,
    active,
    conflictsWith,
    close: () => (closed = true),
    isClosed: () => closed
  };
}

module.exports = { createCoordinator, CONFLICTS, OperationConflict };
