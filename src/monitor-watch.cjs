const fs = require('node:fs');
const path = require('node:path');

// Notifications provide low latency. A yielding directory walk repairs missed notifications, queue
// overflow, newly-created subtrees and offline changes. Symlinks/junctions are never traversed.
function watchFolders(queue, { onError = () => {} } = {}) {
  const watchers = new Map();
  let closed = false,
    walking = false;
  function attach() {
    for (const folder of queue.folders) {
      if (watchers.has(folder)) continue;
      try {
        const watcher = fs.watch(folder, { recursive: true }, (_event, filename) => {
          if (!filename) {
            queue.reconcileNeeded = true;
            return;
          }
          const file = path.join(folder, filename.toString());
          if (!queue.allowed(file)) return;
          queue.enqueue(file, 1);
          // Renaming a populated directory may produce only one notification.
          if (_event === 'rename') queue.reconcileNeeded = true;
        });
        watcher.on('error', err => {
          watcher.close();
          watchers.delete(folder);
          queue.reconcileNeeded = true;
          onError(folder, err);
        });
        watchers.set(folder, watcher);
      } catch (err) {
        onError(folder, err);
      }
    }
  }
  async function* files(folder) {
    if (closed || !queue.allowed(folder)) return;
    let dir;
    try {
      dir = await fs.promises.opendir(folder);
    } catch (err) {
      onError(folder, err);
      return;
    }
    for await (const entry of dir) {
      if (closed) break;
      const file = path.join(folder, entry.name);
      if (!queue.allowed(file) || entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) yield* files(file);
      else if (entry.isFile()) yield file;
    }
  }
  async function reconcile() {
    if (walking || closed) return;
    walking = true;
    queue.reconcileNeeded = false;
    attach();
    try {
      for (const folder of queue.folders)
        for await (const file of files(folder)) {
          if (closed) return;
          // Bound memory without dropping the rest of a large tree. The walk resumes as the queue drains.
          while (!closed && (queue.pending.size >= queue.prefs.maxQueue || queue.paused))
            await new Promise(resolve => setTimeout(resolve, 250));
          if (closed) return;
          await queue.consider(file);
          await new Promise(resolve => setImmediate(resolve));
        }
    } catch (err) {
      onError('Reconciliation', err);
      queue.reconcileNeeded = true;
    } finally {
      walking = false;
    }
  }
  attach();
  return {
    reconcile,
    get walking() {
      return walking;
    },
    close() {
      closed = true;
      for (const w of watchers.values()) w.close();
    }
  };
}

module.exports = { watchFolders };
