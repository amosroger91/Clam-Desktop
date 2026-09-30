const fs = require('node:fs');
const path = require('node:path');
const { spawn, execFile } = require('node:child_process');
const database = require('./database.cjs');

// Used only when the desktop heartbeat has expired. The agent owns all children and stops the engine
// before replacing definitions. A desktop maintenance lease cancels this operation before being granted.
function updateDefinitions(config, dir) {
  const abort = new AbortController();
  const before = database.inspect(config.database).fingerprint;
  let child;
  const done = (async () => {
    const file = path.join(dir, 'freshclam.conf');
    fs.writeFileSync(file, `DatabaseMirror database.clamav.net\nDatabaseDirectory "${config.database}"\n`);
    await new Promise((resolve, reject) => {
      let tail = '';
      child = spawn(path.join(config.engineDir, 'freshclam.exe'), ['--config-file=' + file, '--stdout'], {
        windowsHide: true
      });
      const timer = setTimeout(() => {
        child.kill();
        reject(Error('Background definition update timed out'));
      }, 20 * 60000);
      const stop = () => child.kill();
      abort.signal.addEventListener('abort', stop, { once: true });
      const append = data => {
        tail = (tail + data.toString()).slice(-4096);
      };
      child.stdout.on('data', append);
      child.stderr.on('data', append);
      child.once('error', err => {
        clearTimeout(timer);
        reject(err);
      });
      child.once('close', code => {
        clearTimeout(timer);
        abort.signal.removeEventListener('abort', stop);
        if (abort.signal.aborted) reject(Error('Background definition update cancelled'));
        else if (code === 0) resolve();
        else reject(Error(tail || 'Background definition update failed'));
      });
    });
    abort.signal.throwIfAborted();
    const info = database.inspect(config.database);
    if (!info.present || info.unreadable.length) throw Error('Updated definitions are missing or unreadable');
    const verified = await database.verify(
      info.files,
      path.join(config.engineDir, 'sigtool.exe'),
      (exe, args) =>
        new Promise((resolve, reject) =>
          execFile(
            exe,
            args,
            { windowsHide: true, timeout: 120000, maxBuffer: 1048576, signal: abort.signal },
            (err, stdout, stderr) => (err ? reject(err) : resolve(stdout + stderr))
          )
        )
    );
    if (!verified.verified) throw Error('Background definition verification failed: ' + verified.failures.join(', '));
    return info.fingerprint;
  })().catch(err => {
    err.databaseChanged = database.inspect(config.database).fingerprint !== before;
    throw err;
  });
  return {
    done,
    cancel() {
      abort.abort();
      child?.kill();
    },
    get pid() {
      return child?.pid;
    }
  };
}
module.exports = { updateDefinitions };
