// Journaled quarantine and restore.
//
// Every operation persists its intent before touching the file system, and recovery decides what happened
// from content hashes, not from whether a path exists. A copy is deleted only when identical content is
// verified to exist elsewhere. When identity or completeness is uncertain, both copies are kept and the
// record is marked 'recovery-needed' for the user to review.
//
// Record statuses: prepared → quarantined (same volume: atomic rename)
//                  prepared → copying → quarantined (across volumes: copy, verify, then remove original)
//                  quarantined → restoring → restored
//                  failed (nothing was moved), recovery-needed (user review), reviewed (user dismissed)
const nodeFs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { identify, hashFile } = require('./files.cjs');

const MAX_AUDIT = 30;

class QuarantineError extends Error {
  constructor(message, reason) {
    super(message);
    this.reason = reason;
  }
}

function createQuarantine({
  vault,
  records,
  persist,
  onDetection = () => {},
  fs = nodeFs,
  now = () => new Date(),
  // Test hook: throws at a named step to simulate a crash at that point.
  fault = () => {}
}) {
  let queue = Promise.resolve();
  // File operations run one at a time so a restore cannot race a quarantine of the same file.
  const exclusive = fn => {
    const run = queue.then(fn, fn);
    queue = run.catch(() => {});
    return run;
  };
  const at = () => now().toISOString();
  const partialOf = r => r.stored + '.partial';
  const restoreTempOf = (r, target) =>
    path.join(path.dirname(target), `.${path.basename(target)}.${r.id}.sentinel-restore`);
  const exists = async p =>
    fs.promises.lstat(p).then(
      () => true,
      () => false
    );
  const remove = p => fs.promises.rm(p, { force: true });

  function log(r, action, detail = null) {
    r.updated = at();
    r.audit.push({ at: r.updated, action, detail });
    if (r.audit.length > MAX_AUDIT) r.audit.splice(1, r.audit.length - MAX_AUDIT);
  }
  function set(r, status, action, detail = null, extra = {}) {
    Object.assign(r, { status, issue: null, options: [], ...extra });
    log(r, action, detail);
  }
  // Saving after the file system changed must not hide that change; recovery reconciles it later.
  function persistAfterChange(r) {
    try {
      persist();
    } catch (err) {
      r.saveError = err.message;
    }
  }

  function quarantine(detection) {
    return exclusive(async () => {
      const found = await identify(detection.path, fs);
      if (!found) throw new QuarantineError('The file is no longer at its detected location.', 'missing');
      if (!found.regular) throw new QuarantineError('Only regular files can be quarantined.', 'not-regular');
      if (detection.sha256 && found.sha256 !== detection.sha256)
        throw new QuarantineError(
          'The file has changed since it was detected. Scan it again before quarantining.',
          'changed'
        );
      const id = crypto.randomUUID();
      const r = {
        id,
        detectionId: detection.id,
        original: detection.path,
        stored: path.join(vault, id + '.quarantine'),
        signature: detection.signature,
        sha256: found.sha256,
        size: found.size,
        // Supporting information only; identity is established by the content hash.
        modified: found.modified,
        created: at(),
        status: 'prepared',
        error: null,
        issue: null,
        options: [],
        audit: []
      };
      log(r, 'prepared');
      records.unshift(r);
      try {
        persist();
      } catch (err) {
        records.splice(records.indexOf(r), 1);
        throw err;
      }
      fault('prepared');
      try {
        await fs.promises.rename(r.original, r.stored);
        fault('moved');
        set(r, 'quarantined', 'moved');
      } catch (err) {
        if (err.reason === 'fault') throw err;
        if (err.code !== 'EXDEV') {
          set(r, 'failed', 'failed', err.message, { error: friendly(err) });
          persistAfterChange(r);
          throw new QuarantineError(r.error, 'failed');
        }
        try {
          await copyAcrossVolumes(r);
        } catch (copyErr) {
          if (copyErr.reason === 'fault') throw copyErr;
          // Let recovery decide from the files what state this partial operation left behind.
          await recoverQuarantine(r);
          persistAfterChange(r);
          throw new QuarantineError(friendly(copyErr) + (r.issue ? ' ' + r.issue : ''), 'failed');
        }
      }
      persistAfterChange(r);
      onDetection(r.detectionId, r.status === 'quarantined' ? 'quarantined' : 'detected', r);
      return r;
    });
  }

  async function copyAcrossVolumes(r) {
    set(r, 'copying', 'copying');
    persist();
    fault('copying');
    await fs.promises.copyFile(r.original, partialOf(r), fs.constants.COPYFILE_EXCL);
    fault('copied-partial');
    if ((await hashFile(partialOf(r), fs)) !== r.sha256) {
      await remove(partialOf(r));
      set(r, 'failed', 'failed', 'Copy verification failed.', { error: 'The quarantine copy could not be verified.' });
      return;
    }
    await fs.promises.rename(partialOf(r), r.stored);
    fault('copied');
    const current = await identify(r.original, fs);
    if (current?.sha256 !== r.sha256) {
      set(r, 'recovery-needed', 'changed-during-copy', null, {
        issue: 'The original file changed while it was being quarantined. Both copies were kept.',
        options: ['dismiss']
      });
      return;
    }
    await fs.promises.unlink(r.original);
    fault('removed-original');
    set(r, 'quarantined', 'copied');
  }

  function restore(id, target) {
    return exclusive(async () => {
      const r = records.find(q => q.id === id && q.status === 'quarantined');
      if (!r) throw new QuarantineError('This file is no longer in quarantine.', 'missing');
      target = target || r.original;
      if (await exists(target))
        throw new QuarantineError('A file already exists at ' + target + '. Choose another location.', 'exists');
      const stored = await identify(r.stored, fs);
      if (!stored || (r.sha256 && stored.sha256 !== r.sha256))
        throw new QuarantineError('The quarantined copy is missing or has changed, so it was not restored.', 'damaged');
      const temp = restoreTempOf(r, target);
      set(r, 'restoring', 'restoring', target, { restoreTarget: target });
      try {
        persist();
      } catch (err) {
        set(r, 'quarantined', 'restore-not-started');
        throw err;
      }
      try {
        await fs.promises.mkdir(path.dirname(target), { recursive: true });
        await fs.promises.copyFile(r.stored, temp, fs.constants.COPYFILE_EXCL);
        fault('restore-copied');
        if ((await hashFile(temp, fs)) !== stored.sha256) throw Error('The restored copy could not be verified.');
        // A hard link publishes the file without ever replacing an existing one. Volumes without
        // hard-link support fall back to an exclusive copy.
        try {
          await fs.promises.link(temp, target);
        } catch (err) {
          if (err.code === 'EEXIST') throw err;
          await fs.promises.copyFile(temp, target, fs.constants.COPYFILE_EXCL);
        }
        fault('restore-linked');
      } catch (err) {
        if (err.reason === 'fault') throw err;
        await remove(temp);
        set(r, 'quarantined', 'restore-failed', err.message);
        persistAfterChange(r);
        throw new QuarantineError(
          err.code === 'EEXIST' ? 'A file already exists at ' + target + '.' : friendly(err),
          'failed'
        );
      }
      await remove(temp);
      await fs.promises.unlink(r.stored);
      fault('restore-removed');
      set(r, 'restored', 'restored', target);
      persistAfterChange(r);
      onDetection(r.detectionId, 'restored', r);
      return r;
    });
  }

  // Reconciles records left mid-operation. Idempotent: running it again changes nothing.
  function recover() {
    return exclusive(async () => {
      const changed = [];
      for (const r of records) {
        if (r.status === 'prepared' || r.status === 'copying') await recoverQuarantine(r);
        else if (r.status === 'restoring') await recoverRestore(r);
        else continue;
        changed.push(r);
      }
      if (changed.length) persistAfterChange(changed[0]);
      return changed;
    });
  }

  async function recoverQuarantine(r) {
    const [stored, original, partial] = await Promise.all([
      identify(r.stored, fs),
      identify(r.original, fs),
      exists(partialOf(r))
    ]);
    const matches = f => !!f && !!r.sha256 && f.sha256 === r.sha256;
    const review = (issue, options = ['dismiss']) =>
      set(r, 'recovery-needed', 'recovery-needed', null, { issue, options });
    if (stored && !r.sha256) {
      // Records from earlier versions have no hash, so identity cannot be proven.
      if (!original) set(r, 'quarantined', 'recovered', 'The move had completed.');
      else
        review('Quarantine was interrupted. A file exists in both places and could not be compared. Both were kept.');
    } else if (matches(stored)) {
      if (!original) set(r, 'quarantined', 'recovered', 'The move had completed.');
      else if (matches(original))
        review('Quarantine was interrupted after copying. The file exists in both places with identical content.', [
          'finish',
          'undo'
        ]);
      else {
        set(r, 'quarantined', 'recovered', 'A different file now exists at the original location; it was not changed.');
        r.issue = 'A different file now exists at the original location. It was not changed.';
      }
    } else if (stored) {
      review('The quarantined copy does not match the detected file. Both copies were kept for review.');
    } else if (partial) {
      if (matches(original)) {
        await remove(partialOf(r));
        set(r, 'failed', 'recovered', 'An incomplete copy was removed; the original is intact.', {
          error: 'Quarantine was interrupted. The file was left in its original location.'
        });
      } else review('Quarantine was interrupted. An incomplete copy was kept at ' + partialOf(r) + '.');
    } else if (original) {
      set(r, 'failed', 'recovered', 'The file had not been moved.', {
        error:
          matches(original) || !r.sha256
            ? 'Quarantine was interrupted. The file was left in its original location.'
            : 'Quarantine was interrupted. A different file is now at the original location.'
      });
    } else review('The file was not found in its original location or in quarantine.');
    onDetection(r.detectionId, r.status === 'quarantined' ? 'quarantined' : 'detected', r);
  }

  async function recoverRestore(r) {
    const target = r.restoreTarget || r.original;
    const temp = restoreTempOf(r, target);
    const [restored, stored, tempFile] = await Promise.all([
      identify(target, fs),
      identify(r.stored, fs),
      identify(temp, fs)
    ]);
    const matches = f => !!f && !!r.sha256 && f.sha256 === r.sha256;
    if (matches(restored)) {
      if (tempFile && matches(tempFile)) await remove(temp);
      if (matches(stored)) await remove(r.stored);
      set(r, 'restored', 'recovered', target);
      onDetection(r.detectionId, 'restored', r);
    } else if (matches(stored)) {
      if (tempFile) await remove(temp);
      set(r, 'quarantined', 'recovered', 'Restore was interrupted; the file is still in quarantine.');
    } else if (matches(tempFile)) {
      set(r, 'recovery-needed', 'recovery-needed', null, {
        issue: 'Restore was interrupted. The only verified copy is at ' + temp + '.',
        options: ['dismiss']
      });
    } else {
      set(r, 'recovery-needed', 'recovery-needed', null, {
        issue: 'Restore was interrupted and no verified copy could be found. Nothing was deleted.',
        options: ['dismiss']
      });
    }
  }

  // User decisions for records that need review. Each re-verifies content before deleting anything.
  function resolve(id, action) {
    return exclusive(async () => {
      const r = records.find(q => q.id === id && q.status === 'recovery-needed');
      if (!r || !r.options.includes(action)) throw new QuarantineError('That action is no longer available.', 'stale');
      if (action === 'dismiss') {
        set(r, 'reviewed', 'dismissed', 'Files were left where they are.');
      } else {
        const [stored, original] = await Promise.all([identify(r.stored, fs), identify(r.original, fs)]);
        if (!stored || !original || stored.sha256 !== r.sha256 || original.sha256 !== r.sha256)
          throw new QuarantineError(
            'The files changed since this was checked. Restart Sentinel to re-check them.',
            'stale'
          );
        if (action === 'finish') {
          await fs.promises.unlink(r.original);
          set(r, 'quarantined', 'finished');
          onDetection(r.detectionId, 'quarantined', r);
        } else {
          await fs.promises.unlink(r.stored);
          set(r, 'failed', 'undone', null, {
            error: 'Quarantine was undone. The file was left in its original location.'
          });
          onDetection(r.detectionId, 'detected', r);
        }
      }
      persistAfterChange(r);
      return r;
    });
  }

  return { quarantine, restore, recover, resolve };
}

function friendly(err) {
  if (err.code === 'EBUSY' || err.code === 'EPERM' || err.code === 'EACCES')
    return 'Windows denied access to the file. It may be open in another program, or you may not have permission to move it.';
  if (err.code === 'ENOSPC') return 'There is not enough free disk space.';
  if (err.code === 'ENOENT') return 'The file or its folder no longer exists.';
  return err.message;
}

module.exports = { createQuarantine, QuarantineError };
