// Journaled quarantine and restore.
//
// Every operation persists its intent before touching the file system, and recovery decides what happened
// from content hashes, not from whether a path exists. A copy is deleted only when identical content is
// verified to exist elsewhere. When identity or completeness is uncertain, both copies are kept and the
// record is marked 'recovery-needed' for the user to review.
//
// Record statuses: prepared → quarantined (same volume: atomic rename, then verify what was moved)
//                  prepared → copying → quarantined (across volumes: copy, verify, then remove original)
//                  quarantined → restoring → restored
//                  failed (nothing was moved), recovery-needed (user review), reviewed (user dismissed)
//
// Identity (R04): a committed record always describes the bytes actually retained. Content moved into
// quarantine is hashed after the move; an original is removed only after it has been renamed aside (so
// later writers at that path create a new file) and the isolated file re-verified. Node cannot take a
// Windows deny-share lock on a path, so a process that already holds the file open can still write to it
// until the rename; the post-move verification is what catches that case.
//
// Paths (R11): the stored location is always derived from the record's validated id, never trusted from
// disk. A record whose stored path disagrees is left untouched and flagged for review.
const nodeFs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { identify, hashFile } = require('./files.cjs');

const MAX_AUDIT = 30;
const RECORD_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Absolute drive or UNC paths only; device namespaces (\\?\, \\.\) are rejected.
const isUsablePath = p => typeof p === 'string' && path.win32.isAbsolute(p) && !/^[\\/]{2}[?.][\\/]/.test(p);

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
  const storedOf = r => path.join(vault, r.id + '.quarantine');
  // A record may be acted on only if its id is valid and its stored path is the one derived from it.
  const trusted = r =>
    RECORD_ID.test(r.id) &&
    typeof r.stored === 'string' &&
    path.resolve(r.stored).toLowerCase() === storedOf(r).toLowerCase() &&
    isUsablePath(r.original);
  const partialOf = r => storedOf(r) + '.partial';
  const stagingOf = r => path.join(path.dirname(r.original), `.${path.basename(r.original)}.${r.id}.sentinel-remove`);
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
        await fs.promises.rename(r.original, storedOf(r));
        fault('moved');
        // Verify what was actually moved: the file may have changed after it was hashed (R04).
        const kept = await identify(storedOf(r), fs);
        if (kept?.sha256 === r.sha256) set(r, 'quarantined', 'moved');
        else
          set(r, 'recovery-needed', 'changed-during-move', null, {
            storedSha256: kept?.sha256 ?? null,
            issue:
              'The file changed while it was being quarantined. What was moved into quarantine differs from the detected file and was kept for review.',
            options: ['dismiss']
          });
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
    await fs.promises.rename(partialOf(r), storedOf(r));
    fault('copied');
    if (!(await removeVerifiedOriginal(r))) {
      set(r, 'recovery-needed', 'changed-during-copy', null, {
        issue: 'The original file changed while it was being quarantined. Both copies were kept.',
        options: ['dismiss']
      });
      return;
    }
    set(r, 'quarantined', 'copied');
  }

  // Removes the original only if it still holds the detected content (R04.3). It is first renamed aside,
  // so anything written to the original path afterwards is a new file that is never deleted, and the
  // isolated file is verified before removal. Unexpected content is put back (or kept beside it).
  async function removeVerifiedOriginal(r) {
    const staging = stagingOf(r);
    await fs.promises.rename(r.original, staging);
    fault('isolated');
    const isolated = await identify(staging, fs);
    if (isolated?.sha256 === r.sha256) {
      await fs.promises.unlink(staging);
      fault('removed-original');
      return true;
    }
    if (!(await exists(r.original))) await fs.promises.rename(staging, r.original);
    return false;
  }

  function restore(id, target) {
    return exclusive(async () => {
      const r = records.find(q => q.id === id && q.status === 'quarantined');
      if (!r) throw new QuarantineError('This file is no longer in quarantine.', 'missing');
      if (!trusted(r))
        throw new QuarantineError('This record points outside Sentinel’s quarantine, so it was not used.', 'untrusted');
      target = target || r.original;
      if (!isUsablePath(target)) throw new QuarantineError('That restore location is not supported.', 'invalid-target');
      if (await exists(target))
        throw new QuarantineError('A file already exists at ' + target + '. Choose another location.', 'exists');
      const stored = await identify(storedOf(r), fs);
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
        await fs.promises.copyFile(storedOf(r), temp, fs.constants.COPYFILE_EXCL);
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
      await fs.promises.unlink(storedOf(r));
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
        if (!['prepared', 'copying', 'restoring', 'recovery-needed', 'quarantined'].includes(r.status)) continue;
        if (r.status === 'quarantined' && trusted(r)) continue;
        const before = JSON.stringify([r.status, r.issue, r.options]);
        await reconcile(r);
        if (JSON.stringify([r.status, r.issue, r.options]) !== before) changed.push(r);
      }
      if (changed.length) persistAfterChange(changed[0]);
      return changed;
    });
  }

  // Re-derives a record's state from the files now on disk. Records waiting for review are rechecked too,
  // so a decision that went stale can be refreshed (R10).
  async function reconcile(r) {
    if (!trusted(r)) {
      if (r.status !== 'recovery-needed' || !r.untrusted)
        set(r, 'recovery-needed', 'untrusted-record', null, {
          untrusted: true,
          issue:
            'This record’s stored location is outside Sentinel’s quarantine folder, so Sentinel will not act on it. No files were changed.',
          options: ['dismiss']
        });
      return;
    }
    if (r.status === 'restoring' || r.interruptedPhase === 'restore') await recoverRestore(r);
    else await recoverQuarantine(r);
  }

  function recheck(id) {
    return exclusive(async () => {
      const r = records.find(q => q.id === id && ['recovery-needed', 'reviewed'].includes(q.status));
      if (!r) throw new QuarantineError('This item does not need to be rechecked.', 'stale');
      await reconcile(r);
      persistAfterChange(r);
      return r;
    });
  }

  async function recoverQuarantine(r) {
    // A removal interrupted after the original was renamed aside (R04).
    const staging = stagingOf(r);
    const staged = await identify(staging, fs);
    if (staged) {
      const storedNow = await identify(storedOf(r), fs);
      if (r.sha256 && staged.sha256 === r.sha256 && storedNow?.sha256 === r.sha256) await remove(staging);
      else if (!(await exists(r.original))) await fs.promises.rename(staging, r.original);
    }
    const [stored, original, partial] = await Promise.all([
      identify(storedOf(r), fs),
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
    } else if (staged && (await exists(staging))) {
      review('Quarantine was interrupted while removing the original. The file was kept at ' + staging + '.');
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
      identify(storedOf(r), fs),
      identify(temp, fs)
    ]);
    const matches = f => !!f && !!r.sha256 && f.sha256 === r.sha256;
    if (matches(restored)) {
      if (tempFile && matches(tempFile)) await remove(temp);
      if (matches(stored)) await remove(storedOf(r));
      set(r, 'restored', 'recovered', target, { interruptedPhase: null });
      onDetection(r.detectionId, 'restored', r);
    } else if (matches(stored)) {
      if (tempFile) await remove(temp);
      set(r, 'quarantined', 'recovered', 'Restore was interrupted; the file is still in quarantine.', {
        interruptedPhase: null
      });
    } else if (matches(tempFile)) {
      set(r, 'recovery-needed', 'recovery-needed', null, {
        issue: 'Restore was interrupted. The only verified copy is at ' + temp + '.',
        options: ['dismiss'],
        interruptedPhase: 'restore'
      });
    } else {
      set(r, 'recovery-needed', 'recovery-needed', null, {
        issue: 'Restore was interrupted and no verified copy could be found. Nothing was deleted.',
        options: ['dismiss'],
        interruptedPhase: 'restore'
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
        if (!trusted(r)) throw new QuarantineError('This record cannot be acted on.', 'untrusted');
        const [stored, original] = await Promise.all([identify(storedOf(r), fs), identify(r.original, fs)]);
        if (!stored || !original || stored.sha256 !== r.sha256 || original.sha256 !== r.sha256)
          throw new QuarantineError(
            'The files changed since this was checked. Use Recheck to review them again.',
            'stale'
          );
        if (action === 'finish') {
          if (!(await removeVerifiedOriginal(r)))
            throw new QuarantineError('The original changed at the last moment and was kept. Use Recheck.', 'stale');
          set(r, 'quarantined', 'finished');
          onDetection(r.detectionId, 'quarantined', r);
        } else {
          await fs.promises.unlink(storedOf(r));
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

  return { quarantine, restore, recover, recheck, resolve };
}

function friendly(err) {
  if (err.code === 'EBUSY' || err.code === 'EPERM' || err.code === 'EACCES')
    return 'Windows denied access to the file. It may be open in another program, or you may not have permission to move it.';
  if (err.code === 'ENOSPC') return 'There is not enough free disk space.';
  if (err.code === 'ENOENT') return 'The file or its folder no longer exists.';
  return err.message;
}

module.exports = { createQuarantine, QuarantineError };
