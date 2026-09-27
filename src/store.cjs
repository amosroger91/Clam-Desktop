// Versioned JSON persistence with atomic writes, backups, migrations, and preserved invalid files.
//
// Each file is stored as { schema, savedAt, data }. Files written before versioning (schema 0) are bare
// values. Loading never silently discards data: unreadable or invalid files are copied aside for
// diagnosis and reported as issues so the UI can explain what happened.
const nodeFs = require('node:fs');
const path = require('node:path');

class StorageError extends Error {
  constructor(message, { code, file, cause } = {}) {
    super(message, { cause });
    this.name = 'StorageError';
    this.code = code;
    this.file = file;
  }
}

function describeFailure(err, file) {
  const name = path.basename(file);
  switch (err.code) {
    case 'ENOSPC':
      return `The disk is full, so ${name} could not be saved. Free some space and try again.`;
    case 'EROFS':
      return `${name} could not be saved because its folder is read-only.`;
    case 'EACCES':
    case 'EPERM':
    case 'EBUSY':
      return `Windows denied access to ${name}. Another program, such as antivirus or file sync, may be using it. Try again shortly.`;
    default:
      return `${name} could not be saved (${err.code || err.message}).`;
  }
}

// Windows can briefly lock a file that was just written (antivirus, indexing, sync clients).
function retrying(fn, attempts = 4) {
  for (let i = 1; ; i++) {
    try {
      return fn();
    } catch (err) {
      if (i >= attempts || !['EPERM', 'EACCES', 'EBUSY'].includes(err.code)) throw err;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 40 * i);
    }
  }
}

function unwrap(parsed) {
  if (
    parsed &&
    typeof parsed === 'object' &&
    !Array.isArray(parsed) &&
    Number.isInteger(parsed.schema) &&
    'data' in parsed
  )
    return { version: parsed.schema, data: parsed.data };
  return { version: 0, data: parsed };
}

// Generations: `name.json` (primary), `name.json.tmp` (a new generation being committed), and
// `name.json.bak` (the previous valid primary). A save writes and fsyncs the new generation before
// touching anything else, rotates the primary into the backup only if the primary is itself valid, and
// keeps a complete new generation when its promotion fails. Loading picks the newest valid candidate.
function createStore(root, { fs = nodeFs, now = () => new Date() } = {}) {
  const file = name => path.join(root, name + '.json');
  const stamp = () => now().toISOString().replace(/[:.]/g, '-');
  // Files written by a newer Sentinel: kept untouched until an update can read them.
  const readOnly = new Set();

  function preserve(target, reason) {
    const copy = `${target}.${reason}-${stamp()}`;
    try {
      fs.copyFileSync(target, copy);
      return copy;
    } catch {
      return null;
    }
  }

  function read(target) {
    const raw = JSON.parse(fs.readFileSync(target, 'utf8'));
    return { ...unwrap(raw), savedAt: typeof raw?.savedAt === 'string' ? raw.savedAt : '' };
  }
  function tryRead(target) {
    try {
      return { ok: true, ...read(target) };
    } catch (err) {
      return { ok: false, missing: err.code === 'ENOENT' };
    }
  }

  /**
   * spec: { version, fallback(), migrations: { [from]: data => data }, validate(data) => { value, problems } }
   * Returns { value, issue, legacy, migrated, readOnly } where legacy is the pre-migration schema-0 data.
   */
  function load(name, spec) {
    const target = file(name);
    const primary = tryRead(target);
    const pending = tryRead(target + '.tmp');
    let loaded,
      issue = null,
      preservedAs = null;
    if (!pending.ok && !pending.missing) {
      // A partially written generation was abandoned mid-write; the committed files are authoritative.
      try {
        fs.rmSync(target + '.tmp', { force: true });
      } catch {}
    }
    if (!primary.ok && !primary.missing) preservedAs = preserve(target, 'corrupt');
    if (pending.ok && (!primary.ok || pending.savedAt > primary.savedAt)) {
      loaded = pending;
      issue = { file: name, message: 'The latest save had not finished, so it was completed on startup.', preservedAs };
    } else if (primary.ok) loaded = primary;
    else {
      const backup = tryRead(target + '.bak');
      if (!backup.ok) {
        if (primary.missing && backup.missing) return { value: spec.fallback(), issue: null };
        return {
          value: spec.fallback(),
          issue: { file: name, message: 'Could not be read and was reset to defaults.', preservedAs }
        };
      }
      loaded = backup;
      issue = { file: name, message: 'Could not be read, so the previous saved copy was restored.', preservedAs };
    }
    if (loaded.version > spec.version) {
      readOnly.add(name);
      return {
        value: spec.fallback(),
        readOnly: true,
        issue: {
          file: name,
          message:
            'Was created by a newer version of Sentinel. It is kept unchanged, and changes to it cannot be saved until Sentinel is updated.'
        }
      };
    }
    const legacy = loaded.version === 0 ? loaded.data : undefined;
    let data = loaded.data;
    try {
      for (let v = loaded.version; v < spec.version; v++) data = spec.migrations[v](data);
    } catch (err) {
      return {
        value: spec.fallback(),
        issue: {
          file: name,
          message: 'Could not be upgraded (' + err.message + ') and was reset.',
          preservedAs: preserve(target, 'unmigrated')
        },
        legacy
      };
    }
    const { value, problems } = spec.validate(data);
    if (problems.length) {
      const detail = problems.slice(0, 3).join('; ') + (problems.length > 3 ? `; and ${problems.length - 3} more` : '');
      issue = {
        file: name,
        message: 'Contained invalid entries that were set aside: ' + detail + '.',
        preservedAs: issue?.preservedAs ?? preserve(target, 'invalid')
      };
    }
    return { value, issue, legacy, migrated: loaded.version !== spec.version };
  }

  function save(name, value, version) {
    const target = file(name);
    const tmp = target + '.tmp';
    if (readOnly.has(name))
      throw new StorageError(
        `${path.basename(target)} was created by a newer version of Sentinel and is kept unchanged. Update Sentinel to save changes.`,
        { code: 'EREADONLY', file: target }
      );
    const text = JSON.stringify({ schema: version, savedAt: now().toISOString(), data: value }, null, 2);
    // 1. Write and fsync the new generation. A failure here leaves the committed files untouched.
    try {
      fs.mkdirSync(root, { recursive: true });
      const fd = fs.openSync(tmp, 'w');
      try {
        fs.writeSync(fd, text);
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
    } catch (err) {
      try {
        fs.rmSync(tmp, { force: true });
      } catch {}
      throw new StorageError(describeFailure(err, target), { code: err.code, file: target, cause: err });
    }
    // 2. Rotate the primary into the backup only when it is valid, so a corrupt primary can never
    //    replace a known-good backup. 3. Promote the new generation. If either fails, the complete
    //    new generation stays on disk and is preferred on the next load.
    try {
      if (tryRead(target).ok) retrying(() => fs.copyFileSync(target, target + '.bak'));
      retrying(() => fs.renameSync(tmp, target));
    } catch (err) {
      throw new StorageError(describeFailure(err, target), { code: err.code, file: target, cause: err });
    }
  }

  return { load, save, file };
}

module.exports = { createStore, StorageError };
