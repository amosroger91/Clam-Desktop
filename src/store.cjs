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

function createStore(root, { fs = nodeFs, now = () => new Date() } = {}) {
  const file = name => path.join(root, name + '.json');
  const stamp = () => now().toISOString().replace(/[:.]/g, '-');

  function preserve(target, reason) {
    const copy = `${target}.${reason}-${stamp()}`;
    try {
      fs.copyFileSync(target, copy);
      return copy;
    } catch {
      return null;
    }
  }

  function parse(target) {
    return unwrap(JSON.parse(fs.readFileSync(target, 'utf8')));
  }

  /**
   * spec: { version, fallback(), migrations: { [from]: data => data }, validate(data) => { value, problems } }
   * Returns { value, issue, legacy } where legacy is the pre-migration schema-0 data, if any.
   */
  function load(name, spec) {
    const target = file(name);
    // A leftover temporary file is an abandoned write; the committed file (or its backup) is authoritative.
    try {
      fs.rmSync(target + '.tmp', { force: true });
    } catch {}
    let loaded,
      issue = null;
    try {
      loaded = parse(target);
    } catch (err) {
      if (err.code === 'ENOENT' && !fs.existsSync(target + '.bak')) return { value: spec.fallback(), issue: null };
      const preservedAs = err.code === 'ENOENT' ? null : preserve(target, 'corrupt');
      try {
        loaded = parse(target + '.bak');
        issue = { file: name, message: 'Could not be read, so the previous saved copy was restored.', preservedAs };
      } catch {
        return {
          value: spec.fallback(),
          issue: { file: name, message: 'Could not be read and was reset to defaults.', preservedAs }
        };
      }
    }
    if (loaded.version > spec.version) {
      const preservedAs = preserve(target, 'newer');
      return {
        value: spec.fallback(),
        issue: { file: name, message: 'Was created by a newer version of Sentinel and could not be used.', preservedAs }
      };
    }
    const legacy = loaded.version === 0 ? loaded.data : undefined;
    let data = loaded.data;
    try {
      for (let v = loaded.version; v < spec.version; v++) data = spec.migrations[v](data);
    } catch (err) {
      const preservedAs = preserve(target, 'unmigrated');
      return {
        value: spec.fallback(),
        issue: { file: name, message: 'Could not be upgraded (' + err.message + ') and was reset.', preservedAs },
        legacy
      };
    }
    const { value, problems } = spec.validate(data);
    if (problems.length) {
      const preservedAs = issue?.preservedAs ?? preserve(target, 'invalid');
      const detail = problems.slice(0, 3).join('; ') + (problems.length > 3 ? `; and ${problems.length - 3} more` : '');
      issue = { file: name, message: 'Contained invalid entries that were set aside: ' + detail + '.', preservedAs };
    }
    return { value, issue, legacy, migrated: loaded.version !== spec.version };
  }

  function save(name, value, version) {
    const target = file(name);
    const tmp = target + '.tmp';
    const text = JSON.stringify({ schema: version, savedAt: now().toISOString(), data: value }, null, 2);
    try {
      fs.mkdirSync(root, { recursive: true });
      const fd = fs.openSync(tmp, 'w');
      try {
        fs.writeSync(fd, text);
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      if (fs.existsSync(target)) retrying(() => fs.copyFileSync(target, target + '.bak'));
      retrying(() => fs.renameSync(tmp, target));
    } catch (err) {
      try {
        fs.rmSync(tmp, { force: true });
      } catch {}
      throw new StorageError(describeFailure(err, target), { code: err.code, file: target, cause: err });
    }
  }

  return { load, save, file };
}

module.exports = { createStore, StorageError };
