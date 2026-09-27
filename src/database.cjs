// Signature database inspection. The 512-byte CVD/CLD header gives the version and build time instantly;
// full verification uses ClamAV's own sigtool, which checks each file's digital signature.
const nodeFs = require('node:fs');
const path = require('node:path');

const REQUIRED = ['main', 'daily'];
const KNOWN = ['main', 'daily', 'bytecode'];

// "ClamAV-VDB:27 Sep 2026 06-26 +0000:28136:355678:90:..."
function parseHeader(text) {
  const m = /^ClamAV-VDB:(\d{1,2} \w{3} \d{4}) (\d{2})-(\d{2}) ([+-]\d{4}):(\d+):(\d+):/.exec(text);
  if (!m) return null;
  const built = new Date(`${m[1]} ${m[2]}:${m[3]} ${m[4]}`);
  return {
    buildTime: Number.isNaN(built.getTime()) ? null : built.toISOString(),
    version: Number(m[5]),
    signatures: Number(m[6])
  };
}

function readHeader(file, fs = nodeFs) {
  let fd;
  try {
    fd = fs.openSync(file, 'r');
    const buffer = Buffer.alloc(512);
    const bytes = fs.readSync(fd, buffer, 0, 512, 0);
    return parseHeader(buffer.subarray(0, bytes).toString('latin1'));
  } catch {
    return null;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

// Quick, synchronous summary of what is on disk.
function inspect(dir, fs = nodeFs) {
  const files = [];
  for (const name of KNOWN) {
    for (const ext of ['.cld', '.cvd']) {
      const file = path.join(dir, name + ext);
      let stat;
      try {
        stat = fs.statSync(file);
      } catch {
        continue;
      }
      files.push({ name, file, size: stat.size, modified: stat.mtime.toISOString(), header: readHeader(file, fs) });
      break;
    }
  }
  const byName = Object.fromEntries(files.map(f => [f.name, f]));
  const daily = byName.daily?.header;
  return {
    present: REQUIRED.every(n => byName[n]),
    missing: REQUIRED.filter(n => !byName[n]),
    unreadable: files.filter(f => !f.header).map(f => path.basename(f.file)),
    version: daily?.version ?? null,
    buildTime: daily?.buildTime ?? null,
    files,
    // Changes whenever any database file changes, so verification can be cached.
    fingerprint: files.map(f => `${f.name}:${f.size}:${f.modified}`).join('|')
  };
}

// Verifies every database file with sigtool. `run(exe, args)` resolves to stdout+stderr text.
async function verify(files, sigtool, run) {
  const failures = [];
  for (const f of files) {
    let output = '';
    try {
      output = await run(sigtool, ['--info=' + f.file]);
    } catch (err) {
      output = String(err.output || err.message);
    }
    if (!/Verification OK/.test(output)) failures.push(path.basename(f.file));
  }
  return { verified: failures.length === 0, failures };
}

module.exports = { parseHeader, readHeader, inspect, verify };
