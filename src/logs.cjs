// Log namespaces with separate retention (R14):
//   logs/scans/<scan id>.log  diagnostic scan output; removed when its report ages out
//   logs/app/errors.log       application fault diagnostics; size-rotated, never pruned with reports
// Scan evidence lives in the journal folder, which log cleanup never touches.
const nodeFs = require('node:fs');
const path = require('node:path');
const { SCAN_ID } = require('./journal.cjs');

const APP_LOG_LIMIT = 1024 * 1024;
const APP_LOG_GENERATIONS = 3;

function layout(logsRoot) {
  return { scans: path.join(logsRoot, 'scans'), app: path.join(logsRoot, 'app') };
}

// Moves files from the 1.x flat layout into their namespaces. Safe to run repeatedly.
function migrateLayout(logsRoot, fs = nodeFs) {
  const dirs = layout(logsRoot);
  fs.mkdirSync(dirs.scans, { recursive: true });
  fs.mkdirSync(dirs.app, { recursive: true });
  let names = [];
  try {
    names = fs.readdirSync(logsRoot);
  } catch {}
  for (const name of names) {
    const from = path.join(logsRoot, name);
    try {
      if (name === 'app-errors.log') {
        fs.appendFileSync(path.join(dirs.app, 'errors.log'), fs.readFileSync(from));
        fs.rmSync(from);
      } else if (name.endsWith('.log') && SCAN_ID.test(name.slice(0, -4)))
        fs.renameSync(from, path.join(dirs.scans, name));
    } catch {}
  }
  return dirs;
}

// Removes scan logs whose reports are no longer retained. Only UUID-named scan logs are candidates.
function pruneScanLogs(scansDir, keepIds, fs = nodeFs) {
  const keep = new Set(keepIds);
  let removed = 0;
  let names = [];
  try {
    names = fs.readdirSync(scansDir);
  } catch {}
  for (const name of names) {
    const id = name.slice(0, -4);
    if (!name.endsWith('.log') || !SCAN_ID.test(id) || keep.has(id)) continue;
    try {
      fs.rmSync(path.join(scansDir, name), { force: true });
      removed++;
    } catch {}
  }
  return removed;
}

// Appends to the bounded application error log, rotating older generations. Never throws.
function appendAppError(appDir, text, fs = nodeFs) {
  try {
    fs.mkdirSync(appDir, { recursive: true });
    const file = path.join(appDir, 'errors.log');
    let size = 0;
    try {
      size = fs.statSync(file).size;
    } catch {}
    if (size > APP_LOG_LIMIT) {
      for (let g = APP_LOG_GENERATIONS - 1; g >= 1; g--) {
        const older = path.join(appDir, `errors.${g}.log`);
        const newer = g === 1 ? file : path.join(appDir, `errors.${g - 1}.log`);
        try {
          fs.renameSync(newer, older);
        } catch {}
      }
    }
    fs.appendFileSync(file, `${new Date().toISOString()} ${text}\n`);
    return file;
  } catch {
    return null;
  }
}

module.exports = { layout, migrateLayout, pruneScanLogs, appendAppError };
