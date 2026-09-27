const path = require('node:path');

function nextRun(schedule, after = new Date()) {
  const [hour, minute] = schedule.time.split(':').map(Number);
  const next = new Date(after);
  next.setHours(hour, minute, 0, 0);
  if (schedule.frequency === 'weekly') {
    next.setDate(next.getDate() + ((schedule.day - next.getDay() + 7) % 7));
    if (next <= after) next.setDate(next.getDate() + 7);
  } else if (next <= after) next.setDate(next.getDate() + 1);
  return next.toISOString();
}
function defaults() {
  return {
    engineDir: '',
    launchAtLogin: false,
    notifications: true,
    closeToTray: true,
    autoUpdate: true,
    scanArchives: true,
    detectPUA: false,
    // Definitions older than this are reported as outdated.
    staleAfterDays: 3,
    exclusions: [],
    // Schedule configuration only; next-run and retry state is kept by the scheduler (schedule.json).
    schedules: [
      { id: 'quick', enabled: true, frequency: 'daily', time: '12:00', day: 0 },
      { id: 'full', enabled: true, frequency: 'weekly', time: '18:00', day: 0 }
    ]
  };
}
function validateSettings(input, previous) {
  const out = { ...previous };
  for (const key of ['launchAtLogin', 'notifications', 'closeToTray', 'autoUpdate', 'scanArchives', 'detectPUA']) {
    if (typeof input[key] !== 'boolean') throw Error('Invalid preference: ' + key);
    out[key] = input[key];
  }
  if (!Array.isArray(input.schedules) || input.schedules.length !== 2) throw Error('Two scan schedules are required.');
  out.schedules = ['quick', 'full'].map(id => {
    const s = input.schedules.find(s => s.id === id);
    if (
      !s ||
      typeof s.enabled !== 'boolean' ||
      !['daily', 'weekly'].includes(s.frequency) ||
      !/^([01]\d|2[0-3]):[0-5]\d$/.test(s.time) ||
      !Number.isInteger(s.day) ||
      s.day < 0 ||
      s.day > 6
    )
      throw Error('Invalid schedule.');
    return { id, enabled: s.enabled, frequency: s.frequency, time: s.time, day: s.day };
  });
  if (!Number.isInteger(input.staleAfterDays) || input.staleAfterDays < 1 || input.staleAfterDays > 30)
    throw Error('Choose how many days definitions stay current (1–30).');
  out.staleAfterDays = input.staleAfterDays;
  return out;
}
function scanArgs(settings, database, targets) {
  // Targets come from native pickers or known folders. Requiring absolute paths also guarantees that no
  // target can be mistaken for a command-line option.
  for (const t of targets) if (!path.win32.isAbsolute(t) || /^[-/]/.test(t)) throw Error('Invalid scan location: ' + t);
  return [
    '--recursive=yes',
    '--verbose',
    '--stdout',
    '--database=' + database,
    '--scan-archive=' + (settings.scanArchives ? 'yes' : 'no'),
    '--detect-pua=' + (settings.detectPUA ? 'yes' : 'no'),
    ...settings.exclusions.map(p => '--exclude-dir=^' + p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '([\\\\/]|$)'),
    ...targets
  ];
}
function parseLine(line) {
  // Classify "Scanning <path>" first so file names containing "error" are not reported as warnings.
  if (line.startsWith('Scanning ')) return { type: 'scanning', path: line.slice(9) };
  const found = line.match(/^(.*): (.+) FOUND$/);
  if (found) return { type: 'threat', path: found[1], signature: found[2] };
  if (/: OK$/.test(line)) return { type: 'file', path: line.slice(0, -4) };
  const count = line.match(/^Scanned files:\s*(\d+)/);
  if (count) return { type: 'count', count: Number(count[1]) };
  if (/\sERROR$|^(LibClamAV )?(ERROR|WARNING)\b|Access (is )?denied/i.test(line))
    return { type: 'warning', message: line };
  return { type: 'info', message: line };
}
module.exports = { nextRun, defaults, validateSettings, scanArgs, parseLine };
